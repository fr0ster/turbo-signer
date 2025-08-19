package signature

import (
	"context"
	"sync"
	"time"
)

// AsyncSigner асинхронний підписувач
type AsyncSigner struct {
	workers  int
	queue    chan SignRequest
	results  chan SignResult
	stopChan chan struct{}
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// SignRequest запит на підпис
type SignRequest struct {
	ID       string
	Message  string
	Signer   Sign
	Priority int // Вищий пріоритет = швидше обробка
	Timeout  time.Duration
}

// SignResult результат підпису
type SignResult struct {
	ID        string
	Signature string
	Error     error
	Duration  time.Duration
}

// NewAsyncSigner створює новий асинхронний підписувач
func NewAsyncSigner(workers int, queueSize int) *AsyncSigner {
	ctx, cancel := context.WithCancel(context.Background())

	signer := &AsyncSigner{
		workers:  workers,
		queue:    make(chan SignRequest, queueSize),
		results:  make(chan SignResult, queueSize),
		stopChan: make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
	}

	signer.start()
	return signer
}

// start запускає робочі горутини
func (as *AsyncSigner) start() {
	for i := 0; i < as.workers; i++ {
		as.wg.Add(1)
		go as.worker(i)
	}
}

// worker робоча горутина для обробки запитів
func (as *AsyncSigner) worker(id int) {
	defer as.wg.Done()

	for {
		select {
		case req := <-as.queue:
			as.processRequest(req)
		case <-as.ctx.Done():
			return
		case <-as.stopChan:
			return
		}
	}
}

// processRequest обробляє запит на підпис
func (as *AsyncSigner) processRequest(req SignRequest) {
	start := time.Now()

	// Створюємо контекст з таймаутом
	ctx := as.ctx
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(as.ctx, req.Timeout)
		defer cancel()
	}

	// Обробляємо запит
	select {
	case <-ctx.Done():
		as.results <- SignResult{
			ID:       req.ID,
			Error:    ctx.Err(),
			Duration: time.Since(start),
		}
	default:
		signature, _ := req.Signer.CreateSignature(req.Message)
		as.results <- SignResult{
			ID:        req.ID,
			Signature: signature,
			Duration:  time.Since(start),
		}
	}
}

// SignAsync асинхронно підписує повідомлення
func (as *AsyncSigner) SignAsync(req SignRequest) {
	select {
	case as.queue <- req:
		// Запит додано до черги
	case <-as.ctx.Done():
		// Контекст скасовано
	case <-as.stopChan:
		// Підписувач зупинено
	}
}

// GetResult отримує результат підпису
func (as *AsyncSigner) GetResult() (SignResult, bool) {
	select {
	case result := <-as.results:
		return result, true
	case <-as.ctx.Done():
		return SignResult{}, false
	case <-as.stopChan:
		return SignResult{}, false
	default:
		return SignResult{}, false
	}
}

// Stop зупиняє асинхронний підписувач
func (as *AsyncSigner) Stop() {
	close(as.stopChan)
	as.cancel()
	as.wg.Wait()
	close(as.queue)
	close(as.results)
}

// BatchSigner пакетний підписувач
type BatchSigner struct {
	batchSize    int
	batchTimeout time.Duration
	queue        chan BatchRequest
	results      chan BatchResult
	stopChan     chan struct{}
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
}

// BatchRequest пакетний запит
type BatchRequest struct {
	ID       string
	Messages []string
	Signer   Sign
	Timeout  time.Duration
}

// BatchResult результат пакетного підпису
type BatchResult struct {
	ID         string
	Signatures []string
	Errors     []error
	Duration   time.Duration
}

// NewBatchSigner створює новий пакетний підписувач
func NewBatchSigner(batchSize int, batchTimeout time.Duration) *BatchSigner {
	ctx, cancel := context.WithCancel(context.Background())

	signer := &BatchSigner{
		batchSize:    batchSize,
		batchTimeout: batchTimeout,
		queue:        make(chan BatchRequest, 10),
		results:      make(chan BatchResult, 10),
		stopChan:     make(chan struct{}),
		ctx:          ctx,
		cancel:       cancel,
	}

	signer.start()
	return signer
}

// start запускає обробку пакетів
func (bs *BatchSigner) start() {
	bs.wg.Add(1)
	go bs.batchProcessor()
}

// batchProcessor обробляє пакети запитів
func (bs *BatchSigner) batchProcessor() {
	defer bs.wg.Done()

	var currentBatch []SignRequest
	ticker := time.NewTicker(bs.batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case req := <-bs.queue:
			// Додаємо запит до поточного пакету
			for _, message := range req.Messages {
				currentBatch = append(currentBatch, SignRequest{
					ID:      req.ID,
					Message: message,
					Signer:  req.Signer,
					Timeout: req.Timeout,
				})
			}

			// Якщо пакет заповнений, обробляємо його
			if len(currentBatch) >= bs.batchSize {
				bs.processBatch(currentBatch)
				currentBatch = currentBatch[:0]
			}

		case <-ticker.C:
			// Обробляємо поточний пакет за таймаутом
			if len(currentBatch) > 0 {
				bs.processBatch(currentBatch)
				currentBatch = currentBatch[:0]
			}

		case <-bs.ctx.Done():
			// Обробляємо залишок перед завершенням
			if len(currentBatch) > 0 {
				bs.processBatch(currentBatch)
			}
			return

		case <-bs.stopChan:
			// Обробляємо залишок перед зупинкою
			if len(currentBatch) > 0 {
				bs.processBatch(currentBatch)
			}
			return
		}
	}
}

// processBatch обробляє пакет запитів
func (bs *BatchSigner) processBatch(batch []SignRequest) {
	if len(batch) == 0 {
		return
	}

	start := time.Now()
	signatures := make([]string, len(batch))
	errors := make([]error, len(batch))

	// Обробляємо запити паралельно
	var wg sync.WaitGroup
	for i, req := range batch {
		wg.Add(1)
		go func(index int, request SignRequest) {
			defer wg.Done()

			// Створюємо контекст з таймаутом
			ctx := bs.ctx
			if request.Timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(bs.ctx, request.Timeout)
				defer cancel()
			}

			select {
			case <-ctx.Done():
				errors[index] = ctx.Err()
			default:
				signatures[index], _ = request.Signer.CreateSignature(request.Message)
			}
		}(i, req)
	}

	wg.Wait()

	// Відправляємо результат
	bs.results <- BatchResult{
		ID:         batch[0].ID,
		Signatures: signatures,
		Errors:     errors,
		Duration:   time.Since(start),
	}
}

// SignBatch асинхронно підписує пакет повідомлень
func (bs *BatchSigner) SignBatch(req BatchRequest) {
	select {
	case bs.queue <- req:
		// Запит додано до черги
	case <-bs.ctx.Done():
		// Контекст скасовано
	case <-bs.stopChan:
		// Підписувач зупинено
	}
}

// GetBatchResult отримує результат пакетного підпису
func (bs *BatchSigner) GetBatchResult() (BatchResult, bool) {
	select {
	case result := <-bs.results:
		return result, true
	case <-bs.ctx.Done():
		return BatchResult{}, false
	case <-bs.stopChan:
		return BatchResult{}, false
	default:
		return BatchResult{}, false
	}
}

// Stop зупиняє пакетний підписувач
func (bs *BatchSigner) Stop() {
	close(bs.stopChan)
	bs.cancel()
	bs.wg.Wait()
	close(bs.queue)
	close(bs.results)
}

// Глобальні екземпляри
var (
	GlobalAsyncSigner = NewAsyncSigner(4, 100)                   // 4 робочі горутини, черга на 100
	GlobalBatchSigner = NewBatchSigner(10, 100*time.Millisecond) // Пакети по 10, таймаут 100мс
)

// SignAsyncSimple простий асинхронний підпис
func SignAsyncSimple(message string, signer Sign) chan SignResult {
	resultChan := make(chan SignResult, 1)

	go func() {
		start := time.Now()
		signature, _ := signer.CreateSignature(message)
		resultChan <- SignResult{
			Signature: signature,
			Duration:  time.Since(start),
		}
		close(resultChan)
	}()

	return resultChan
}

// SignBatchSimple простий пакетний підпис
func SignBatchSimple(messages []string, signer Sign) chan BatchResult {
	resultChan := make(chan BatchResult, 1)

	go func() {
		start := time.Now()
		signatures := make([]string, len(messages))
		errors := make([]error, len(messages))

		for i, message := range messages {
			signatures[i], _ = signer.CreateSignature(message)
		}

		resultChan <- BatchResult{
			Signatures: signatures,
			Errors:     errors,
			Duration:   time.Since(start),
		}
		close(resultChan)
	}()

	return resultChan
}
