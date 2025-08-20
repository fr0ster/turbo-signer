package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/fr0ster/turbo-signer/v2/signature"
)

func main() {
	fmt.Println("=== Turbo Signer Async Example ===")

	// Створюємо HMAC підписувач
	signer := signature.NewSignHMAC("test_api_key", "test_secret_key_that_is_long_enough_for_testing")

	// Демонструємо асинхронний підпис
	demonstrateAsyncSigning(signer)

	// Демонструємо пакетний підпис
	demonstrateBatchSigning(signer)

	// Демонструємо кешування ключів
	demonstrateKeyCaching()

	// Демонструємо глобальні підписувачі
	demonstrateGlobalSigners()

	// Очікуємо сигнал для завершення
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("\nPress Ctrl+C to exit...")
	<-sigChan

	fmt.Println("Shutting down...")
}

func demonstrateAsyncSigning(signer signature.Sign) {
	fmt.Println("\n--- Async Signing Demo ---")

	// Створюємо асинхронний підписувач
	asyncSigner := signature.NewAsyncSigner(4, 50)
	defer asyncSigner.Stop()

	// Додаємо кілька запитів
	messages := []string{
		"timestamp=1234567890&symbol=BTCUSDT",
		"timestamp=1234567891&symbol=ETHUSDT",
		"timestamp=1234567892&symbol=ADAUSDT",
	}

	var wg sync.WaitGroup
	results := make([]signature.SignResult, len(messages))

	for i, message := range messages {
		wg.Add(1)
		go func(index int, msg string) {
			defer wg.Done()

			req := signature.SignRequest{
				ID:      fmt.Sprintf("req_%d", index),
				Message: msg,
				Signer:  signer,
				Timeout: 2 * time.Second,
			}

			asyncSigner.SignAsync(req)

			// Отримуємо результат
			result, ok := asyncSigner.GetResult()
			if ok {
				results[index] = result
				fmt.Printf("Request %d: %s -> %s (took %v)\n",
					index, msg[:20]+"...", result.Signature[:20]+"...", result.Duration)
			}
		}(i, message)
	}

	wg.Wait()
	fmt.Printf("Processed %d async requests\n", len(results))
}

func demonstrateBatchSigning(signer signature.Sign) {
	fmt.Println("\n--- Batch Signing Demo ---")

	// Створюємо пакетний підписувач
	batchSigner := signature.NewBatchSigner(5, 200*time.Millisecond)
	defer batchSigner.Stop()

	// Створюємо пакет повідомлень
	messages := []string{
		"timestamp=1234567890&symbol=BTCUSDT&side=BUY",
		"timestamp=1234567891&symbol=ETHUSDT&side=SELL",
		"timestamp=1234567892&symbol=ADAUSDT&side=BUY",
		"timestamp=1234567893&symbol=DOTUSDT&side=SELL",
		"timestamp=1234567894&symbol=LINKUSDT&side=BUY",
	}

	// Розбиваємо на пакети
	batchSize := 3
	for i := 0; i < len(messages); i += batchSize {
		end := i + batchSize
		if end > len(messages) {
			end = len(messages)
		}

		batch := messages[i:end]
		req := signature.BatchRequest{
			ID:       fmt.Sprintf("batch_%d", i/batchSize),
			Messages: batch,
			Signer:   signer,
			Timeout:  2 * time.Second,
		}

		batchSigner.SignBatch(req)
		fmt.Printf("Submitted batch %d with %d messages\n", i/batchSize, len(batch))
	}

	// Отримуємо результати
	time.Sleep(300 * time.Millisecond) // Даємо час на обробку

	for i := 0; i < (len(messages)+batchSize-1)/batchSize; i++ {
		result, ok := batchSigner.GetBatchResult()
		if ok {
			fmt.Printf("Batch %d: processed %d messages in %v\n",
				i, len(result.Signatures), result.Duration)

			for j, sig := range result.Signatures {
				if sig != "" {
					fmt.Printf("  Message %d: %s...\n", j, sig[:20])
				}
			}
		}
	}
}

func demonstrateKeyCaching() {
	fmt.Println("\n--- Key Caching Demo ---")

	// Очищаємо глобальний кеш для демонстрації
	signature.GlobalKeyCache.Clear()

	// Демонструємо кешування
	fmt.Printf("Initial cache size: %d\n", signature.GlobalKeyCache.Size())

	// Додаємо тестові ключі
	signature.GlobalKeyCache.Set("key1", "value1", "string")
	signature.GlobalKeyCache.Set("key2", "value2", "int")
	signature.GlobalKeyCache.Set("key3", "value3", "float")

	fmt.Printf("After adding keys: %d\n", signature.GlobalKeyCache.Size())

	// Отримуємо статистику
	stats := signature.GlobalKeyCache.Stats()
	fmt.Printf("Cache stats: size=%d, max_size=%d, ttl=%s\n",
		stats["size"], stats["max_size"], stats["ttl"])

	// Очищаємо після демонстрації
	signature.GlobalKeyCache.Clear()
}

func demonstrateGlobalSigners() {
	fmt.Println("\n--- Global Signers Demo ---")

	// Використовуємо глобальні підписувачі
	signer := signature.NewSignHMAC("global_key", "global_secret_that_is_long_enough")

	// Асинхронний підпис через глобальний підписувач
	req := signature.SignRequest{
		ID:      "global_req",
		Message: "global_message",
		Signer:  signer,
		Timeout: 1 * time.Second,
	}

	signature.GlobalAsyncSigner.SignAsync(req)
	time.Sleep(20 * time.Millisecond)

	result, ok := signature.GlobalAsyncSigner.GetResult()
	if ok {
		fmt.Printf("Global async result: %s (took %v)\n",
			result.Signature[:20]+"...", result.Duration)
	}

	// Пакетний підпис через глобальний підписувач
	batchReq := signature.BatchRequest{
		ID:       "global_batch",
		Messages: []string{"msg1", "msg2"},
		Signer:   signer,
		Timeout:  1 * time.Second,
	}

	signature.GlobalBatchSigner.SignBatch(batchReq)
	time.Sleep(150 * time.Millisecond)

	batchResult, ok := signature.GlobalBatchSigner.GetBatchResult()
	if ok {
		fmt.Printf("Global batch result: processed %d messages in %v\n",
			len(batchResult.Signatures), batchResult.Duration)
	}
}
