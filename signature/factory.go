package signature

import (
	"fmt"
	"sync"
)

// SignerFactory фабрика для створення підписувачів
type SignerFactory struct {
	mu       sync.RWMutex
	creators map[string]SignerCreator
	cache    map[string]Sign
}

// SignerCreator функція для створення підписувача
type SignerCreator func(config SignerConfig) (Sign, error)

// SignerConfig конфігурація для створення підписувача
type SignerConfig struct {
	Algorithm  string            // hmac, rsa, ed25519, ecdsa
	APIKey     string            // API ключ
	SecretKey  string            // Секретний ключ (для HMAC)
	PublicKey  string            // Публічний ключ (для RSA, Ed25519, ECDSA)
	PrivateKey string            // Приватний ключ (для RSA, Ed25519, ECDSA)
	Options    map[string]string // Додаткові опції
}

// NewSignerFactory створює нову фабрику підписувачів
func NewSignerFactory() *SignerFactory {
	factory := &SignerFactory{
		creators: make(map[string]SignerCreator),
		cache:    make(map[string]Sign),
	}

	// Реєструємо стандартні креатори
	factory.RegisterCreator("hmac", createHMACSigner)
	factory.RegisterCreator("rsa", createRSASigner)
	factory.RegisterCreator("ed25519", createEd25519Signer)
	factory.RegisterCreator("ecdsa", createECDSASigner)

	return factory
}

// RegisterCreator реєструє новий креатор для алгоритму
func (sf *SignerFactory) RegisterCreator(algorithm string, creator SignerCreator) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	sf.creators[algorithm] = creator
}

// CreateSigner створює підписувача за алгоритмом та конфігурацією
func (sf *SignerFactory) CreateSigner(config SignerConfig) (Sign, error) {
	// Перевіряємо кеш
	cacheKey := sf.generateCacheKey(config)
	if cached, exists := sf.getFromCache(cacheKey); exists {
		return cached, nil
	}

	// Створюємо новий підписувач
	sf.mu.RLock()
	creator, exists := sf.creators[config.Algorithm]
	sf.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unsupported algorithm: %s", config.Algorithm)
	}

	signer, err := creator(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s signer: %w", config.Algorithm, err)
	}

	// Зберігаємо в кеш
	sf.addToCache(cacheKey, signer)

	return signer, nil
}

// CreateSignerWithCache створює підписувача з кешуванням
func (sf *SignerFactory) CreateSignerWithCache(config SignerConfig) (Sign, error) {
	return sf.CreateSigner(config)
}

// GetSupportedAlgorithms повертає список підтримуваних алгоритмів
func (sf *SignerFactory) GetSupportedAlgorithms() []string {
	sf.mu.RLock()
	defer sf.mu.RUnlock()

	algorithms := make([]string, 0, len(sf.creators))
	for algo := range sf.creators {
		algorithms = append(algorithms, algo)
	}
	return algorithms
}

// ClearCache очищає кеш підписувачів
func (sf *SignerFactory) ClearCache() {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	sf.cache = make(map[string]Sign)
}

// GetCacheStats повертає статистику кешу
func (sf *SignerFactory) GetCacheStats() map[string]interface{} {
	sf.mu.RLock()
	defer sf.mu.RUnlock()

	return map[string]interface{}{
		"cached_signers":       len(sf.cache),
		"supported_algorithms": len(sf.creators),
	}
}

// generateCacheKey генерує ключ для кешу
func (sf *SignerFactory) generateCacheKey(config SignerConfig) string {
	// Простий ключ на основі алгоритму та ключів
	return fmt.Sprintf("%s:%s:%s", config.Algorithm, config.APIKey, config.PublicKey)
}

// getFromCache отримує підписувача з кешу
func (sf *SignerFactory) getFromCache(key string) (Sign, bool) {
	sf.mu.RLock()
	defer sf.mu.RUnlock()
	signer, exists := sf.cache[key]
	return signer, exists
}

// addToCache додає підписувача в кеш
func (sf *SignerFactory) addToCache(key string, signer Sign) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	sf.cache[key] = signer
}

// createHMACSigner створює HMAC підписувача
func createHMACSigner(config SignerConfig) (Sign, error) {
	if config.SecretKey == "" {
		return nil, fmt.Errorf("secret key is required for HMAC")
	}
	return NewSignHMAC(PublicKey(config.APIKey), SecretKey(config.SecretKey)), nil
}

// createRSASigner створює RSA підписувача
func createRSASigner(config SignerConfig) (Sign, error) {
	if config.PublicKey == "" || config.PrivateKey == "" {
		return nil, fmt.Errorf("both public and private keys are required for RSA")
	}
	return NewSignRSA(config.APIKey, config.PublicKey, config.PrivateKey)
}

// createEd25519Signer створює Ed25519 підписувача
func createEd25519Signer(config SignerConfig) (Sign, error) {
	if config.PublicKey == "" || config.PrivateKey == "" {
		return nil, fmt.Errorf("both public and private keys are required for Ed25519")
	}
	return NewSignEd25519(config.APIKey, config.PublicKey, config.PrivateKey)
}

// createECDSASigner створює ECDSA підписувача
func createECDSASigner(config SignerConfig) (Sign, error) {
	if config.PublicKey == "" || config.PrivateKey == "" {
		return nil, fmt.Errorf("both public and private keys are required for ECDSA")
	}
	// ECDSA не реалізує інтерфейс Sign через різні сигнатури
	// Повертаємо помилку для цього алгоритму
	return nil, fmt.Errorf("ECDSA not yet fully integrated with Sign interface")
}

// Глобальна фабрика
var GlobalSignerFactory = NewSignerFactory()

// CreateSigner глобальна функція для створення підписувача
func CreateSigner(config SignerConfig) (Sign, error) {
	return GlobalSignerFactory.CreateSigner(config)
}

// CreateSignerWithCache глобальна функція для створення підписувача з кешуванням
func CreateSignerWithCache(config SignerConfig) (Sign, error) {
	return GlobalSignerFactory.CreateSignerWithCache(config)
}
