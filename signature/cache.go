package signature

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// KeyCache кеш для зберігання розпарсених ключів
type KeyCache struct {
	mu       sync.RWMutex
	keys     map[string]*CachedKey
	maxSize  int
	ttl      time.Duration
	cleanup  *time.Ticker
	stopChan chan struct{}
}

// CachedKey закешований ключ
type CachedKey struct {
	Key       interface{}
	Type      string
	CreatedAt time.Time
	LastUsed  time.Time
	UseCount  int
}

// NewKeyCache створює новий кеш ключів
func NewKeyCache(maxSize int, ttl time.Duration) *KeyCache {
	cache := &KeyCache{
		keys:     make(map[string]*CachedKey),
		maxSize:  maxSize,
		ttl:      ttl,
		cleanup:  time.NewTicker(5 * time.Minute), // Очищення кожні 5 хвилин
		stopChan: make(chan struct{}),
	}

	go cache.cleanupRoutine()
	return cache
}

// Get отримує ключ з кешу
func (kc *KeyCache) Get(keyHash string) (interface{}, bool) {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	if cached, exists := kc.keys[keyHash]; exists {
		// Перевіряємо TTL
		if time.Since(cached.CreatedAt) > kc.ttl {
			delete(kc.keys, keyHash)
			return nil, false
		}

		// Оновлюємо статистику використання
		cached.LastUsed = time.Now()
		cached.UseCount++
		return cached.Key, true
	}

	return nil, false
}

// Set зберігає ключ в кеш
func (kc *KeyCache) Set(keyHash string, key interface{}, keyType string) {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	// Якщо кеш переповнений, видаляємо найстаріший ключ
	if len(kc.keys) >= kc.maxSize {
		kc.evictOldest()
	}

	kc.keys[keyHash] = &CachedKey{
		Key:       key,
		Type:      keyType,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		UseCount:  1,
	}
}

// Remove видаляє ключ з кешу
func (kc *KeyCache) Remove(keyHash string) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	delete(kc.keys, keyHash)
}

// Clear очищає весь кеш
func (kc *KeyCache) Clear() {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	kc.keys = make(map[string]*CachedKey)
}

// Size повертає розмір кешу
func (kc *KeyCache) Size() int {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return len(kc.keys)
}

// Stats повертає статистику кешу
func (kc *KeyCache) Stats() map[string]interface{} {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	stats := map[string]interface{}{
		"size":      len(kc.keys),
		"max_size":  kc.maxSize,
		"ttl":       kc.ttl.String(),
		"key_types": make(map[string]int),
	}

	for _, cached := range kc.keys {
		keyType := cached.Type
		if count, exists := stats["key_types"].(map[string]int); exists {
			count[keyType]++
		}
	}

	return stats
}

// evictOldest видаляє найстаріший ключ з кешу
func (kc *KeyCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range kc.keys {
		if oldestKey == "" || cached.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(kc.keys, oldestKey)
	}
}

// cleanupRoutine регулярно очищає застарілі ключі
func (kc *KeyCache) cleanupRoutine() {
	for {
		select {
		case <-kc.cleanup.C:
			kc.cleanupExpired()
		case <-kc.stopChan:
			kc.cleanup.Stop()
			return
		}
	}
}

// cleanupExpired видаляє застарілі ключі
func (kc *KeyCache) cleanupExpired() {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	now := time.Now()
	for key, cached := range kc.keys {
		if now.Sub(cached.CreatedAt) > kc.ttl {
			delete(kc.keys, key)
		}
	}
}

// Stop зупиняє кеш
func (kc *KeyCache) Stop() {
	close(kc.stopChan)
}

// generateKeyHash генерує хеш для ключа
func generateKeyHash(keyContent string) string {
	hash := sha256.Sum256([]byte(keyContent))
	return hex.EncodeToString(hash[:])
}

// GlobalKeyCache глобальний кеш ключів
var GlobalKeyCache = NewKeyCache(100, 30*time.Minute)

// CacheableKey інтерфейс для ключів, які можна кешувати
type CacheableKey interface {
	GetKeyContent() string
	GetKeyType() string
}

// LoadKeyFromCache завантажує ключ з кешу або створює новий
func LoadKeyFromCache(keyContent string, keyType string, loader func() (interface{}, error)) (interface{}, error) {
	keyHash := generateKeyHash(keyContent)

	// Спробуємо отримати з кешу
	if cached, exists := GlobalKeyCache.Get(keyHash); exists {
		return cached, nil
	}

	// Завантажуємо новий ключ
	key, err := loader()
	if err != nil {
		return nil, err
	}

	// Зберігаємо в кеш
	GlobalKeyCache.Set(keyHash, key, keyType)
	return key, nil
}

// LoadRSAPrivateKeyFromCache завантажує RSA приватний ключ з кешу
func LoadRSAPrivateKeyFromCache(content string) (*rsa.PrivateKey, error) {
	key, err := LoadKeyFromCache(content, "rsa_private", func() (interface{}, error) {
		return loadRSAPrivateKeyFromPEM(content)
	})
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PrivateKey), nil
}

// LoadECDSAPrivateKeyFromCache завантажує ECDSA приватний ключ з кешу
func LoadECDSAPrivateKeyFromCache(content string) (*ecdsa.PrivateKey, error) {
	key, err := LoadKeyFromCache(content, "ecdsa_private", func() (interface{}, error) {
		return loadECDSAPrivateKeyFromPEM(content)
	})
	if err != nil {
		return nil, err
	}
	return key.(*ecdsa.PrivateKey), nil
}

// LoadECDSAPublicKeyFromCache завантажує ECDSA публічний ключ з кешу
func LoadECDSAPublicKeyFromCache(content string) (*ecdsa.PublicKey, error) {
	key, err := LoadKeyFromCache(content, "ecdsa_public", func() (interface{}, error) {
		return loadECDSAPublicKeyFromPEM(content)
	})
	if err != nil {
		return nil, err
	}
	return key.(*ecdsa.PublicKey), nil
}

// LoadEd25519PrivateKeyFromCache завантажує Ed25519 приватний ключ з кешу
func LoadEd25519PrivateKeyFromCache(content string) (ed25519.PrivateKey, error) {
	key, err := LoadKeyFromCache(content, "ed25519_private", func() (interface{}, error) {
		return loadEd25519PrivateKeyFromPEM(content)
	})
	if err != nil {
		return nil, err
	}
	return key.(ed25519.PrivateKey), nil
}

// LoadEd25519PublicKeyFromCache завантажує Ed25519 публічний ключ з кешу
func LoadEd25519PublicKeyFromCache(content string) (ed25519.PublicKey, error) {
	key, err := LoadKeyFromCache(content, "ed25519_public", func() (interface{}, error) {
		return loadEd25519PublicKeyFromPEM(content)
	})
	if err != nil {
		return nil, err
	}
	return key.(ed25519.PublicKey), nil
}
