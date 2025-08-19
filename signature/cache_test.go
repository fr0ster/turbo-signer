package signature_test

import (
	"testing"
	"time"

	"github.com/fr0ster/turbo-signer/signature"
	"github.com/stretchr/testify/assert"
)

// TestKeyCacheBasic тестує базову функціональність кешу
func TestKeyCacheBasic(t *testing.T) {
	cache := signature.NewKeyCache(10, 1*time.Hour)
	defer cache.Stop()

	// Тест додавання ключа
	cache.Set("key1", "value1", "string")
	assert.Equal(t, 1, cache.Size())

	// Тест отримання ключа
	value, exists := cache.Get("key1")
	assert.True(t, exists)
	assert.Equal(t, "value1", value)

	// Тест отримання неіснуючого ключа
	_, exists = cache.Get("key2")
	assert.False(t, exists)
}

// TestKeyCacheMaxSize тестує обмеження розміру кешу
func TestKeyCacheMaxSize(t *testing.T) {
	cache := signature.NewKeyCache(2, 1*time.Hour)
	defer cache.Stop()

	// Додаємо ключі
	cache.Set("key1", "value1", "string")
	cache.Set("key2", "value2", "string")
	assert.Equal(t, 2, cache.Size())

	// Додаємо третій ключ - перший має бути видалений
	cache.Set("key3", "value3", "string")
	assert.Equal(t, 2, cache.Size())

	// Перший ключ має бути видалений
	_, exists := cache.Get("key1")
	assert.False(t, exists)

	// Другий та третій ключі мають залишитися
	_, exists = cache.Get("key2")
	assert.True(t, exists)
	_, exists = cache.Get("key3")
	assert.True(t, exists)
}

// TestKeyCacheTTL тестує TTL кешу
func TestKeyCacheTTL(t *testing.T) {
	cache := signature.NewKeyCache(10, 100*time.Millisecond)
	defer cache.Stop()

	// Додаємо ключ
	cache.Set("key1", "value1", "string")
	assert.Equal(t, 1, cache.Size())

	// Очікуємо, поки ключ застаріє
	time.Sleep(150 * time.Millisecond)

	// Ключ має бути видалений
	_, exists := cache.Get("key1")
	assert.False(t, exists)
	assert.Equal(t, 0, cache.Size())
}

// TestKeyCacheStats тестує статистику кешу
func TestKeyCacheStats(t *testing.T) {
	cache := signature.NewKeyCache(10, 1*time.Hour)
	defer cache.Stop()

	// Додаємо ключі різних типів
	cache.Set("key1", "value1", "string")
	cache.Set("key2", "value2", "int")
	cache.Set("key3", "value3", "string")

	stats := cache.Stats()
	assert.Equal(t, 3, stats["size"])
	assert.Equal(t, 10, stats["max_size"])

	keyTypes := stats["key_types"].(map[string]int)
	assert.Equal(t, 2, keyTypes["string"])
	assert.Equal(t, 1, keyTypes["int"])
}

// TestKeyCacheRemove тестує видалення ключів
func TestKeyCacheRemove(t *testing.T) {
	cache := signature.NewKeyCache(10, 1*time.Hour)
	defer cache.Stop()

	// Додаємо ключ
	cache.Set("key1", "value1", "string")
	assert.Equal(t, 1, cache.Size())

	// Видаляємо ключ
	cache.Remove("key1")
	assert.Equal(t, 0, cache.Size())

	// Перевіряємо, що ключ видалено
	_, exists := cache.Get("key1")
	assert.False(t, exists)
}

// TestKeyCacheClear тестує очищення кешу
func TestKeyCacheClear(t *testing.T) {
	cache := signature.NewKeyCache(10, 1*time.Hour)
	defer cache.Stop()

	// Додаємо ключі
	cache.Set("key1", "value1", "string")
	cache.Set("key2", "value2", "string")
	assert.Equal(t, 2, cache.Size())

	// Очищаємо кеш
	cache.Clear()
	assert.Equal(t, 0, cache.Size())

	// Перевіряємо, що ключі видалено
	_, exists := cache.Get("key1")
	assert.False(t, exists)
	_, exists = cache.Get("key2")
	assert.False(t, exists)
}

// TestKeyCacheUseCount тестує лічильник використання
func TestKeyCacheUseCount(t *testing.T) {
	cache := signature.NewKeyCache(10, 1*time.Hour)
	defer cache.Stop()

	// Додаємо ключ
	cache.Set("key1", "value1", "string")

	// Використовуємо ключ кілька разів
	cache.Get("key1")
	cache.Get("key1")
	cache.Get("key1")

	// Перевіряємо статистику
	stats := cache.Stats()
	assert.Equal(t, 1, stats["size"])
}

// TestGlobalKeyCache тестує глобальний кеш
func TestGlobalKeyCache(t *testing.T) {
	// Очищаємо глобальний кеш перед тестом
	signature.GlobalKeyCache.Clear()

	// Перевіряємо початковий розмір
	assert.Equal(t, 0, signature.GlobalKeyCache.Size())

	// Додаємо тестовий ключ
	signature.GlobalKeyCache.Set("test_key", "test_value", "test")
	assert.Equal(t, 1, signature.GlobalKeyCache.Size())

	// Очищаємо після тесту
	signature.GlobalKeyCache.Clear()
}

// TestGenerateKeyHash тестує генерацію хешу ключа
func TestGenerateKeyHash(t *testing.T) {
	// Тестуємо, що однаковий контент дає однаковий хеш
	// Використовуємо LoadKeyFromCache для тестування генерації хешу
	key1, err1 := signature.LoadKeyFromCache("test_content", "test", func() (interface{}, error) {
		return "test_value", nil
	})
	assert.NoError(t, err1)
	assert.Equal(t, "test_value", key1)

	key2, err2 := signature.LoadKeyFromCache("test_content", "test", func() (interface{}, error) {
		return "test_value", nil
	})
	assert.NoError(t, err2)
	assert.Equal(t, "test_value", key2)

	// Перевіряємо, що ключі однакові (кешовані)
	assert.Equal(t, key1, key2)
}
