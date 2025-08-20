package signature_test

import (
	"testing"

	"github.com/fr0ster/turbo-signer/v2/signature"
	"github.com/stretchr/testify/assert"
)

// TestSignerFactoryCreation тестує створення фабрики
func TestSignerFactoryCreation(t *testing.T) {
	factory := signature.NewSignerFactory()
	assert.NotNil(t, factory)

	// Перевіряємо, що стандартні алгоритми зареєстровані
	algorithms := factory.GetSupportedAlgorithms()
	assert.Contains(t, algorithms, "hmac")
	assert.Contains(t, algorithms, "rsa")
	assert.Contains(t, algorithms, "ed25519")
	assert.Contains(t, algorithms, "ecdsa")
}

// TestCreateHMACSigner тестує створення HMAC підписувача
func TestCreateHMACSigner(t *testing.T) {
	factory := signature.NewSignerFactory()

	config := signature.SignerConfig{
		Algorithm: "hmac",
		APIKey:    "test_api_key",
		SecretKey: "test_secret_key_that_is_long_enough_for_testing",
	}

	signer, err := factory.CreateSigner(config)
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	// Перевіряємо, що це HMAC підписувач
	hmacSigner, ok := signer.(*signature.SignHMAC)
	assert.True(t, ok)
	assert.Equal(t, "test_api_key", hmacSigner.GetAPIKey())
}

// TestCreateRSASigner тестує створення RSA підписувача
func TestCreateRSASigner(t *testing.T) {
	factory := signature.NewSignerFactory()

	// Використовуємо тестові ключі з існуючих тестів
	const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtBjXiXgAHU/pslRsD6wO
Ef4JFsYMHHgun0Q8PxKsukScwd1Eqpv0Gd0j6I/i/YtyAf6GmrMOUzIdCrULenDR
+xFtb+rBMQ+/JLiqsGm3Nc+glJsE4XVQOPZ3ILwqlvQ5K7LpSi3YO+Bko3vwCD7B
RpqfotBDi+SbK//3A8QyiiEVqh6XK2cG0qkhX3W4NahxOwc2LIpTKd6arZtg3DMc
RzG7fyGm/qbFXKH2Q3bjzO4uMUJhPUTUizGQH+vpMgIxfEgADtyr4J/Mz+UuzDWK
6akQi7UeE93aAEqTezqrUFhqc1sWXLB/8eE29H/HRW+mO0X0Oyv5Q8pDLiW8B42V
pwIDAQAB
-----END PUBLIC KEY-----`

	const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC0GNeJeAAdT+my
VGwPrA4R/gkWxgwceC6fRDw/Eqy6RJzB3USqm/QZ3SPoj+L9i3IB/oaasw5TMh0K
tQt6cNH7EW1v6sExD78kuKqwabc1z6CUmwThdVA49ncgvCqW9DkrsulKLdg74GSj
e/AIPsFGmp+i0EOL5Jsr//cDxDKKIRWqHpcrZwbSqSFfdbg1qHE7BzYsilMp3pqt
m2DcMxxHMbt/Iab+psVcofZDduPM7i4xQmE9RNSLMZAf6+kyAjF8SAAO3Kvgn8zP
5S7MNYrpqRCLtR4T3doASpN7OqtQWGpzWxZcsH/x4Tb0f8dFb6Y7RfQ7K/lDykMu
JbwHjZWnAgMBAAECggEAMrK/kjpOxfGmFwZ++RZ1S4lY46lS5XzLmxgpYZQPPcxs
2IJCf0ixucov/prqyndD293b5Ja9VJxJ4qa+mXRDGEt6pEPQqNAG/f5iRpEr+yD8
0nilMhbFQ5PWS0fNMXuE0JFn7PLk6U4s5nzQQHHyFL8Ya0v3h90N9Z/z2IKVu55E
/BF3Gub0/xsnD1qRj4QAk/rh5DP6X5O0q9ItqA9t92OWsfKo11HjfEAJohJeUGLA
KlGxImSeYjSG8mErVwQoHfQ8jEJZqsn3DAe4/vwEQ3ow1R0Ra0+XAWriT0PnpOFW
eGYh71eoagMAw2aW9IgPPH/gL9gtRHnSL7ecXMdWYQKBgQDwzz6+6PjA+18B5EA6
S4uHtYaX7eEbT/fWLDroicrZqSDv4Vjk+7ZwXyJMIyZjnBdrT7ShfoFC3f5o4lrF
tyi3CzWjHY6M6R5+eq7m3i4iZn9A1rRTjMzYhgMg58cI59uwU/QCG+Ukm8L2Lb6D
o7tsmC7SnzbYEcDxE5il/ov3kQKBgQC/dSuXiUuK2IzZzWqDekcYHh6AiO17BIOJ
RmC2kRWZmGV+bhnd1VTzQk2PQraYfcDQxSMwLpS2bELNq++OLzfKz3rQt8MuQZ9W
DEvfLunSLAPiOjcGfqvYPOEBEUbw1rumdsIWd3jIlmLtzj49vxtz3gVDYzMD9p4l
f50ObPlNtwKBgHtomi1YU3MC37Omd8voPz9zJeDihcRrfQWDcUUOqKhXZovInrfq
z5pTBs6iDOBrdA0Isfc5T6EnB2RU7FP7A6Ca3AgV86H/LiN/V/b00gvLH1fpMEzJ
EYm9VAke/v9vY0TAIYKbLRlPweBLnSD1Xe3PJ9/EvGSK5KgndMlM5AohAoGAJnW2
HQnCeBDKMpJ2HBU7JNggDnfzJKwidDgEA4ifiyw27y/U2GAbYYZnKCkhnv5b9lQz
nmEtFHwo60HnrGtFzOLi6/yOI8Og61sq/plg9QxMd2x0U0Ss5pJMLLe4xXaNWYIv
uO2lAL5c/yJYFHVIYX0vF3tc6yXmXOgGt7giWH8CgYASD3KZTZugdqWuBE9HNepp
W7uJwSLfGQs47i/LkgHDBlSRZOqODY9Y4KIcWuCK7gSu1duCzF+y6KTx5jW5ZYgJ
bvhsA8v6qN+jkbA2DR2CVFStAJXGRmic0D/KJ1lrOTzBIXLw8ZAO/HtwqE7Z1/eK
bSPd4xwzzEbd4WCAodhFMw==
-----END PRIVATE KEY-----`

	config := signature.SignerConfig{
		Algorithm:  "rsa",
		APIKey:     "test_api_key",
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	signer, err := factory.CreateSigner(config)
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	// Перевіряємо, що це RSA підписувач
	rsaSigner, ok := signer.(*signature.SignRSA)
	assert.True(t, ok)
	assert.Equal(t, "test_api_key", rsaSigner.GetAPIKey())
}

// TestCreateEd25519Signer тестує створення Ed25519 підписувача
func TestCreateEd25519Signer(t *testing.T) {
	factory := signature.NewSignerFactory()

	// Використовуємо тестові ключі з існуючих тестів
	const publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw9lhPqnUzA1vnPz+vYpzl9BQwGVUrsKqEk1co+bKSYQ=
-----END PUBLIC KEY-----`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMlz8ym0r5xai1MbDRJo+8HwkaVXWknuQhfFrphnpNwC
-----END PRIVATE KEY-----`

	config := signature.SignerConfig{
		Algorithm:  "ed25519",
		APIKey:     "test_api_key",
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	signer, err := factory.CreateSigner(config)
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	// Перевіряємо, що це Ed25519 підписувач
	ed25519Signer, ok := signer.(*signature.SignEd25519)
	assert.True(t, ok)
	assert.Equal(t, "test_api_key", ed25519Signer.GetAPIKey())
}

// TestCreateECDSASigner тестує створення ECDSA підписувача (поки не підтримується)
func TestCreateECDSASigner(t *testing.T) {
	factory := signature.NewSignerFactory()

	config := signature.SignerConfig{
		Algorithm:  "ecdsa",
		APIKey:     "test_api_key",
		PublicKey:  "test_public_key",
		PrivateKey: "test_private_key",
	}

	signer, err := factory.CreateSigner(config)
	assert.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "ECDSA not yet fully integrated")
}

// TestCreateSignerWithInvalidAlgorithm тестує створення підписувача з неправильним алгоритмом
func TestCreateSignerWithInvalidAlgorithm(t *testing.T) {
	factory := signature.NewSignerFactory()

	config := signature.SignerConfig{
		Algorithm: "invalid_algorithm",
		APIKey:    "test_api_key",
		SecretKey: "test_secret",
	}

	signer, err := factory.CreateSigner(config)
	assert.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

// TestCreateSignerWithMissingKeys тестує створення підписувача з відсутніми ключами
func TestCreateSignerWithMissingKeys(t *testing.T) {
	factory := signature.NewSignerFactory()

	// HMAC без секретного ключа
	config := signature.SignerConfig{
		Algorithm: "hmac",
		APIKey:    "test_api_key",
		// SecretKey відсутній
	}

	signer, err := factory.CreateSigner(config)
	assert.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "secret key is required for HMAC")

	// RSA без публічного ключа
	config = signature.SignerConfig{
		Algorithm:  "rsa",
		APIKey:     "test_api_key",
		PrivateKey: "test_private_key",
		// PublicKey відсутній
	}

	signer, err = factory.CreateSigner(config)
	assert.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "both public and private keys are required for RSA")
}

// TestSignerFactoryCaching тестує кешування фабрики
func TestSignerFactoryCaching(t *testing.T) {
	factory := signature.NewSignerFactory()

	config := signature.SignerConfig{
		Algorithm: "hmac",
		APIKey:    "test_api_key",
		SecretKey: "test_secret_key_that_is_long_enough_for_testing",
	}

	// Створюємо перший підписувач
	signer1, err := factory.CreateSigner(config)
	assert.NoError(t, err)
	assert.NotNil(t, signer1)

	// Створюємо другий підписувач з тією ж конфігурацією
	signer2, err := factory.CreateSigner(config)
	assert.NoError(t, err)
	assert.NotNil(t, signer2)

	// Перевіряємо, що це той самий екземпляр (кешований)
	assert.Equal(t, signer1, signer2)

	// Перевіряємо статистику кешу
	stats := factory.GetCacheStats()
	assert.Equal(t, 1, stats["cached_signers"])
}

// TestSignerFactoryClearCache тестує очищення кешу
func TestSignerFactoryClearCache(t *testing.T) {
	factory := signature.NewSignerFactory()

	config := signature.SignerConfig{
		Algorithm: "hmac",
		APIKey:    "test_api_key",
		SecretKey: "test_secret_key_that_is_long_enough_for_testing",
	}

	// Створюємо підписувача
	signer1, err := factory.CreateSigner(config)
	assert.NoError(t, err)

	// Очищаємо кеш
	factory.ClearCache()

	// Створюємо підписувача знову
	signer2, err := factory.CreateSigner(config)
	assert.NoError(t, err)

	// Перевіряємо, що підписувачі створені успішно
	assert.NotNil(t, signer1)
	assert.NotNil(t, signer2)

	// Перевіряємо статистику кешу (після створення нового підписувача)
	stats := factory.GetCacheStats()
	assert.Equal(t, 1, stats["cached_signers"])
}

// TestGlobalSignerFactory тестує глобальну фабрику
func TestGlobalSignerFactory(t *testing.T) {
	// Перевіряємо, що глобальна фабрика існує
	assert.NotNil(t, signature.GlobalSignerFactory)

	// Перевіряємо, що вона має стандартні алгоритми
	algorithms := signature.GlobalSignerFactory.GetSupportedAlgorithms()
	assert.Contains(t, algorithms, "hmac")
	assert.Contains(t, algorithms, "rsa")
	assert.Contains(t, algorithms, "ed25519")
}

// TestGlobalCreateSigner тестує глобальні функції створення
func TestGlobalCreateSigner(t *testing.T) {
	config := signature.SignerConfig{
		Algorithm: "hmac",
		APIKey:    "test_api_key",
		SecretKey: "test_secret_key_that_is_long_enough_for_testing",
	}

	// Тестуємо глобальну функцію CreateSigner
	signer, err := signature.CreateSigner(config)
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	// Тестуємо глобальну функцію CreateSignerWithCache
	signer2, err := signature.CreateSignerWithCache(config)
	assert.NoError(t, err)
	assert.NotNil(t, signer2)

	// Перевіряємо, що це той самий екземпляр (кешований)
	assert.Equal(t, signer, signer2)
}
