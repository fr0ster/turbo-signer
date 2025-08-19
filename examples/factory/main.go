// Package demonstrates how to use the SignerFactory for creating different types of signers.
// This is a demo file showing factory pattern usage in turbo-signer.
//
// To run this demo:
//
//	go run factory_demo.go
package main

import (
	"fmt"
	"log"

	"github.com/fr0ster/turbo-signer/signature"
)

func main() {
	factoryDemo()
}

func factoryDemo() {
	fmt.Println("=== Turbo Signer Factory Example ===")

	// Демонструємо створення різних типів підписувачів
	demonstrateHMACSigner()
	demonstrateRSASigner()
	demonstrateEd25519Signer()
	demonstrateFactoryFeatures()
	demonstrateGlobalFactory()
}

func demonstrateHMACSigner() {
	fmt.Println("\n--- HMAC Signer Demo ---")

	config := signature.SignerConfig{
		Algorithm: "hmac",
		APIKey:    "hmac_api_key",
		SecretKey: "hmac_secret_key_that_is_long_enough_for_testing",
	}

	signer, err := signature.CreateSigner(config)
	if err != nil {
		log.Printf("Failed to create HMAC signer: %v", err)
		return
	}

	message := "timestamp=1234567890&symbol=BTCUSDT"
	sig, err := signer.CreateSignature(message)
	if err != nil {
		log.Printf("Failed to create signature: %v", err)
		return
	}

	fmt.Printf("HMAC Signature: %s...\n", sig[:20])
	fmt.Printf("API Key: %s\n", signer.GetAPIKey())
}

func demonstrateRSASigner() {
	fmt.Println("\n--- RSA Signer Demo ---")

	// Тестові RSA ключі
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
		APIKey:     "rsa_api_key",
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	signer, err := signature.CreateSigner(config)
	if err != nil {
		log.Printf("Failed to create RSA signer: %v", err)
		return
	}

	message := "timestamp=1234567890&symbol=ETHUSDT"
	sig, err := signer.CreateSignature(message)
	if err != nil {
		log.Printf("Failed to create signature: %v", err)
		return
	}

	fmt.Printf("RSA Signature: %s...\n", sig[:20])
	fmt.Printf("API Key: %s\n", signer.GetAPIKey())
}

func demonstrateEd25519Signer() {
	fmt.Println("\n--- Ed25519 Signer Demo ---")

	// Тестові Ed25519 ключі
	const publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw9lhPqnUzA1vnPz+vYpzl9BQwGVUrsKqEk1co+bKSYQ=`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMlz8ym0r5xai1MbDRJo+8HwkaVXWknuQhfFrphnpNwC`

	config := signature.SignerConfig{
		Algorithm:  "ed25519",
		APIKey:     "ed25519_api_key",
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	signer, err := signature.CreateSigner(config)
	if err != nil {
		log.Printf("Failed to create Ed25519 signer: %v", err)
		return
	}

	message := "timestamp=1234567890&symbol=ADAUSDT"
	sig, err := signer.CreateSignature(message)
	if err != nil {
		log.Printf("Failed to create signature: %v", err)
		return
	}

	fmt.Printf("Ed25519 Signature: %s...\n", sig[:20])
	fmt.Printf("API Key: %s\n", signer.GetAPIKey())
}

func demonstrateFactoryFeatures() {
	fmt.Println("\n--- Factory Features Demo ---")

	factory := signature.NewSignerFactory()

	// Показуємо підтримувані алгоритми
	algorithms := factory.GetSupportedAlgorithms()
	fmt.Printf("Supported algorithms: %v\n", algorithms)

	// Демонструємо кешування
	config := signature.SignerConfig{
		Algorithm: "hmac",
		APIKey:    "cache_test_key",
		SecretKey: "cache_test_secret_that_is_long_enough_for_testing",
	}

	// Створюємо перший підписувач
	signer1, err := factory.CreateSigner(config)
	if err != nil {
		log.Printf("Failed to create first signer: %v", err)
		return
	}

	// Створюємо другий підписувач з тією ж конфігурацією
	signer2, err := factory.CreateSigner(config)
	if err != nil {
		log.Printf("Failed to create second signer: %v", err)
		return
	}

	// Перевіряємо, що це той самий екземпляр (кешований)
	if signer1 == signer2 {
		fmt.Println("✅ Caching works: Same signer instance returned")
	} else {
		fmt.Println("❌ Caching failed: Different signer instances")
	}

	// Показуємо статистику кешу
	stats := factory.GetCacheStats()
	fmt.Printf("Cache stats: %+v\n", stats)

	// Очищаємо кеш
	factory.ClearCache()
	fmt.Println("Cache cleared")

	// Показуємо оновлену статистику
	stats = factory.GetCacheStats()
	fmt.Printf("Updated cache stats: %+v\n", stats)
}

func demonstrateGlobalFactory() {
	fmt.Println("\n--- Global Factory Demo ---")

	// Використовуємо глобальну фабрику
	config := signature.SignerConfig{
		Algorithm: "hmac",
		APIKey:    "global_test_key",
		SecretKey: "global_test_secret_that_is_long_enough_for_testing",
	}

	// Створюємо підписувача через глобальну функцію
	signer, err := signature.CreateSigner(config)
	if err != nil {
		log.Printf("Failed to create signer via global function: %v", err)
		return
	}

	message := "timestamp=1234567890&symbol=GLOBAL"
	sig, err := signer.CreateSignature(message)
	if err != nil {
		log.Printf("Failed to create signature: %v", err)
		return
	}

	fmt.Printf("Global Factory Signature: %s...\n", sig[:20])

	// Показуємо статистику глобальної фабрики
	stats := signature.GlobalSignerFactory.GetCacheStats()
	fmt.Printf("Global factory cache stats: %+v\n", stats)
}
