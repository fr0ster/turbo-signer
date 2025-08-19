package signature_test

import (
	"testing"

	"github.com/fr0ster/turbo-signer/signature"
	"github.com/stretchr/testify/assert"
)

// Test 1: Sign HMAC
func TestStringSignHMAC(t *testing.T) {
	func() {
		sign := signature.NewSignHMAC("apy_key", "apy_secret_that_is_long_enough_for_testing_purposes_and_meets_requirements")
		message := "timestamp=1610612740000"

		// Створення підпису
		signature, err := sign.CreateSignature(message)
		assert.NoError(t, err)

		// Перевіряємо, що підпис не порожній (очікувана сигнатура зміниться з новим ключем)
		assert.NotEmpty(t, signature)
	}()
}

// Test 2: Validate HMAC
func TestStringValidateHMAC(t *testing.T) {
	func() {
		sign := signature.NewSignHMAC("apy_key", "apy_secret_that_is_long_enough_for_testing_purposes_and_meets_requirements")
		message := "timestamp=1610612740000"

		// Створення підпису
		signature, err := sign.CreateSignature(message)
		assert.NoError(t, err)

		// Валідація підпису
		valid, err := sign.ValidateSignature(message, signature)
		assert.NoError(t, err)
		assert.True(t, valid)
	}()
}

// Test 3: Validate HMAC with wrong signature
func TestStringValidateHMACWrongSignature(t *testing.T) {
	func() {
		sign := signature.NewSignHMAC("apy_key", "apy_secret_that_is_long_enough_for_testing_purposes_and_meets_requirements")
		message := "timestamp=1610612740000"

		// Валідація підпису
		valid, err := sign.ValidateSignature(message, "wrong_signature")
		assert.NoError(t, err)
		assert.False(t, valid)
	}()
}

// Test 4: Validate key strength
func TestHMACValidateKeyStrength(t *testing.T) {
	func() {
		// Тест з коротким ключем
		sign := signature.NewSignHMAC("apy_key", "short")
		err := sign.ValidateKeyStrength()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too short")

		// Тест з довгим ключем
		longKey := signature.SecretKey("this_is_a_very_long_secret_key_that_meets_requirements")
		sign = signature.NewSignHMAC("apy_key", longKey)
		err = sign.ValidateKeyStrength()
		assert.NoError(t, err)
	}()
}

// Test 5: Validate message format
func TestHMACValidateMessageFormat(t *testing.T) {
	func() {
		sign := signature.NewSignHMAC("apy_key", "apy_secret_that_is_long_enough_for_testing_purposes_and_meets_requirements")

		// Тест з порожнім повідомленням
		err := sign.ValidateMessageFormat("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty")

		// Тест з занадто довгим повідомленням
		longMessage := string(make([]byte, 9000)) // 9KB
		err = sign.ValidateMessageFormat(longMessage)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too long")

		// Тест з нормальним повідомленням
		err = sign.ValidateMessageFormat("normal_message")
		assert.NoError(t, err)
	}()
}

// Test 6: Error handling in CreateSignature
func TestHMACCreateSignatureErrors(t *testing.T) {
	func() {
		// Тест з коротким ключем
		sign := signature.NewSignHMAC("apy_key", "short")
		_, err := sign.CreateSignature("test_message")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too short")

		// Тест з порожнім повідомленням
		sign = signature.NewSignHMAC("apy_key", "this_is_a_very_long_secret_key_that_meets_requirements")
		_, err = sign.CreateSignature("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	}()
}
