package signature_test

import (
	"testing"

	"github.com/bitly/go-simplejson"
	"github.com/fr0ster/turbo-signer/signature"
	"github.com/stretchr/testify/assert"
)

// Test 1: Sign HMAC Parameters
func TestParamsSignHMAC(t *testing.T) {
	func() {
		// Використовуємо довший ключ для тестування
		longSecret := signature.SecretKey("apy_secret_that_is_long_enough_for_testing_purposes_and_meets_requirements")
		sign := signature.NewSignHMAC("apy_key", longSecret)
		params := simplejson.New()
		params.Set("timestamp", 1610612740000)

		// Створення підпису
		signedParams, err := sign.SignParameters(params)
		assert.NoError(t, err)
		assert.NotNil(t, signedParams)

		// Перевірка, що підпис додано
		signature := signedParams.Get("signature").MustString()
		assert.NotEmpty(t, signature)
	}()
}

// Test 2: Validate HMAC Parameters
func TestParamsValidateHMAC(t *testing.T) {
	func() {
		// Використовуємо довший ключ для тестування
		longSecret := signature.SecretKey("apy_secret_that_is_long_enough_for_testing_purposes_and_meets_requirements")
		sign := signature.NewSignHMAC("apy_key", longSecret)
		params := simplejson.New()
		params.Set("timestamp", 1610612740000)

		// Створення підпису
		signedParams, err := sign.SignParameters(params)
		assert.NoError(t, err)

		// Валідація підпису
		valid, err := sign.ValidateSignatureParams(signedParams)
		assert.NoError(t, err)
		assert.True(t, valid)
	}()
}

// Test 3: Validate HMAC Parameters with wrong signature
func TestParamsValidateHMACWrongSignature(t *testing.T) {
	func() {
		// Використовуємо довший ключ для тестування
		longSecret := signature.SecretKey("apy_secret_that_is_long_enough_for_testing_purposes_and_meets_requirements")
		sign := signature.NewSignHMAC("apy_key", longSecret)
		params := simplejson.New()
		params.Set("timestamp", 1610612740000)

		// Створення підпису
		signedParams, err := sign.SignParameters(params)
		assert.NoError(t, err)

		// Зміна підпису
		signedParams.Set("signature", "wrong_signature")

		// Валідація підпису
		valid, err := sign.ValidateSignatureParams(signedParams)
		assert.NoError(t, err)
		assert.False(t, valid)
	}()
}

// Test 4: Validate HMAC Parameters without signature
func TestParamsValidateHMACNoSignature(t *testing.T) {
	func() {
		// Використовуємо довший ключ для тестування
		longSecret := signature.SecretKey("apy_secret_that_is_long_enough_for_testing_purposes_and_meets_requirements")
		sign := signature.NewSignHMAC("apy_key", longSecret)
		params := simplejson.New()
		params.Set("timestamp", 1610612740000)

		// Валідація без підпису
		valid, err := sign.ValidateSignatureParams(params)
		assert.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "signature field is missing")
	}()
}
