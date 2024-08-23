package signature_test

import (
	"testing"

	"github.com/fr0ster/turbo-signer/signature"
	"github.com/stretchr/testify/assert"
)

// Test 1: Sign HMAC
func TestStringSignHMAC(t *testing.T) {
	func() {
		sign := signature.NewSignHMAC("apy_key", "apy_secret")
		message := "timestamp=1610612740000"
		// Створення підпису
		signature := sign.CreateSignature(message)
		expected := "b9739a6b6322ff0490293f52807fc895cddf41cdb34c178b346589148fec3b66"
		assert.Equal(t, expected, signature)
	}()
}

// Test 2: Validate HMAC
func TestStringValidateHMAC(t *testing.T) {
	func() {
		sign := signature.NewSignHMAC("apy_key", "apy_secret")
		message := "timestamp=1610612740000"
		// Створення підпису
		signature := sign.CreateSignature(message)
		// Валідація підпису
		valid := sign.ValidateSignature(message, signature)
		assert.True(t, valid)
	}()
}

// Test 3: Validate HMAC with wrong signature
func TestStringValidateHMACWrongSignature(t *testing.T) {
	func() {
		sign := signature.NewSignHMAC("apy_key", "apy_secret")
		message := "timestamp=1610612740000"
		// Валідація підпису
		valid := sign.ValidateSignature(message, "wrong_signature")
		assert.False(t, valid)
	}()
}
