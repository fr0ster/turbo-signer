package signature_test

import (
	"testing"

	"github.com/fr0ster/turbo-signer/signature"
	"github.com/stretchr/testify/assert"
)

// Test 4: Sign Ed25519
func TestStringSignEd25519(t *testing.T) {
	const publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw9lhPqnUzA1vnPz+vYpzl9BQwGVUrsKqEk1co+bKSYQ=
-----END PUBLIC KEY-----`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMlz8ym0r5xai1MbDRJo+8HwkaVXWknuQhfFrphnpNwC
-----END PRIVATE KEY-----`
	func() {
		sign, err :=
			signature.NewSignEd25519(
				"apy_key",
				publicKey,
				privateKey)
		assert.Nil(t, err)

		message := "timestamp=1610612740000"
		// Створення підпису
		signature := sign.CreateSignature(message)
		expected := "pYQHhxozljZc0/wqTz4I1i1GmJbzQpdT8AHILc1ZZHF7YvjsUDRtTVBJpktdx10Z1Iy37wbJJjRtbMDpyx9BCQ=="
		assert.Equal(t, expected, signature)
	}()
}

// Test 5: Validate Ed25519
func TestStringValidateEd25519(t *testing.T) {
	const publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw9lhPqnUzA1vnPz+vYpzl9BQwGVUrsKqEk1co+bKSYQ=
-----END PUBLIC KEY-----`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMlz8ym0r5xai1MbDRJo+8HwkaVXWknuQhfFrphnpNwC
-----END PRIVATE KEY-----`
	func() {
		sign, err :=
			signature.NewSignEd25519(
				"apy_key",
				publicKey,
				privateKey)
		assert.Nil(t, err)
		message := "timestamp=1610612740000"
		// Створення підпису
		signature := sign.CreateSignature(message)
		// Валідація підпису
		valid := sign.ValidateSignature(message, signature)
		assert.True(t, valid)
	}()
}

// Test 6: Validate Ed25519 with wrong signature
func TestStringValidateEd25519WrongSignature(t *testing.T) {
	const publicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw9lhPqnUzA1vnPz+vYpzl9BQwGVUrsKqEk1co+bKSYQ=
-----END PUBLIC KEY-----`
	const privateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMlz8ym0r5xai1MbDRJo+8HwkaVXWknuQhfFrphnpNwC
-----END PRIVATE KEY-----`
	func() {
		sign, err :=
			signature.NewSignEd25519(
				"apy_key",
				publicKey,
				privateKey)
		assert.Nil(t, err)
		message := "timestamp=1610612740000"
		// Валідація підпису
		valid := sign.ValidateSignature(message, "wrong_signature")
		assert.False(t, valid)
	}()
}
