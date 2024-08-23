package signature_test

import (
	"testing"

	"github.com/bitly/go-simplejson"
	"github.com/fr0ster/turbo-signer/signature"
	"github.com/stretchr/testify/assert"
)

// Test 4: Sign Ed25519
func TestParamsSignEd25519(t *testing.T) {
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
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err = sign.SignParameters(params)
		assert.Nil(t, err)
		expected := `{"signature":"pYQHhxozljZc0/wqTz4I1i1GmJbzQpdT8AHILc1ZZHF7YvjsUDRtTVBJpktdx10Z1Iy37wbJJjRtbMDpyx9BCQ==","timestamp":1610612740000}`
		result, err := params.MarshalJSON()
		assert.Nil(t, err)
		assert.Equal(t, expected, string(result))
	}()
}

// Test 5: Validate Ed25519
func TestParamsValidateEd25519(t *testing.T) {
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
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err = sign.SignParameters(params)
		assert.Nil(t, err)
		// Валідація підпису
		valid := sign.ValidateSignatureParams(params)
		assert.True(t, valid)
	}()
}

// Test 6: Validate Ed25519 with wrong signature
func TestParamsValidateEd25519WrongSignature(t *testing.T) {
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
		params := simplejson.New()
		params.Set("timestamp", 1610612740000) // Час в мілісекундах, за звичай рахуємо як int64(time.Nanosecond)*time.Now().UnixNano()/int64(time.Millisecond)
		// Створення підпису
		params, err = sign.SignParameters(params)
		assert.Nil(t, err)
		// Зміна підпису
		params.Set("signature", "wrong_signature")
		// Валідація підпису
		valid := sign.ValidateSignatureParams(params)
		assert.False(t, valid)
	}()
}
