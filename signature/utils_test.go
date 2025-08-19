package signature_test

import (
	"testing"

	"github.com/bitly/go-simplejson"
	"github.com/fr0ster/turbo-signer/signature"
	"github.com/stretchr/testify/assert"
)

func TestConvertSimpleJSONToString(t *testing.T) {
	params := simplejson.New()
	params.Set("timestamp", 1610612740000)
	result, err := signature.ConvertSimpleJSONToString(params)
	assert.Nil(t, err)
	expected := `timestamp=1610612740000`
	assert.Equal(t, expected, result)
}

func TestSignParameters(t *testing.T) {
	// Використовуємо довший ключ для тестування
	sign := signature.NewSignHMAC("apy_key", "apy_secret_that_is_long_enough_for_testing_purposes_and_meets_requirements")
	params := simplejson.New()
	params.Set("timestamp", 1610612740000)
	signedParams, err := sign.SignParameters(params)
	assert.Nil(t, err)

	// Перевіряємо, що підпис додано
	signature := signedParams.Get("signature").MustString()
	assert.NotEmpty(t, signature)

	// Перевіряємо, що timestamp залишився
	timestamp := signedParams.Get("timestamp").MustInt64()
	assert.Equal(t, int64(1610612740000), timestamp)

	// Перевіряємо, що оригінальні параметри не змінилися
	assert.Empty(t, params.Get("signature").Interface())
}
