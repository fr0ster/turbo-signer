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
	sign := signature.NewSignHMAC("apy_key", "apy_secret")
	params := simplejson.New()
	params.Set("timestamp", 1610612740000)
	signedParams, err := sign.SignParameters(params)
	assert.Nil(t, err)
	expected := `{"signature":"b9739a6b6322ff0490293f52807fc895cddf41cdb34c178b346589148fec3b66","timestamp":1610612740000}`
	result, err := signedParams.MarshalJSON()
	assert.Nil(t, err)
	assert.Equal(t, expected, string(result))
	assert.Empty(t, params.Get("signature").Interface())
}
