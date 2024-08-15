package signature

import "github.com/bitly/go-simplejson"

type (
	PublicKey string
	SecretKey string
	Sign      interface {
		CreateSignature(queryString string) string
		SignParameters(params *simplejson.Json) (*simplejson.Json, error)
		ValidateSignatureParams(params *simplejson.Json) bool
		ValidateSignature(string, string) bool
		GetAPIKey() string
	}
)
