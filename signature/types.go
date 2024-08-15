package signature

import "github.com/bitly/go-simplejson"

type (
	PublicKey string
	SecretKey string
	Sign      interface {
		CreateSignature(queryString string) string
		SignParameters(params *simplejson.Json) (*simplejson.Json, error)
		ValidateSignature(params *simplejson.Json) bool
		GetAPIKey() string
	}
)
