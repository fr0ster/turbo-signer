package signature

import (
	"fmt"
	"net/url"

	"github.com/bitly/go-simplejson"
)

func convertSimpleJSONToString(js *simplejson.Json) (string, error) {
	// Парсинг JSON строки
	values := url.Values{}
	for key, value := range js.MustMap() {
		values.Set(key, fmt.Sprintf("%v", value))
	}

	return values.Encode(), nil
}

func SignParameters(params *simplejson.Json, sign Sign) (*simplejson.Json, error) {
	// Створення підпису
	signature, err := convertSimpleJSONToString(params)
	if err != nil {
		return nil, fmt.Errorf("error encoding params: %v", err)
	}
	params.Set("signature", sign.CreateSignature(signature))
	return params, nil
}
