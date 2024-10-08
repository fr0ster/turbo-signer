package signature

import (
	"fmt"
	"net/url"

	"github.com/bitly/go-simplejson"
)

func ConvertSimpleJSONToString(js *simplejson.Json) (string, error) {
	// Парсинг JSON строки
	values := url.Values{}
	for key, value := range js.MustMap() {
		values.Set(key, fmt.Sprintf("%v", value))
	}

	return values.Encode(), nil
}

func signParameters(params *simplejson.Json, sign Sign) (*simplejson.Json, error) {
	// Створення підпису
	signature, err := ConvertSimpleJSONToString(params)
	if err != nil {
		return nil, fmt.Errorf("error encoding params: %v", err)
	}
	js, err := params.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("error marshalling params: %v", err)
	}
	signedParams, err := simplejson.NewJson(js)
	if err != nil {
		return nil, fmt.Errorf("error creating new json: %v", err)
	}
	signedParams.Set("signature", sign.CreateSignature(signature))
	return signedParams, nil
}
