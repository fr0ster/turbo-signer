package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/bitly/go-simplejson"
)

type SignHMAC struct {
	apiSecret string
	apiKey    string
}

// Функція для створення підпису з обробкою помилок
func (sign *SignHMAC) CreateSignature(queryString string) (string, error) {
	// Валідація повідомлення
	if err := sign.ValidateMessageFormat(queryString); err != nil {
		return "", err
	}

	// Валідація ключа
	if err := sign.ValidateKeyStrength(); err != nil {
		return "", err
	}

	h := hmac.New(sha256.New, []byte(sign.apiSecret))
	h.Write([]byte(queryString))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (sign *SignHMAC) SignParameters(params *simplejson.Json) (*simplejson.Json, error) {
	return signParameters(params, sign)
}

func (sign *SignHMAC) ValidateSignatureParams(params *simplejson.Json) (bool, error) {
	// Считування сігнатури
	signature := params.Get("signature").MustString()
	if signature == "" {
		return false, NewSignatureError(ErrInvalidFormat, "signature field is missing")
	}

	// Видалення підпису з параметрів
	js, err := params.MarshalJSON()
	if err != nil {
		return false, NewSignatureErrorWithDetails(ErrInternalError, "failed to marshal params", map[string]interface{}{
			"error": err.Error(),
		})
	}

	unsignedParams, err := simplejson.NewJson(js)
	if err != nil {
		return false, NewSignatureErrorWithDetails(ErrInternalError, "failed to create unsigned params", map[string]interface{}{
			"error": err.Error(),
		})
	}

	unsignedParams.Del("signature")

	expectedSignature, err := func() (string, error) {
		paramsStr, err := ConvertSimpleJSONToString(unsignedParams)
		if err != nil {
			return "", err
		}
		return paramsStr, nil
	}()

	if err != nil {
		return false, NewSignatureErrorWithDetails(ErrInternalError, "failed to convert params to string", map[string]interface{}{
			"error": err.Error(),
		})
	}

	return sign.ValidateSignature(expectedSignature, signature)
}

func (sign *SignHMAC) ValidateSignature(message, signature string) (bool, error) {
	// Валідація вхідних параметрів
	if err := sign.ValidateMessageFormat(message); err != nil {
		return false, err
	}

	if signature == "" {
		return false, NewSignatureError(ErrInvalidFormat, "signature is empty")
	}

	// Створення очікуваного підпису
	expectedSignature, err := sign.CreateSignature(message)
	if err != nil {
		return false, err
	}

	// Порівняння підписів
	return expectedSignature == signature, nil
}

func (sign *SignHMAC) GetAPIKey() string {
	return sign.apiKey
}

// Нова функція: валідація сили ключа
func (sign *SignHMAC) ValidateKeyStrength() error {
	if len(sign.apiSecret) < 32 {
		return NewSignatureErrorWithDetails(ErrKeyTooShort, "API secret key is too short", map[string]interface{}{
			"current_length": len(sign.apiSecret),
			"minimum_length": 32,
		})
	}
	return nil
}

// Нова функція: валідація формату повідомлення
func (sign *SignHMAC) ValidateMessageFormat(message string) error {
	if message == "" {
		return NewSignatureError(ErrEmptyMessage, "message cannot be empty")
	}

	if len(message) > 8192 {
		return NewSignatureErrorWithDetails(ErrMessageTooLong, "message is too long", map[string]interface{}{
			"current_length": len(message),
			"maximum_length": 8192,
		})
	}

	return nil
}

func NewSignHMAC(apiKey PublicKey, apiSecret SecretKey) *SignHMAC {
	return &SignHMAC{
		apiSecret: string(apiSecret),
		apiKey:    string(apiKey),
	}
}
