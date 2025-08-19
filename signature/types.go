package signature

import (
	"time"
	"github.com/bitly/go-simplejson"
)

type (
	PublicKey string
	SecretKey string
	
	// Покращений інтерфейс підпису
	Sign interface {
		CreateSignature(queryString string) (string, error)
		SignParameters(params *simplejson.Json) (*simplejson.Json, error)
		ValidateSignatureParams(params *simplejson.Json) (bool, error)
		ValidateSignature(string, string) (bool, error)
		GetAPIKey() string
		ValidateKeyStrength() error
		ValidateMessageFormat(message string) error
	}

	// Структуровані помилки
	SignatureError struct {
		Code    string                 `json:"code"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details,omitempty"`
		Time    int64                  `json:"time"`
	}

	// Коди помилок
	ErrorCode string
)

// Константи для кодів помилок
const (
	ErrInvalidKey        ErrorCode = "INVALID_KEY"
	ErrInvalidFormat     ErrorCode = "INVALID_FORMAT"
	ErrValidationFailed  ErrorCode = "VALIDATION_FAILED"
	ErrInternalError     ErrorCode = "INTERNAL_ERROR"
	ErrKeyTooShort       ErrorCode = "KEY_TOO_SHORT"
	ErrMessageTooLong    ErrorCode = "MESSAGE_TOO_LONG"
	ErrEmptyMessage      ErrorCode = "EMPTY_MESSAGE"
	ErrInvalidAlgorithm  ErrorCode = "INVALID_ALGORITHM"
)

// Методи для SignatureError
func (e *SignatureError) Error() string {
	return e.Message
}

func (e *SignatureError) GetCode() string {
	return e.Code
}

func (e *SignatureError) GetDetails() map[string]interface{} {
	return e.Details
}

// Функції для створення помилок
func NewSignatureError(code ErrorCode, message string) *SignatureError {
	return &SignatureError{
		Code:    string(code),
		Message: message,
		Time:    time.Now().Unix(),
		Details: make(map[string]interface{}),
	}
}

func NewSignatureErrorWithDetails(code ErrorCode, message string, details map[string]interface{}) *SignatureError {
	return &SignatureError{
		Code:    string(code),
		Message: message,
		Time:    time.Now().Unix(),
		Details: details,
	}
}
