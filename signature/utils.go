package signature

import (
	"fmt"
	"net/url"
	"time"

	"github.com/bitly/go-simplejson"
)

// RetryConfig налаштування для retry логіки
type RetryConfig struct {
	MaxRetries int
	Delay      time.Duration
	Backoff    float64 // Множник для збільшення затримки
}

// DefaultRetryConfig стандартні налаштування retry
var DefaultRetryConfig = RetryConfig{
	MaxRetries: 3,
	Delay:      100 * time.Millisecond,
	Backoff:    2.0,
}

// withRetry виконує функцію з retry логікою
func withRetry[T any](fn func() (T, error), config RetryConfig) (T, error) {
	var lastErr error
	delay := config.Delay

	for i := 0; i <= config.MaxRetries; i++ {
		if result, err := fn(); err == nil {
			return result, nil
		} else {
			lastErr = err
			if i < config.MaxRetries {
				time.Sleep(delay)
				delay = time.Duration(float64(delay) * config.Backoff)
			}
		}
	}

	var zero T
	return zero, fmt.Errorf("failed after %d retries: %w", config.MaxRetries, lastErr)
}

// withRetrySimple простий retry без конфігурації
func withRetrySimple[T any](fn func() (T, error), maxRetries int) (T, error) {
	config := DefaultRetryConfig
	config.MaxRetries = maxRetries
	return withRetry(fn, config)
}

func ConvertSimpleJSONToString(js *simplejson.Json) (string, error) {
	// Парсинг JSON строки
	values := url.Values{}
	for key, value := range js.MustMap() {
		values.Set(key, fmt.Sprintf("%v", value))
	}

	return values.Encode(), nil
}

func signParameters(params *simplejson.Json, sign Sign) (*simplejson.Json, error) {
	// Створення підпису з retry логікою
	signature, err := withRetrySimple(func() (string, error) {
		// Створення підпису
		message, err := ConvertSimpleJSONToString(params)
		if err != nil {
			return "", fmt.Errorf("error encoding params: %w", err)
		}

		return sign.CreateSignature(message)
	}, 2)

	if err != nil {
		return nil, fmt.Errorf("failed to create signature after retries: %w", err)
	}

	// Копіювання параметрів
	js, err := params.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("error marshalling params: %w", err)
	}

	signedParams, err := simplejson.NewJson(js)
	if err != nil {
		return nil, fmt.Errorf("error creating new json: %w", err)
	}

	signedParams.Set("signature", signature)
	return signedParams, nil
}
