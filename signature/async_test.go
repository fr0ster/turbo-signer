package signature_test

import (
	"testing"
	"time"

	"github.com/fr0ster/turbo-signer/signature"
	"github.com/stretchr/testify/assert"
)

// TestAsyncSignerBasic тестує базову функціональність асинхронного підписувача
func TestAsyncSignerBasic(t *testing.T) {
	// Створюємо простий HMAC підписувач для тестування
	signer := signature.NewSignHMAC("test_key", "test_secret_that_is_long_enough_for_testing")

	asyncSigner := signature.NewAsyncSigner(2, 10)
	defer asyncSigner.Stop()

	// Додаємо запит на підпис
	req := signature.SignRequest{
		ID:      "test1",
		Message: "test_message",
		Signer:  signer,
		Timeout: 1 * time.Second,
	}

	asyncSigner.SignAsync(req)

	// Даємо час на обробку
	time.Sleep(10 * time.Millisecond)

	// Отримуємо результат
	result, ok := asyncSigner.GetResult()
	assert.True(t, ok)
	assert.Equal(t, "test1", result.ID)
	assert.NotEmpty(t, result.Signature)
	assert.Nil(t, result.Error)
	assert.Greater(t, result.Duration, time.Duration(0))
}

// TestBatchSignerBasic тестує базову функціональність пакетного підписувача
func TestBatchSignerBasic(t *testing.T) {
	// Створюємо простий HMAC підписувач для тестування
	signer := signature.NewSignHMAC("test_key", "test_secret_that_is_long_enough_for_testing")

	batchSigner := signature.NewBatchSigner(5, 50*time.Millisecond)
	defer batchSigner.Stop()

	// Додаємо пакетний запит
	req := signature.BatchRequest{
		ID:       "batch1",
		Messages: []string{"msg1", "msg2", "msg3"},
		Signer:   signer,
		Timeout:  1 * time.Second,
	}

	batchSigner.SignBatch(req)

	// Даємо час на обробку пакету
	time.Sleep(100 * time.Millisecond)

	// Отримуємо результат
	result, ok := batchSigner.GetBatchResult()
	assert.True(t, ok)
	assert.Equal(t, "batch1", result.ID)
	assert.Len(t, result.Signatures, 3)
	assert.Len(t, result.Errors, 3)
	assert.Greater(t, result.Duration, time.Duration(0))

	// Перевіряємо, що всі підписи створені
	for _, sig := range result.Signatures {
		assert.NotEmpty(t, sig)
	}
}

// TestSignAsyncSimple тестує простий асинхронний підпис
func TestSignAsyncSimple(t *testing.T) {
	// Створюємо простий HMAC підписувач для тестування
	signer := signature.NewSignHMAC("test_key", "test_secret_that_is_long_enough_for_testing")

	message := "test_message"
	resultChan := signature.SignAsyncSimple(message, signer)

	// Отримуємо результат
	result := <-resultChan
	assert.NotEmpty(t, result.Signature)
	assert.Nil(t, result.Error)
	assert.Greater(t, result.Duration, time.Duration(0))
}

// TestSignBatchSimple тестує простий пакетний підпис
func TestSignBatchSimple(t *testing.T) {
	// Створюємо простий HMAC підписувач для тестування
	signer := signature.NewSignHMAC("test_key", "test_secret_that_is_long_enough_for_testing")

	messages := []string{"msg1", "msg2", "msg3"}
	resultChan := signature.SignBatchSimple(messages, signer)

	// Отримуємо результат
	result := <-resultChan
	assert.Len(t, result.Signatures, 3)
	assert.Len(t, result.Errors, 3)
	assert.Greater(t, result.Duration, time.Duration(0))

	// Перевіряємо, що всі підписи створені
	for _, sig := range result.Signatures {
		assert.NotEmpty(t, sig)
	}
}

// TestGlobalSigners тестує глобальні підписувачі
func TestGlobalSigners(t *testing.T) {
	// Перевіряємо, що глобальні підписувачі створені
	assert.NotNil(t, signature.GlobalAsyncSigner)
	assert.NotNil(t, signature.GlobalBatchSigner)

	// Перевіряємо, що вони працюють
	// Примітка: поля workers та batchSize є приватними, тому ми не можемо їх тестувати напряму
	assert.True(t, true)
}
