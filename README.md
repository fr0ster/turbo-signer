# Turbo Signer

## 📍 **Опис модуля**

**Turbo Signer** - це простий wrapper для підпису WebAPI та RESTful параметрів. Модуль надає уніфікований інтерфейс для роботи з різними алгоритмами цифрового підпису.

## 🏗️ **Архітектура**

### **Основні компоненти**
```
turbo-signer/
├── signature/           # Пакет підписів
│   ├── types.go        # Інтерфейси та типи
│   ├── hmac.go         # HMAC-SHA256 підписи
│   ├── ed25519.go      # Ed25519 підписи
│   ├── rsa.go          # RSA підписи
│   ├── utils.go        # Утиліти
│   └── *_test.go       # Тести
├── types.go             # Основні типи
├── go.mod               # Залежності
└── LICENSE              # Ліцензія
```

## 🔐 **Алгоритми підпису**

### **1. HMAC-SHA256**
- **Призначення**: Симметричний підпис для API ключів
- **Використання**: Binance, більшість криптобірж
- **Переваги**: Швидкий, простий у використанні
- **Недоліки**: Потребує секретний ключ

```go
sign := signature.NewSignHMAC("api_key", "api_secret")
signature := sign.CreateSignature("timestamp=1610612740000")
```

### **2. Ed25519**
- **Призначення**: Асиметричний підпис нового покоління
- **Використання**: Сучасні криптографічні системи
- **Переваги**: Швидкий, безпечний, короткі ключі
- **Недоліки**: Складніший у налаштуванні

```go
sign, err := signature.NewSignEd25519("api_key", "public_key.pem", "private_key.pem")
signature := sign.CreateSignature("timestamp=1610612740000")
```

### **3. RSA**
- **Призначення**: Класичний асиметричний підпис
- **Використання**: Традиційні фінансові системи
- **Переваги**: Широко підтримується, доведена безпека
- **Недоліки**: Повільніший, довші ключі

```go
sign, err := signature.NewSignRSA("api_key", "public_key.pem", "private_key.pem")
signature := sign.CreateSignature("timestamp=1610612740000")
```

## 🔧 **API інтерфейс**

### **Інтерфейс Sign**
```go
type Sign interface {
    CreateSignature(queryString string) string
    SignParameters(params *simplejson.Json) (*simplejson.Json, error)
    ValidateSignatureParams(params *simplejson.Json) bool
    ValidateSignature(string, string) bool
    GetAPIKey() string
}
```

### **Основні методи**

#### **CreateSignature(queryString string) string**
- Створює цифровий підпис для рядка
- Повертає підпис у hex/base64 форматі

#### **SignParameters(params *simplejson.Json) (*simplejson.Json, error)**
- Підписує JSON параметри
- Автоматично додає поле `signature`
- Повертає підписані параметри

#### **ValidateSignatureParams(params *simplejson.Json) bool**
- Валідує підпис у параметрах
- Автоматично видаляє поле `signature` перед перевіркою
- Повертає `true` якщо підпис валідний

#### **ValidateSignature(message, signature string) bool**
- Валідує підпис для повідомлення
- Пряме порівняння без обробки JSON

## 📊 **Приклади використання**

### **HMAC підпис**
```go
package main

import (
    "fmt"
    "github.com/fr0ster/turbo-signer/signature"
    "github.com/bitly/go-simplejson"
)

func main() {
    // Створення HMAC підпису
    sign := signature.NewSignHMAC("api_key", "api_secret")
    
    // Підпис рядка
    message := "timestamp=1610612740000"
    signature := sign.CreateSignature(message)
    fmt.Printf("Signature: %s\n", signature)
    
    // Підпис JSON параметрів
    params := simplejson.New()
    params.Set("timestamp", 1610612740000)
    params.Set("symbol", "BTCUSDT")
    
    signedParams, err := sign.SignParameters(params)
    if err != nil {
        panic(err)
    }
    
    // Валідація підпису
    valid := sign.ValidateSignatureParams(signedParams)
    fmt.Printf("Signature valid: %t\n", valid)
}
```

### **Ed25519 підпис**
```go
package main

import (
    "fmt"
    "github.com/fr0ster/turbo-signer/signature"
)

func main() {
    // Створення Ed25519 підпису
    sign, err := signature.NewSignEd25519(
        "api_key",
        "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
        "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    )
    if err != nil {
        panic(err)
    }
    
    // Створення та валідація підпису
    message := "timestamp=1610612740000"
    signature := sign.CreateSignature(message)
    valid := sign.ValidateSignature(message, signature)
    
    fmt.Printf("Signature: %s\n", signature)
    fmt.Printf("Valid: %t\n", valid)
}
```

### **RSA підпис**
```go
package main

import (
    "fmt"
    "github.com/fr0ster/turbo-signer/signature"
)

func main() {
    // Створення RSA підпису
    sign, err := signature.NewSignRSA(
        "api_key",
        "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
    )
    if err != nil {
        panic(err)
    }
    
    // Створення та валідація підпису
    message := "timestamp=1610612740000"
    signature := sign.CreateSignature(message)
    valid := sign.ValidateSignature(message, signature)
    
    fmt.Printf("Signature: %s\n", signature)
    fmt.Printf("Valid: %t\n", valid)
}
```

## 🧪 **Тестування**

### **Покриття тестами**
- **HMAC**: Параметри та рядки
- **Ed25519**: Параметри та рядки  
- **RSA**: Параметри та рядки
- **Утиліти**: Функції перетворення

### **Запуск тестів**
```bash
cd turbo-signer
go test ./signature/...
```

## 🔒 **Безпека**

### **Рекомендації**
1. **HMAC**: Використовуйте для API ключів
2. **Ed25519**: Для сучасних систем з високими вимогами безпеки
3. **RSA**: Для сумісності з існуючими системами

### **Обмеження**
- **HMAC**: Секретний ключ має бути безпечним
- **Ed25519**: Потребує правильне форматування PEM
- **RSA**: Мінімальний розмір ключа 2048 біт

## 📈 **Версії та оновлення**

### **v0.1.7 (2024-08-23)**
- Рефакторинг функції `signParameters`

### **v0.1.6 (2024-08-21)**
- Функція `convertSimpleJSONToString` стала публічною

### **v0.1.5 (2024-09-15)**
- Рефакторинг та перейменування функцій

### **v0.1.4 (2024-09-15)**
- Покращена валідація параметрів без побічних ефектів

## 🎯 **Застосування**

### **Криптобіржі**
- Binance API
- Coinbase API
- Kraken API

### **Фінансові системи**
- REST API
- WebSocket API
- Webhook підписи

### **Загальне використання**
- Автентифікація запитів
- Верифікація даних
- Цифрові підписи документів

## 🚀 **Майбутні покращення**

1. **Додаткові алгоритми**: ECDSA, DSA
2. **Підтримка JWT**: JSON Web Tokens
3. **Асинхронні операції**: Go routines для великих обсягів
4. **Кешування ключів**: Оптимізація продуктивності
5. **Метрики**: Prometheus інтеграція

## 📄 **Ліцензія**

Цей проект розповсюджується під ліцензією, деталі якої можна знайти в файлі LICENSE.
