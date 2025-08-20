# 🔐 Turbo Signer

Професійна Go бібліотека для створення цифрових підписів з підтримкою різних алгоритмів та архітектурних патернів.

## 🚀 Особливості

### ✨ **Підтримувані алгоритми**
- **HMAC-SHA256** - для API ключів
- **RSA** - PKCS#1 та PKCS#8 формати
- **Ed25519** - сучасний алгоритм на основі еліптичних кривих
- **ECDSA** - з підтримкою різних кривих (P-224, P-256, P-384, P-521)

### 🏗️ **Архітектурні патерни**
- **Dependency Injection** - гнучка архітектура
- **Factory Pattern** - централізоване створення підписувачів
- **Strategy Pattern** - різні алгоритми через єдиний інтерфейс

### ⚡ **Продуктивність**
- **Кешування ключів** - LRU з TTL
- **Асинхронні операції** - worker pools та batch processing
- **Thread-safe** - безпечне використання в goroutines

## 📦 Встановлення

```bash
go get github.com/fr0ster/turbo-signer
```

## 🔧 Швидкий старт

### Базове використання

```go
package main

import (
    "fmt"
    "github.com/fr0ster/turbo-signer/signature"
)

func main() {
    // Створення HMAC підписувача
    hmacSigner := signature.NewSignHMAC("api_key", "secret_key")
    
    // Створення підпису
    message := "timestamp=1234567890&symbol=BTCUSDT"
    signature := hmacSigner.CreateSignature(message)
    
    fmt.Printf("Signature: %s\n", signature)
}
```

### Використання через фабрику

```go
package main

import (
    "fmt"
    "github.com/fr0ster/turbo-signer/signature"
)

func main() {
    // Конфігурація для RSA підписувача
    config := signature.SignerConfig{
        Algorithm:  "rsa",
        APIKey:     "api_key",
        PublicKey:  publicKeyPEM,
        PrivateKey: privateKeyPEM,
    }
    
    // Створення через фабрику
    signer, err := signature.CreateSigner(config)
    if err != nil {
        panic(err)
    }
    
    // Використання
    message := "Hello, World!"
    signature := signer.CreateSignature(message)
    fmt.Printf("RSA Signature: %s\n", signature)
}
```

### Асинхронні операції

```go
package main

import (
    "fmt"
    "github.com/fr0ster/turbo-signer/signature"
)

func main() {
    // Створення асинхронного підписувача
    asyncSigner := signature.NewAsyncSigner(4) // 4 workers
    
    // Асинхронне створення підпису
    request := signature.SignRequest{
        Message: "Async message",
        Signer:  signature.NewSignHMAC("key", "secret"),
    }
    
    asyncSigner.SignAsync(request)
    result := asyncSigner.GetResult()
    
    fmt.Printf("Async signature: %s\n", result.Signature)
}
```

## 🏗️ Архітектура

### SignerFactory

```go
// Створення фабрики
factory := signature.NewSignerFactory()

// Реєстрація власного креатора
factory.RegisterCreator("custom", func(config signature.SignerConfig) (signature.Sign, error) {
    // Ваша реалізація
    return customSigner, nil
})

// Створення підписувача
signer, err := factory.CreateSigner(signature.SignerConfig{
    Algorithm: "custom",
    // ... інші параметри
})
```

### Кешування ключів

```go
// Глобальний кеш ключів
cache := signature.GlobalKeyCache

// Завантаження ключа з кешу
privateKey, err := signature.LoadRSAPrivateKeyFromCache("key_id")
if err != nil {
    // Завантаження з файлу та кешування
    privateKey, err = signature.LoadRSAPrivateKeyFromCache("key_id")
}
```

## 🧪 Тестування

```bash
# Запуск всіх тестів
go test ./...

# Запуск тестів конкретного пакету
go test ./signature -v

# Запуск тестів з покриттям
go test ./signature -cover
```

## 🔨 Збірка

```bash
# Збірка всіх прикладів
make build

# Запуск прикладів
make run-factory
make run-async

# Очищення
make clean

# Допомога
make help
```

## 📚 Документація

- [**Phase 1**](PHASE1_IMPROVEMENTS.md) - Критичні покращення
- [**Phase 2**](README_IMPROVEMENTS.md) - Оптимізація та розширення  
- [**Phase 3**](PHASE3_ARCHITECTURE.md) - Архітектурні покращення
- [**TODO**](TODO.md) - Поточний статус розробки

## 🚀 Roadmap

### ✅ **Завершено**
- **Phase 1**: Покращена обробка помилок
- **Phase 2**: ECDSA, кешування, асинхронні операції
- **Phase 3**: Dependency Injection, Factory Pattern, система збірки

### 🔮 **Майбутнє**
- Покращення ECDSA інтерфейсу
- Додавання нових алгоритмів
- Метрики та моніторинг
- WebAssembly підтримка

## 🤝 Внесок

1. Fork репозиторію
2. Створіть feature branch (`git checkout -b feature/amazing-feature`)
3. Зробіть коміт змін (`git commit -m 'Add amazing feature'`)
4. Push до branch (`git push origin feature/amazing-feature`)
5. Відкрийте Pull Request

## 📄 Ліцензія

Цей проект ліцензовано під MIT License - дивіться [LICENSE](LICENSE) файл для деталей.

## 🆘 Підтримка

Якщо у вас є питання або проблеми:
- Створіть [Issue](https://github.com/fr0ster/turbo-signer/issues)
- Перегляньте [документацію](docs/)
- Перевірте [приклади](examples/)

---

**Turbo Signer** - професійна бібліотека для цифрових підписів в Go! 🚀
