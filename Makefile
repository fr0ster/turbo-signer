# Makefile for Turbo Signer

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary output directory
BINARY_DIR=bin

# Examples
EXAMPLES_DIR=examples
ASYNC_EXAMPLE=$(EXAMPLES_DIR)/async_example.go
FACTORY_EXAMPLE=$(EXAMPLES_DIR)/factory/main.go

# Binary names
ASYNC_BINARY=$(BINARY_DIR)/async_example
FACTORY_BINARY=$(BINARY_DIR)/factory_example

.PHONY: all build examples clean test deps help

# Default target
all: build

# Build all examples
build: examples

# Build examples into bin directory
examples: $(ASYNC_BINARY) $(FACTORY_BINARY)

$(ASYNC_BINARY): $(ASYNC_EXAMPLE)
	@echo "Building async example..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) -o $(ASYNC_BINARY) $(ASYNC_EXAMPLE)

$(FACTORY_BINARY): $(FACTORY_EXAMPLE)
	@echo "Building factory example..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) -o $(FACTORY_BINARY) $(FACTORY_EXAMPLE)

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./signature

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./signature
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BINARY_DIR)
	rm -f coverage.out coverage.html

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) tidy
	$(GOMOD) download

# Update dependencies
deps-update:
	@echo "Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy

# Run async example
run-async: $(ASYNC_BINARY)
	@echo "Running async example..."
	./$(ASYNC_BINARY)

# Run factory example
run-factory: $(FACTORY_BINARY)
	@echo "Running factory example..."
	./$(FACTORY_BINARY)

# Install git hooks (if any)
install-hooks:
	@echo "Installing git hooks..."
	# Add git hooks installation here if needed

# Lint code
lint:
	@echo "Running linter..."
	golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# Generate documentation
docs:
	@echo "Generating documentation..."
	$(GOCMD) doc -all > docs.txt

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build all (default)"
	@echo "  build        - Build all examples"
	@echo "  examples     - Build all examples into bin/"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage"
	@echo "  clean        - Clean build artifacts"
	@echo "  deps         - Download dependencies"
	@echo "  deps-update  - Update dependencies"
	@echo "  run-async    - Build and run async example"
	@echo "  run-factory  - Build and run factory example"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  docs         - Generate documentation"
	@echo "  help         - Show this help"
