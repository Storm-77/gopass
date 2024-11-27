build:
	go build -o bin/pass ./cmd/pass/main.go

run:
	go run ./cmd/pass/main.go

test:
	go test ./tests -v | grcat .grc/conf.gotest
