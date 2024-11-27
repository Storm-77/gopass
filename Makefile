build:
	go build -o bin/pass ./cmd/pass/main.go

run:
	go run ./cmd/pass/main.go

test:
	go test ./tests -v | grcat .grc/conf.gotest | grcat .grc/conf.pass | grcat .grc/conf.skip | grcat .grc/conf.names | grcat .grc/conf.time
