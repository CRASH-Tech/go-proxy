BINARY := goproxy

.PHONY: build test vet clean

build:
	go build -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
