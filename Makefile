
all: client server
.PHONY: client
client:
	@go build ./cmd/client

.PHONY: server
server:
	@go build ./cmd/server

clean:
	@rm server client