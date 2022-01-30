VERSION        := snapshot
GIT_HEAD       := $(shell git rev-parse HEAD)
IMAGE          := vulny
BIN            := vulny
COMMAND        := ./cmd/cli/main.go
BUILD_FLAGS    := -mod=readonly -v
LINK_FLAGS     := -X github.com/kgalli/vulny/cmd/cli.Version=$(VERSION) -X github.com/kgalli/vulny/cmd/cli.GitHead=$(GIT_HEAD)
TEST_FLAGS     := -mod=readonly -v -race -count=1 -cover

build:
	go build $(BUILD_FLAGS) -ldflags="$(LINK_FLAGS)" -o ./build/$(BIN) $(COMMAND)

build.linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -ldflags="$(LINK_FLAGS)" -o ./build/linux/$(BIN) $(COMMAND)

test:
	go test $(TEST_FLAGS) ./...

build.image: build.linux
	podman build -t kgalli/$(IMAGE):$(VERSION) -t kgalli/$(IMAGE):latest .

container:
	podman run --rm -it kgalli/$(IMAGE):$(VERSION) bash

clean:
	rm -rvf ./build/*

.PHONY: build test clean container
