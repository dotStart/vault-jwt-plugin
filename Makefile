PLATFORMS := darwin/386 darwin/amd64 linux/386 linux/amd64 linux/arm windows/386/.exe windows/amd64/.exe

DEP := $(shell command -v dep 2> /dev/null)
GO := $(shell command -v go 2> /dev/null)
SHASUM := $(shell command -v sha256sum 2> /dev/null)
ZIP := $(shell command -v zip 2> /dev/null)

# magical formula:
temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))
ext = $(word 3, $(temp))

all: check-env install-dependencies generate-sources $(PLATFORMS) package

check-env:
	@echo "==> Checking prerequisites"
	@echo -n "Checking for go ... "
ifndef GO
	@echo "Not Found"
	$(error "go is unavailable")
endif
	@echo $(GO)
	@echo -n "Checking for dep ... "
ifndef DEP
	@echo "Not Found"
	$(error "dep is unavailable")
endif
	@echo $(DEP)
	@echo ""

clean:
	@echo "==> Clearing previous build data"
	@rm -rf build/ || true
	@$(GO) clean -cache

install-dependencies:
	@echo "==> Installing dependencies"
	@$(DEP) ensure -v
	@echo ""

generate-sources:
	@echo "==> Generating sources"
	@$(GO) generate -v github.com/dotStart/vault-jwt-plugin/plugin
	@echo ""

$(PLATFORMS):
	@echo "==> Building for ${os} (${arch})"
	@export GOOS=$(os); export GOARCH=$(arch); $(GO) build -v -o build/$(os)-$(arch)/jwt-backend$(ext)
	@sha256sum build/$(os)-$(arch)/jwt-backend$(ext) | cut -d' ' -f1 > build/$(os)-$(arch)/sha256.sig
	@echo ""

package:
	@echo "==> Creating distribution packages"
ifndef ZIP
	@echo "zip is unavailable - Skipping step"
else
	@for dir in build/*; do if [ -d "$$dir" ]; then zip -j "$(basename "$$dir").zip" "$$dir/*"; fi; done
endif


.PHONY: build
