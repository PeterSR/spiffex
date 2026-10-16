# Everyday tasks; CI runs the same checks (.github/workflows/test.yml). make help lists them.

IMG ?= spiffex:dev
SANDBOX = unshare --user --map-current-user --pid --fork --mount --mount-proc sh -c

STATICCHECK = honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOVULNCHECK = golang.org/x/vuln/cmd/govulncheck@v1.9.0
GOLANGCI_LINT = github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
ACTIONLINT = github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
SHELL_SCRIPTS = conformance/run.sh test/e2e/*.sh scripts/*.sh

.PHONY: all
all: build

.PHONY: build
build: ## Build the spiffex binary.
	CGO_ENABLED=0 go build -trimpath -o spiffex ./cmd/spiffex

.PHONY: test
test: ## Run the Go tests with the race detector, in a PID namespace of their own (Linux).
	$(SANDBOX) 'go test -race ./...'

.PHONY: conformance
conformance: ## Run the conformance matrix, in a PID namespace of its own (needs uv).
	$(SANDBOX) conformance/run.sh

.PHONY: e2e
e2e: ## Run the end-to-end test on kind with the plain manifests.
	$(SANDBOX) test/e2e/kind.sh

.PHONY: e2e-helm
e2e-helm: ## Run the end-to-end test on kind with the Helm chart.
	$(SANDBOX) test/e2e/kind-helm.sh

.PHONY: fmt
fmt: ## gofmt the tree.
	gofmt -w .

.PHONY: lint
lint: ## gofmt, go mod tidy, vet, staticcheck, govulncheck, golangci-lint, actionlint, shellcheck.
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	go mod tidy -diff
	go vet ./...
	go run $(STATICCHECK) ./...
	go run $(GOVULNCHECK) ./...
	go run $(GOLANGCI_LINT) run ./...
	go run $(ACTIONLINT)
	shellcheck $(SHELL_SCRIPTS)

.PHONY: helm-lint
helm-lint: ## Lint the chart with each value set, and check what it renders.
	for values in charts/spiffex/ci/*-values.yaml; do \
		helm lint --strict charts/spiffex --namespace spiffex -f "$$values" || exit 1; \
	done
	SPIFFEX_REQUIRE_HELM=1 $(SANDBOX) "go test -run 'TestChart' ./cmd/spiffex"

.PHONY: docker-build
docker-build: ## Build the image from source as $(IMG).
	docker build -t $(IMG) .

.PHONY: release-check
release-check: ## Validate the goreleaser configuration.
	goreleaser check

.PHONY: release-snapshot
release-snapshot: ## Build the release artifacts and images locally into dist/, unsigned and unpublished (needs goreleaser and syft).
	goreleaser release --snapshot --clean --skip=sign

.PHONY: help
help: ## Show this help.
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-17s %s\n", $$1, $$2}'
