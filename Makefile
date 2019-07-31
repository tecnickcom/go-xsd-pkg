# MAKEFILE
#
# @author      Nicola Asuni <info@tecnick.com>
# @link        https://github.com/tecnickcom/go-xsd-pkg
# ------------------------------------------------------------------------------

# Use bash as shell (Note: Ubuntu now uses dash which doesn't support PIPESTATUS).
SHELL=/bin/bash

# CVS path (path to the parent dir containing the project)
CVSPATH=github.com/miracl

# Project owner
OWNER=MIRACL UK LTD

# Project vendor
VENDOR=miracl

# Project name
PROJECT=go-xsd-pkg

# Project version
VERSION=$(shell cat VERSION)

# Project release number (packaging build number)
RELEASE=$(shell cat RELEASE)

# Current directory
CURRENTDIR=$(shell pwd)

# GO lang path
ifneq ($(GOPATH),)
	ifeq ($(findstring $(GOPATH),$(CURRENTDIR)),)
		# the defined GOPATH is not valid
		GOPATH=
	endif
endif
ifeq ($(GOPATH),)
	# extract the GOPATH
	GOPATH=$(firstword $(subst /src/, ,$(CURRENTDIR)))
endif

# Add the GO binary dir in the PATH
export PATH := $(GOPATH)/bin:$(PATH)


# --- MAKE TARGETS ---

# Display general help about this command
.PHONY: help
help:
	@echo ""
	@echo "$(PROJECT) Makefile."
	@echo "GOPATH=$(GOPATH)"
	@echo "The following commands are available:"
	@echo ""
	@echo "    make qa          : Run all the tests and static analysis reports"
	@echo "    make test        : Run the unit tests"
	@echo ""
	@echo "    make format      : Format the source code"
	@echo "    make fmtcheck    : Check if the source code has been formatted"
	@echo "    make vet         : Check for suspicious constructs"
	@echo "    make lint        : Check for style errors"
	@echo "    make coverage    : Generate the coverage report"
	@echo "    make cyclo       : Generate the cyclomatic complexity report"
	@echo "    make ineffassign : Detect ineffectual assignments"
	@echo "    make misspell    : Detect commonly misspelled words in source files"
	@echo "    make astscan     : GO AST scanner"
	@echo ""
	@echo "    make docs        : Generate source code documentation"
	@echo ""
	@echo "    make deps        : Get the dependencies"
	@echo "    make build       : Compile the application"
	@echo "    make clean       : Remove any build artifact"
	@echo ""

# Alias for help target
all: help

# Run the unit tests
.PHONY: test
test:
	@mkdir -p target/test
	GOPATH=$(GOPATH) \
	go test -covermode=atomic -bench=. -race -v ./... | \
	tee >(PATH=$(GOPATH)/bin:$(PATH) go-junit-report > target/test/report.xml); \
	test $${PIPESTATUS[0]} -eq 0

# Format the source code
.PHONY: format
format:
	@find . -type f -name "*.go" -exec gofmt -s -w {} \;

# Check if the source code has been formatted
.PHONY: fmtcheck
fmtcheck:
	@mkdir -p target
	@find . -type f -name "*.go" -exec gofmt -s -d {} \; | tee target/format.diff
	@test ! -s target/format.diff || { echo "ERROR: the source code has not been formatted - please use 'make format' or 'gofmt'"; exit 1; }

# Check for syntax errors
.PHONY: vet
vet:
	GOPATH=$(GOPATH) go vet ./...

# Check for style errors
.PHONY: lint
lint:
	GOPATH=$(GOPATH) PATH=$(GOPATH)/bin:$(PATH) golint ./...

# Generate the coverage report
.PHONY: coverage
coverage:
	mkdir -p target/report/
	echo "mode: count" > target/report/coverage.out
	GOPATH=$(GOPATH) go list ./... | xargs -L 1 -I % go test -covermode=count -coverprofile=target/report/coverage.part % | xargs -L 1 -I % sh -c 'echo % && grep -h -v "mode: count" target/report/coverage.part >> target/report/coverage.out'
	GOPATH=$(GOPATH) go tool cover -html=target/report/coverage.out -o target/report/coverage.html

# Report cyclomatic complexity
.PHONY: cyclo
cyclo:
	@mkdir -p target/report
	GOPATH=$(GOPATH) gocyclo -avg . | tee target/report/cyclo.txt ; test $${PIPESTATUS[0]} -eq 0

# Detect ineffectual assignments
.PHONY: ineffassign
ineffassign:
	@mkdir -p target/report
	GOPATH=$(GOPATH) ineffassign . | tee target/report/ineffassign.txt ; test $${PIPESTATUS[0]} -eq 0

# Detect commonly misspelled words in source files
.PHONY: misspell
misspell:
	@mkdir -p target/report
	GOPATH=$(GOPATH) misspell -error ./...  | tee target/report/misspell.txt ; test $${PIPESTATUS[0]} -eq 0

# AST scanner
.PHONY: astscan
astscan:
	@mkdir -p target/report
	GOPATH=$(GOPATH) gosec ./... | tee target/report/astscan.txt ; test $${PIPESTATUS[0]} -eq 0 || true

# Generate source docs
.PHONY: docs
docs:
	@mkdir -p target/docs
	nohup sh -c 'GOPATH=$(GOPATH) godoc -http=127.0.0.1:6060' > target/godoc_server.log 2>&1 &
	wget --directory-prefix=target/docs/ --execute robots=off --retry-connrefused --recursive --no-parent --adjust-extension --page-requisites --convert-links http://127.0.0.1:6060/pkg/github.com/${VENDOR}/${PROJECT}/ ; kill -9 `lsof -ti :6060`
	@echo '<html><head><meta http-equiv="refresh" content="0;./127.0.0.1:6060/pkg/'${CVSPATH}'/'${PROJECT}'/index.html"/></head><a href="./127.0.0.1:6060/pkg/'${CVSPATH}'/'${PROJECT}'/index.html">'${PKGNAME}' Documentation ...</a></html>' > target/docs/index.html

# Alias to run targets: fmtcheck test vet lint coverage
#qa: fmtcheck test vet lint coverage cyclo ineffassign misspell astscan
.PHONY: qa
qa: fmtcheck test vet lint ineffassign misspell astscan

# Get the dependencies
.PHONY: deps
deps:
	GOPATH=$(GOPATH) go get ./...
	GOPATH=$(GOPATH) go get github.com/inconshreveable/mousetrap
	GOPATH=$(GOPATH) go get golang.org/x/lint/golint
	GOPATH=$(GOPATH) go get github.com/jstemmer/go-junit-report
	GOPATH=$(GOPATH) go get github.com/axw/gocov/gocov
	GOPATH=$(GOPATH) go get github.com/fzipp/gocyclo
	GOPATH=$(GOPATH) go get github.com/gordonklaus/ineffassign
	GOPATH=$(GOPATH) go get github.com/client9/misspell/cmd/misspell
	GOPATH=$(GOPATH) go get github.com/securego/gosec/cmd/gosec/...
	GOPATH=$(GOPATH) go get github.com/stretchr/testify/assert

# Remove any build artifact
.PHONY: clean
clean:
	rm -rf ./target
	GOPATH=$(GOPATH) go clean -i ./...
