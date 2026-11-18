CARGO ?= cargo

# Homebrew Rust needs Homebrew LLVM tools; rustup toolchains use their own.
# Explicit environment/command-line overrides take precedence.
ifneq (,$(findstring Homebrew,$(shell rustc --version 2>/dev/null)))
RSSIG_LLVM_PREFIX := $(shell brew --prefix llvm 2>/dev/null)
ifneq (,$(wildcard $(RSSIG_LLVM_PREFIX)/bin/llvm-cov))
export LLVM_COV ?= $(RSSIG_LLVM_PREFIX)/bin/llvm-cov
export LLVM_PROFDATA ?= $(RSSIG_LLVM_PREFIX)/bin/llvm-profdata
endif
endif

.PHONY: test
test:
	$(CARGO) test --locked

.PHONY: format
format:
	$(CARGO) fmt

.PHONY: lint
lint:
	$(CARGO) fmt --check
	$(CARGO) clippy --all-targets --locked -- -D warnings

# Both native tests and the JSON specification invoke the CLI library.
.PHONY: coverage
coverage: check-coverage-tools
	$(CARGO) llvm-cov clean --workspace
	RSSIG_SPEC_REPORT="$(CURDIR)/target/coverage/conformance.json" $(CARGO) llvm-cov --locked --all-targets --no-report
	$(CARGO) llvm-cov report --ignore-filename-regex '(^|/)tests(/|\.rs$$)' --html --output-dir target/coverage
	$(CARGO) llvm-cov report --ignore-filename-regex '(^|/)tests(/|\.rs$$)' --cobertura --output-path target/coverage/cobertura.xml

.PHONY: check-coverage-tools
check-coverage-tools:
	@$(CARGO) llvm-cov --version >/dev/null 2>&1 || { \
		echo "Coverage requires cargo-llvm-cov. Install with:"; \
		echo "  brew install cargo-llvm-cov  # Homebrew"; \
		echo "  cargo install cargo-llvm-cov --version 0.9.1 --locked  # rustup"; \
		exit 1; \
	}

.PHONY: build
build:
	@$(CARGO) build --locked

# Fuzzing is optional and separate from `make test`: it needs a nightly
# toolchain and cargo-fuzz. See docs/fuzzing.md.
FUZZ_SECONDS ?= 30
FUZZ_TARGETS := parse_cms parse_pe parse_cab_navx parse_msi parse_appx parse_text verify_binary verify_text
FUZZ_FLAGS ?= -max_len=131072 -timeout=10 -rss_limit_mb=2048

.PHONY: fuzz-seed
fuzz-seed:
	./fuzz/seed-corpus.sh

.PHONY: fuzz
fuzz: check-fuzz-tools fuzz-seed
	@set -e; for target in $(FUZZ_TARGETS); do \
		echo "== $$target ($(FUZZ_SECONDS)s)"; \
		$(CARGO) +nightly fuzz run $$target -- -max_total_time=$(FUZZ_SECONDS) $(FUZZ_FLAGS); \
	done

.PHONY: check-fuzz-tools
check-fuzz-tools:
	@$(CARGO) +nightly fuzz --version >/dev/null 2>&1 || { \
		echo "Fuzzing requires a nightly toolchain and cargo-fuzz. Install with:"; \
		echo "  rustup toolchain install nightly --profile minimal"; \
		echo "  cargo install cargo-fuzz --version 0.13.2 --locked"; \
		exit 1; \
	}
