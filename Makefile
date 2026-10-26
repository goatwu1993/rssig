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

.PHONY: test coverage check-coverage-tools

test:
	$(CARGO) test --locked

# Both native tests and the JSON specification invoke the CLI library.
coverage: check-coverage-tools
	$(CARGO) llvm-cov clean --workspace
	RSSIG_SPEC_REPORT="$(CURDIR)/target/coverage/conformance.json" $(CARGO) llvm-cov --locked --all-targets --no-report
	$(CARGO) llvm-cov report --ignore-filename-regex '(^|/)tests(/|\.rs$$)' --html --output-dir target/coverage
	$(CARGO) llvm-cov report --ignore-filename-regex '(^|/)tests(/|\.rs$$)' --cobertura --output-path target/coverage/cobertura.xml

check-coverage-tools:
	@$(CARGO) llvm-cov --version >/dev/null 2>&1 || { \
		echo "Coverage requires cargo-llvm-cov. Install with:"; \
		echo "  brew install cargo-llvm-cov  # Homebrew"; \
		echo "  cargo install cargo-llvm-cov --version 0.9.1 --locked  # rustup"; \
		exit 1; \
	}
