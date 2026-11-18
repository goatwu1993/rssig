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
lint: fuzz-lint
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

# Fuzzing is optional and separate from `make test`: it needs rustup, a nightly
# toolchain and cargo-fuzz. See docs/fuzzing.md. fuzz/targets.txt is the single
# target list; CI runs these same targets.
FUZZ_SECONDS ?= 30
FUZZ_FLAGS ?= -max_len=131072 -timeout=10 -rss_limit_mb=2048
# `rustup run` works whichever cargo is first on PATH, including Homebrew's.
FUZZ_CARGO ?= rustup run nightly cargo
# Name the host target: a prebuilt (musl) cargo-fuzz otherwise defaults to a
# musl target, which the address sanitizer cannot use.
FUZZ_HOST ?= $(shell rustup run nightly rustc -vV 2>/dev/null | sed -n 's/^host: //p')
FUZZ_TARGETS ?= $(shell sed -e 's/\#.*//' -e '/^[[:space:]]*$$/d' fuzz/targets.txt | cut -d' ' -f1)

.PHONY: fuzz-check
fuzz-check:
	./fuzz/check.sh

.PHONY: fuzz-lint
fuzz-lint: fuzz-check
	$(CARGO) fmt --check --manifest-path fuzz/Cargo.toml
	$(CARGO) clippy --manifest-path fuzz/Cargo.toml --locked -- -D warnings

.PHONY: fuzz-seed
fuzz-seed:
	./fuzz/seed-corpus.sh

# Run every target even after a failure, then report all that failed.
.PHONY: fuzz
fuzz: check-fuzz-tools fuzz-seed
	@failed=; for target in $(FUZZ_TARGETS); do \
		echo "== $$target ($(FUZZ_SECONDS)s)"; \
		$(FUZZ_CARGO) fuzz run --target $(FUZZ_HOST) $$target -- \
			-max_total_time=$(FUZZ_SECONDS) $(FUZZ_FLAGS) || failed="$$failed $$target"; \
	done; \
	if [ -n "$$failed" ]; then echo "fuzz targets failed:$$failed"; exit 1; fi

# Shrink each local corpus to the inputs that still add coverage.
.PHONY: fuzz-cmin
fuzz-cmin: check-fuzz-tools
	@set -e; for target in $(FUZZ_TARGETS); do \
		$(FUZZ_CARGO) fuzz cmin --target $(FUZZ_HOST) $$target -- $(FUZZ_FLAGS); \
	done

.PHONY: check-fuzz-tools
check-fuzz-tools:
	@$(FUZZ_CARGO) fuzz --version >/dev/null 2>&1 || { \
		echo "Fuzzing requires rustup, a nightly toolchain and cargo-fuzz. Install with:"; \
		echo "  rustup toolchain install nightly --profile minimal"; \
		echo "  cargo install cargo-fuzz --version 0.13.2 --locked"; \
		exit 1; \
	}
