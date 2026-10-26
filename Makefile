CARGO ?= cargo

.PHONY: test coverage

test:
	$(CARGO) test --locked

# Both native tests and the JSON specification invoke the CLI library.
coverage:
	$(CARGO) llvm-cov clean --workspace
	RSSIG_SPEC_REPORT="$(CURDIR)/target/coverage/conformance.json" $(CARGO) llvm-cov --locked --all-targets --no-report
	$(CARGO) llvm-cov report --ignore-filename-regex '(^|/)tests(/|\.rs$$)' --html --output-dir target/coverage
	$(CARGO) llvm-cov report --ignore-filename-regex '(^|/)tests(/|\.rs$$)' --cobertura --output-path target/coverage/cobertura.xml
