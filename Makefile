COMPOSE ?= docker compose
BACKEND_DIR := backend
CLI_DIR := cli
WEB_DIR := web

.PHONY: compose-up compose-down compose-logs fmt clippy test build \
        web-install web-typecheck web-dev web-build clean

compose-up:
	$(COMPOSE) up -d

compose-down:
	$(COMPOSE) down

compose-logs:
	$(COMPOSE) logs -f

fmt:
	cargo fmt --manifest-path $(BACKEND_DIR)/Cargo.toml --all
	cargo fmt --manifest-path $(CLI_DIR)/Cargo.toml

clippy:
	cargo clippy --manifest-path $(BACKEND_DIR)/Cargo.toml --workspace --all-targets --all-features -- -D warnings
	cargo clippy --manifest-path $(CLI_DIR)/Cargo.toml --all-targets --all-features -- -D warnings

test:
	cargo test --manifest-path $(BACKEND_DIR)/Cargo.toml --workspace
	cargo test --manifest-path $(CLI_DIR)/Cargo.toml

build:
	cargo build --manifest-path $(BACKEND_DIR)/Cargo.toml --workspace
	cargo build --manifest-path $(CLI_DIR)/Cargo.toml

web-install:
	npm ci --prefix $(WEB_DIR)

web-typecheck:
	npm run typecheck --prefix $(WEB_DIR)

web-dev:
	npm run dev --prefix $(WEB_DIR)

web-build:
	npm run build --prefix $(WEB_DIR)

clean:
	cargo clean --manifest-path $(BACKEND_DIR)/Cargo.toml
	cargo clean --manifest-path $(CLI_DIR)/Cargo.toml
	rm -rf $(WEB_DIR)/.next $(WEB_DIR)/out
