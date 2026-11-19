.PHONY: check test format run
check:
	cargo check --workspace --all-targets --locked

test:
	cargo test --workspace --all-targets --locked

format:
	cargo fmt

run:
	cargo run --locked
