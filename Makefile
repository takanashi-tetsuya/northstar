.PHONY: check test format run
check:
	cargo check --all-targets --locked

test:
	cargo test --all-targets --locked

format:
	cargo fmt

run:
	cargo run --locked
