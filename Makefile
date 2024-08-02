build_release:
	cargo build --release
clean:
	rm -rf target
run_release: build_release
	sudo ./target/release/wfsafe-local-server
build_debug:
	cargo build
run_debug: build_debug
	sudo ./target/debug/wfsafe-local-server