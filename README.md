# Headers Security Checker

A high-performance command-line tool written in Rust designed for penetration testing and security auditing of HTTP response headers.

## Overview

This tool connects to a specified URL, retrieves the HTTP response headers, and evaluates them against common security best practices to identify missing configurations, permissive CORS configurations, and potential information leaks (like `.NET`/`PHP` versions or server frameworks).

## Features

- **Blazing Fast**: Built on `tokio` and `reqwest`, making full use of asynchronous Rust.
- **Security Validation**: Checks explicitly for:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- **CORS Analysis**: Explicitly evaluates `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` to find dangerously permissive configurations (like wildcard origins with credentials allowed).
- **Information Leak Detection**: Identifies server stack broadcasting (`Server`, `X-Powered-By`, `X-AspNet-Version`).
- **Authorization Support**: Pass custom headers (like `Authorization` or `Cookie`) to scan authenticated endpoints.

## Installation

Ensure you have Rust installed. Clone this repository and build it using cargo:

```bash
git clone https://github.com/yourusername/headers_security_checker
cd headers_security_checker
cargo build --release
```

The optimized binary will be located at `target/release/headers_security_checker`.

## Usage

You can run the tool directly through cargo, or run the compiled binary. 

```bash
cargo run -- <URL> [OPTIONS]
```

### Basic Scan
```bash
cargo run -- https://example.com
```

### Following Redirects
By default, redirect following is disabled to ensure you only scan the precise endpoint provided.
```bash
cargo run -- https://example.com -f
```

### Scanning Authenticated Endpoints
Use the `-H` or `--header` flag to pass custom headers.
```bash
cargo run -- https://api.example.com -H "Authorization: Bearer <TOKEN>" -H "Cookie: session=xyz"
```

### Raw Header Output
Skip the security analysis entirely and just print the headers returned by the server.
```bash
cargo run -- --only-headers https://example.com
```

## Contributing

Pull requests and feature suggestions are welcome! Ensure you run `cargo clippy` and `cargo fmt` before submitting.

## License

MIT License. See `LICENSE` for details.
