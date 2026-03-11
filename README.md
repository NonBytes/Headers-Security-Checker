# Headers Security Checker

A high-performance command-line tool written in Rust, designed for penetration testing and security auditing of HTTP response headers.

## Overview

This tool connects to a specified URL, retrieves the HTTP response headers, and evaluates them against common security best practices. It helps identify missing configurations, dangerously permissive CORS settings, and potential information leaks (such as exposed server frameworks or `.NET`/`PHP` versions).

## Key Features

- **Blazing Fast Execution**: Powered by `tokio` and `reqwest`, leveraging asynchronous Rust for maximum runtime efficiency.
- **Robust Security Validation**: Explicitly checks for critical security headers, including:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- **CORS Analysis**: Evaluates `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` to detect permissive and potentially dangerous configurations (e.g., wildcard origins combined with allowed credentials).
- **Information Leak Detection**: Flags unintended server stack broadcasting via headers like `Server`, `X-Powered-By`, and `X-AspNet-Version`.
- **Authorization Support**: Allows passing custom headers (such as `Authorization` or `Cookie`) to scan authenticated endpoints effortlessly.

## Installation

Ensure you have Rust installed on your machine. Clone this repository and build the project using Cargo:

```bash
git clone https://github.com/yourusername/headers_security_checker
cd headers_security_checker
cargo build --release
```

After building, the optimized executable will be available at `target/release/headers_security_checker`.

## Usage

You can run the tool directly using Cargo or execute the compiled binary.

```bash
cargo run -- <URL> [OPTIONS]
```

### Basic Scan
Perform a standard security scan on a target URL:
```bash
cargo run -- https://example.com
```

### Following Redirects
By default, the tool does not follow redirects to ensure only the strictly specified endpoint is scanned. To follow redirects, use the `-f` flag:
```bash
cargo run -- https://example.com -f
```

### Scanning Authenticated Endpoints
Use the `-H` or `--header` flag to include custom HTTP headers in your request:
```bash
cargo run -- https://api.example.com -H "Authorization: Bearer <TOKEN>" -H "Cookie: session=xyz"
```

### Raw Header Output
Skip the security analysis and simply print the raw HTTP headers returned by the server:
```bash
cargo run -- --only-headers https://example.com
```

## Contributing

Contributions, bug reports, and feature suggestions are always welcome! Before submitting a pull request, please ensure your code passes `cargo clippy` and is formatted with `cargo fmt`.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
