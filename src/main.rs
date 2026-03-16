use clap::Parser;
use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(about = "HTTP Security Headers Analyzer for Penetration Testing")]
struct Cli {
    /// URL to test (e.g., https://example.com)
    url: String,

    /// Follow redirects (default: false)
    #[arg(short, long)]
    follow_redirects: bool,

    /// Add custom headers to the request (e.g., -H "Authorization: Bearer token" -H "Cookie: session=xyz")
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Only print the raw headers returned by the server (skip security analysis)
    #[arg(long)]
    only_headers: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    // Parse URL, add schema if missing (default to http to check for redirection)
    let initial_url = if cli.url.starts_with("http://") || cli.url.starts_with("https://") {
        cli.url.clone()
    } else {
        format!("http://{}", cli.url)
    };
    let target_url = initial_url.clone();

    if !cli.only_headers {
        println!("{} {}", "Analyzing headers for:".bold(), target_url.bold().blue());
    }

    let mut client_builder = Client::builder()
        .timeout(Duration::from_secs(10));
        
    client_builder = if cli.follow_redirects {
        client_builder
    } else {
        client_builder.redirect(reqwest::redirect::Policy::none())
    };
    
    let client = client_builder.build()?;
    
    let mut request_builder = client.get(&target_url);

    // Add custom headers
    for header in &cli.headers {
        if let Some((k, v)) = header.split_once(':') {
            request_builder = request_builder.header(k.trim(), v.trim());
        } else {
            if !cli.only_headers {
                println!("{} Invalid header format: '{}'. Expected 'Key: Value'", "✗ Warning:".yellow().bold(), header);
            }
        }
    }

    // Perform a GET or HEAD request
    let response_result = request_builder.send().await;
    
    let mut cert_error = None;
    let response = match response_result {
        Ok(resp) => resp,
        Err(e) => {
            let err_msg = e.to_string().to_lowercase();
            if err_msg.contains("certificate") || err_msg.contains("ssl") || err_msg.contains("tls") || 
               err_msg.contains("pkix") || err_msg.contains("mismatch") || err_msg.contains("expired") {
                cert_error = Some(e.to_string());
                // Retry with insecure allowed to at least get headers for analysis
                let mut insecure_builder = Client::builder()
                    .timeout(Duration::from_secs(10));
                
                if !cli.follow_redirects {
                    insecure_builder = insecure_builder.redirect(reqwest::redirect::Policy::none());
                }
                
                let insecure_client = insecure_builder.danger_accept_invalid_certs(true).build()?;
                let mut insecure_req = insecure_client.get(&target_url);
                // Add back custom headers
                for header in &cli.headers {
                    if let Some((k, v)) = header.split_once(':') {
                        insecure_req = insecure_req.header(k.trim(), v.trim());
                    }
                }
                match insecure_req.send().await {
                    Ok(resp) => resp,
                    Err(e2) => {
                        println!("{} Connection failed even with insecure allowed: {}", "✗ Error:".red().bold(), e2);
                        std::process::exit(1);
                    }
                }
            } else {
                println!("{} {}", "✗ Error connecting to target:".red().bold(), e);
                std::process::exit(1);
            }
        }
    };
    
    if !cli.only_headers {
        println!("{} {}", "HTTP Status:".bold(), response.status().as_u16());
        println!("{} {:?}\n", "HTTP Version:".bold(), response.version());
    }

    let final_url = response.url().clone();
    let headers = response.headers();
    
    if cli.only_headers {
        for (key, value) in headers.iter() {
            println!("{}: {}", key, value.to_str().unwrap_or("Non-ASCII Value"));
        }
        return Ok(()); // Exit early if only headers are requested
    }

    let mut missing_security_headers = Vec::new();
    let mut present_security_headers = Vec::new();
    let mut warnings = Vec::new();

    // Security Headers definitions
    let security_headers = vec![
        ("strict-transport-security", "HSTS enforces secure (HTTP over SSL/TLS) connections to the server."),
        ("content-security-policy", "CSP prevents cross-site scripting (XSS), clickjacking and other code injection attacks."),
        ("x-frame-options", "Protects against clickjacking attacks. (Obsolete if CSP frame-ancestors is used)"),
        ("x-content-type-options", "Prevents MIME-sniffing. Should be set to 'nosniff'."),
        ("referrer-policy", "Controls how much referrer information (sent with the Referer header) should be included with requests."),
        ("permissions-policy", "Allows site to control which features and APIs can be used in the browser."),
        ("cache-control", "Specifies caching policies in both client-side and server-side. Should prevent sensitive data from being cached."),
        ("cross-origin-opener-policy", "Controls which documents can share a window with the document."),
        ("cross-origin-embedder-policy", "Prevents a document from loading any cross-origin resources that don't explicitly grant permission."),
        ("cross-origin-resource-policy", "Controls which origins are allowed to fetch the resource."),
        ("x-xss-protection", "Legacy header to enable XSS filtering in browsers. (Mostly obsolete but still used for older clients)"),
    ];

    let info_headers = vec![
        ("server", "Reveals the server software and version."),
        ("x-powered-by", "Reveals the application framework (e.g., PHP, Express)."),
        ("x-aspnet-version", "Reveals ASP.NET version."),
        ("x-generator", "Reveals the CMS or static site generator used."),
        ("x-runtime", "Reveals execution time, often found in Ruby on Rails."),
        ("via", "Reveals proxy server details."),
        ("x-cache", "Reveals caching technology (e.g., Varnish, Squid)."),
        ("cf-ray", "Cloudflare trace ID (reveals usage of Cloudflare)."),
        ("server-timing", "Reveals backend processing times and server metrics."),
    ];

    // Analyze Security Headers
    for (header, desc) in security_headers {
        match headers.get(header) {
            Some(value) => {
                present_security_headers.push((header, value.to_str().unwrap_or("Non-ASCII Value")));
                
                // Specific checks
                let val_str = value.to_str().unwrap_or("").to_lowercase();
                if header == "x-content-type-options" && val_str != "nosniff" {
                    warnings.push(("x-content-type-options", format!("Value is not 'nosniff': {:?}", value)));
                }

                if header == "cache-control" {
                    if !val_str.contains("no-store") && !val_str.contains("no-cache") {
                         warnings.push(("cache-control", "Header exists but doesn't contain 'no-store' or 'no-cache'. Sensitive data might be cached.".to_string()));
                    }
                }

                if header == "strict-transport-security" {
                    if !val_str.contains("includesubdomains") {
                        warnings.push(("strict-transport-security", "HSTS header is missing 'includeSubDomains' directive.".to_string()));
                    }
                    if !val_str.contains("max-age") {
                         warnings.push(("strict-transport-security", "HSTS header is missing 'max-age' directive.".to_string()));
                    }
                }

                if header == "x-xss-protection" && val_str == "0" {
                    warnings.push(("x-xss-protection", "Value is '0', which explicitly disables XSS protection.".to_string()));
                }
            },
            None => {
                missing_security_headers.push((header, desc));
            }
        }
    }

    // Analyze Transport Security
    let mut transport_security = Vec::new();
    let initial_is_https = initial_url.starts_with("https://");
    let final_is_https = final_url.as_str().starts_with("https://");

    if final_is_https {
        if let Some(err) = cert_error {
            transport_security.push(("Connection Status", "NOT SECURE (Invalid Certificate)".red().bold().to_string()));
            transport_security.push(("Certificate Error", err.dimmed().to_string()));
            warnings.push(("transport-security", "CRITICAL: SSL/TLS certificate validation failed. Connection is intercepted or misconfigured.".to_string()));
        } else {
            transport_security.push(("Connection Status", "SECURE (HTTPS)".green().to_string()));
            if !initial_is_https {
                 transport_security.push(("Redirection", "SUCCESSFUL (HTTP -> HTTPS)".green().to_string()));
            }
        }
    } else {
        transport_security.push(("Connection Status", "INSECURE (HTTP)".red().bold().to_string()));
        warnings.push(("transport-security", "CRITICAL: Connection is not encrypted. Data can be intercepted.".to_string()));
    }

    // Analyze CORS Headers
    let acao = headers.get("access-control-allow-origin");
    let acac = headers.get("access-control-allow-credentials");
    
    let mut cors_results = Vec::new();

    if let Some(origin) = acao {
        let origin_str = origin.to_str().unwrap_or("");
        cors_results.push(("access-control-allow-origin", origin_str));
        
        if origin_str == "*" {
            warnings.push(("access-control-allow-origin", "Wildcard '*' origin is highly permissive and generally unsafe if credentials are allowed or sensitive data is returned.".to_string()));
        } else if origin_str == "null" {
             warnings.push(("access-control-allow-origin", "The 'null' origin should not be used. It is easily exploitable.".to_string()));
        }

        if let Some(creds) = acac {
            let creds_str = creds.to_str().unwrap_or("");
            cors_results.push(("access-control-allow-credentials", creds_str));
            if origin_str == "*" && creds_str == "true" {
                 warnings.push(("cors-misconfiguration", "CRITICAL: Access-Control-Allow-Origin is '*' and Access-Control-Allow-Credentials is 'true'. This is a severe security vulnerability.".to_string()));
            }
        }
    }

    // Analyze Cookies
    let mut cookie_warnings = Vec::new();
    for cookie in headers.get_all("set-cookie") {
        let cookie_str = cookie.to_str().unwrap_or("");
        let mut missing_flags = Vec::new();
        
        let cookie_lower = cookie_str.to_lowercase();
        if !cookie_lower.contains("httponly") {
            missing_flags.push("HttpOnly");
        }
        if !cookie_lower.contains("secure") {
            missing_flags.push("Secure");
        }
        if !cookie_lower.contains("samesite") {
            missing_flags.push("SameSite");
        }

        if !missing_flags.is_empty() {
            let cookie_name = cookie_str.split('=').next().unwrap_or("Unknown");
            cookie_warnings.push((cookie_name.to_string(), missing_flags.join(", ")));
        }
    }

    // Analyze Information Leakage
    for (header, desc) in info_headers {
        if let Some(value) = headers.get(header) {
            warnings.push((header, format!("Information leak ({} = {:?}): {}", header, value.to_str().unwrap_or(""), desc)));
        }
    }

    // Output Results //
    
    println!("{}", "=== Transport Security ===".blue().bold());
    for (key, value) in transport_security {
        println!("{}: {}", key.blue(), value);
    }

    println!("\n{}", "=== CORS Headers Configuration ===".cyan().bold());
    if cors_results.is_empty() {
         println!("{}", "No CORS headers found (Restricted to same-origin by default)".dimmed());
    } else {
         for (header, value) in cors_results {
             println!("{}: {}", header.cyan(), value);
         }
    }

    println!("\n{}", "=== Cookie Security Analysis ===".magenta().bold());
    if cookie_warnings.is_empty() {
        if headers.get("set-cookie").is_some() {
            println!("{}", "All cookies identified have secure flags.".green());
        } else {
            println!("{}", "No cookies found in response.".dimmed());
        }
    } else {
        for (cookie, missing) in cookie_warnings {
            println!("{} - {} Missing flags: {}", "Cookie:".magenta(), cookie.bold(), missing.red());
        }
    }

    println!("\n{}", "=== Security Headers Present ===".green().bold());
    if present_security_headers.is_empty() {
        println!("{}", "None".dimmed());
    } else {
        for (header, value) in present_security_headers {
            println!("{}: {}", header.green(), value);
        }
    }
    
    println!("\n{}", "=== Missing Security Headers ===".red().bold());
    if missing_security_headers.is_empty() {
        println!("{}", "None! Excellent!".green().bold());
    } else {
        for (header, desc) in missing_security_headers {
            println!("{} - {}", header.red().bold(), desc.dimmed());
        }
    }

    println!("\n{}", "=== Warnings & Information Leaks ===".yellow().bold());
    if warnings.is_empty() {
        println!("{}", "None! Good job!".green().bold());
    } else {
        for (header, warning) in warnings {
            if warning.starts_with("CRITICAL") {
                 println!("{}: {}", header.red().bold(), warning.red().bold());
            } else {
                 println!("{}: {}", header.yellow().bold(), warning);
            }
        }
    }

    println!("\n{}", "Note: For a comprehensive analysis, verify correct configuration values beyond mere presence.".dimmed());

    Ok(())
}
