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
    
    // Parse URL, add schema if missing
    let target_url = if cli.url.starts_with("http://") || cli.url.starts_with("https://") {
        cli.url.clone()
    } else {
        format!("https://{}", cli.url)
    };

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
    let response = match request_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            println!("{} {}", "✗ Error connecting to target:".red().bold(), e);
            std::process::exit(1);
        }
    };
    
    if !cli.only_headers {
        println!("{} {}\n", "HTTP Status:".bold(), response.status().as_u16());
    }
    
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

    // Analyze Information Leakage
    for (header, desc) in info_headers {
        if let Some(value) = headers.get(header) {
            warnings.push((header, format!("Information leak ({} = {:?}): {}", header, value.to_str().unwrap_or(""), desc)));
        }
    }

    // Output Results //
    
    println!("{}", "=== CORS Headers Configuration ===".cyan().bold());
    if cors_results.is_empty() {
         println!("{}", "No CORS headers found (Restricted to same-origin by default)".dimmed());
    } else {
         for (header, value) in cors_results {
             println!("{}: {}", header.cyan(), value);
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
