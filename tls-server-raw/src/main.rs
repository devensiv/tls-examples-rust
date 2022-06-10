use rustls::ServerConnection;
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::{env, fs, io};

fn main() {
    // Serve an echo service , with proper error handling.
    if let Err(e) = run_server() {
        eprintln!("FAILED: {}", e);
        std::process::exit(1);
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    // First parameter is port number (optional, defaults to 9999)
    let port = match env::args().nth(1) {
        Some(ref p) => p.to_owned(),
        None => "9999".to_owned(),
    };

    // Has to be set to 0.0.0.0 in order to accept requests from all IPs
    let addr = format!("127.0.0.1:{}", port);

    // Build TLS configuration.
    let tls_cfg = {
        // Load public certificate.
        let certs = load_certs("server.crt")?;
        // Load private key.
        let key = load_private_key("server.key")?;

        let cfg = rustls::ServerConfig::builder()
            .with_safe_defaults() // Only allow safe TLS configurations
            .with_no_client_auth() // Disable client auth
            .with_single_cert(certs, key) // Set server certificate
            .map_err(|e| error(format!("{}", e)))?;
        Arc::new(cfg)
    };

    // Create a TCP listener
    let tcp = TcpListener::bind(&addr)?;
    loop {
        println!("awaiting new client");
        let (mut socket, _) = tcp.accept()?;

        // Prepare server side tls handshake
        let mut conn = ServerConnection::new(tls_cfg.clone())?;
        // Perform TLS handshake and create the stream
        let mut tls = rustls::Stream::new(&mut conn, &mut socket);
        println!("tls established");

        // ---------------- Demo specific payload starts here ----------------
        // read stream until 0x00 occurs then repeat the exact same sequence to the client (echo)
        let mut buf_tls = BufReader::new(&mut tls);
        let mut buf = vec![];

        match buf_tls.read_until(0, &mut buf) {
            Ok(_) => (),
            Err(err) => {
                if err.kind() == ErrorKind::ConnectionReset {
                    println!("connection closed");
                    return Ok(()); // Return OK on Connection reset
                } else {
                    return Err(Box::new(err));
                }
            }
        }
        tls.write_all(&buf)?;
        std::io::stdout().write_all(&buf)?; // Write echoed message to stdout
                                            // ---------------- Demo specific payload ends here ----------------
    }
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| error("failed to load certificate".into()))?;
    Ok(certs.into_iter().map(rustls::Certificate).collect())
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|_| error("failed to load private key".into()))?;
    if keys.len() != 1 {
        return Err(error(format!(
            "expected a single private key. got {}",
            keys.len()
        )));
    }

    Ok(rustls::PrivateKey(keys[0].clone()))
}
