use std::io::{ErrorKind, Write};
use std::{env, fs, io, sync};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;

fn main() {
    // Serve an echo service over raw tls data, with proper error handling.
    if let Err(e) = run_server() {
        eprintln!("FAILED: {}", e);
        std::process::exit(1);
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main(flavor = "current_thread")]
async fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        sync::Arc::new(cfg)
    };

    // Create a TCP listener
    let tcp = TcpListener::bind(&addr).await?;
    // Create Tokio specific TlsAcceptor to handle requests
    let tls_acceptor = TlsAcceptor::from(tls_cfg);
    // Prepare a long-running future stream to accept and serve clients.
    loop {
        println!("awaiting new client");
        let acceptor = tls_acceptor.clone(); // We need a new Acceptor for each client because of TLS connection state
        let (socket, _) = tcp.accept().await?; // Accept TCP client

        // Create future for handleing TLS handshake
        let fut = async move {
            let mut tls = acceptor.accept(socket).await?; // Perform TLS Handshake
            println!("tls established");

            // ---------------- Demo specific payload starts here ----------------
            // read stream until 0x00 occurs then repeat the exact same sequence to the client (echo)
            let mut buf_tls = BufReader::new(&mut tls);
            let mut buf = vec![];

            match buf_tls.read_until(0, &mut buf).await {
                Ok(_) => (),
                Err(err) => {
                    if err.kind() == ErrorKind::ConnectionReset {
                        println!("connection closed");
                        return io::Result::Ok(()); // Return OK on Connection reset
                    } else {
                        return Err(err);
                    }
                }
            }
            tls.write_all(&buf).await?;
            std::io::stdout().write_all(&buf)?; // Write echoed message to stdout
                                                // ---------------- Demo specific payload ends here ----------------

            io::Result::Ok(()) // Connection will be automatically closed when future exits
        };

        // Execute the future
        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err); // Print error and keep going (Likely tls handshake failed/tcp connection failed)
                                        // One may want to differentiate this error in production and take different actions
            }
        });
    }
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}:\n{}", filename, e)))?;
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
