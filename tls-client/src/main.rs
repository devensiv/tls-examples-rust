use std::sync::Arc;

use std::convert::TryInto;
use std::io::{stdout, BufReader, Read, Write};
use std::net::TcpStream;

use std::fs::File;

use rustls::RootCertStore;

fn main() {
    // Load custom server certificate
    let mut root_store = RootCertStore::empty();
    let certs = load_certs("server.crt").unwrap();
    root_store.add(&certs[0]).unwrap();

    /* Use Mozilla set of root certificates using webpki_roots crate
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    */

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // This has to be one of the valid aliases in the servers certificate
    let server_name = "hostname".try_into().unwrap();

    // Create client side handshake handler
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();

    // Connect to the server via TCP
    let mut sock = TcpStream::connect("127.0.0.1:9999").unwrap();
    // Perform TLS Handshake and create TLS Stream
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    // ---------------- Demo specific payload starts here ----------------
    // Send message to the server
    tls.write_all(b"abcde\nhehe\n\0").unwrap();
    // Get the active cipher suite and print it
    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    // Receive the server response and print it to stdout
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).unwrap();
    stdout().write_all(&buf).unwrap();
    // ---------------- Demo specific payload starts here ----------------

    // Connection is automatically closed as it leaves scope and is cleaned up
}

// Load server certificate from file.
fn load_certs(filename: &str) -> std::io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = File::open(filename)
        .map_err(|e| panic!("failed to open {}: {}", filename, e))
        .unwrap();
    let mut reader = BufReader::new(certfile);

    // Load and return certificate.
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| panic!("failed to load certificate"))
        .unwrap();
    Ok(certs.into_iter().map(rustls::Certificate).collect())
}
