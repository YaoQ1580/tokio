use std::{env, io};
use std::sync::Arc;
use serde::Deserialize;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls::pki_types::ServerName;
use webpki_roots::TLS_SERVER_ROOTS;

// Bring std::io Read/Write extension traits into scope for conn.reader()/writer()
use std::io::{Read as _, Write as _};

#[derive(Debug, Deserialize)]
struct BookTicker {
    symbol: String,
    #[serde(rename = "bidPrice")]
    bid_price: String,
    #[serde(rename = "bidQty")]
    bid_qty: String,
    #[serde(rename = "askPrice")]
    ask_price: String,
    #[serde(rename = "askQty")]
    ask_qty: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. symbol from CLI (default BTCUSDT)
    let symbol = env::args()
        .nth(1)
        .unwrap_or_else(|| "BTCUSDT".to_string())
        .to_uppercase();

    // 2. Connect TCP
    let addr = "api.binance.com:443";
    println!("Connecting to {} ...", addr);
    // 打印 api.binance.com 的 ip 地址
    let ip_addr = gethostbyname(addr.split(':').next().unwrap());
    println!("IP address: {}", ip_addr);
    // TCP 可以直接连接 IP 加 PORT 吗
    let mut stream = TcpStream::connect(addr).await?;

    // 3. Build rustls config / connector (no tokio-dependent crates)
    let root_store = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from("api.binance.com")?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;

    // 4. Perform TLS handshake manually (async)
    tls_handshake(&mut stream, &mut conn).await?;

    // 5. Send HTTP request
    let path = format!(
        "/api/v3/ticker/bookTicker?symbol={}",
        symbol
    );
    let http_req = format!(
        "GET {} HTTP/1.1\r\nHost: api.binance.com\r\nUser-Agent: rust-tokio-demo\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        path
    );
    conn.writer().write_all(http_req.as_bytes())?;

    flush_tls(&mut stream, &mut conn).await?;

    // 6. Read the whole HTTP response
    let mut response_body = Vec::new();
    let mut plain_buf = [0u8; 4096];
    loop {
        // If TLS session wants to write encrypted frames → flush them.
        if conn.wants_write() {
            flush_tls(&mut stream, &mut conn).await?;
        }

        // Read more ciphertext from socket
        let mut cipher_buf = [0u8; 4096];
        let n = stream.read(&mut cipher_buf).await?;
        if n == 0 {
            break; // socket closed
        }
        let mut cursor = io::Cursor::new(&cipher_buf[..n]);
        conn.read_tls(&mut cursor)?;
        conn.process_new_packets()?;

        // Drain decrypted plaintext
        while let Ok(n_plain) = conn.reader().read(&mut plain_buf) {
            if n_plain == 0 {
                break;
            }
            response_body.extend_from_slice(&plain_buf[..n_plain]);
        }
    }

    // 7. Separate headers & body
    let resp_text = String::from_utf8_lossy(&response_body);
    let (_, body) = resp_text.split_once("\r\n\r\n").ok_or("Invalid HTTP")?;

    // 8. Parse JSON
    let ticker: BookTicker = serde_json::from_str(body.trim())?;

    println!(
        "Symbol: {symbol}\n  Bid: {bid} ({bid_qty})\n  Ask: {ask} ({ask_qty})",
        symbol = ticker.symbol,
        bid = ticker.bid_price,
        bid_qty = ticker.bid_qty,
        ask = ticker.ask_price,
        ask_qty = ticker.ask_qty
    );

    Ok(())
}

// ---------- helpers ----------

async fn flush_tls(stream: &mut TcpStream, conn: &mut ClientConnection) -> io::Result<()> {
    while conn.wants_write() {
        let mut buf = Vec::new();
        conn.write_tls(&mut buf)?;
        stream.write_all(&buf).await?;
    }
    Ok(())
}

async fn tls_handshake(stream: &mut TcpStream, conn: &mut ClientConnection) -> io::Result<()> {
    loop {
        if conn.is_handshaking() {
            // Read if needed
            if conn.wants_read() {
                let mut cipher_buf = [0u8; 1024];
                let n = stream.read(&mut cipher_buf).await?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof during handshake"));
                }
                let mut cursor = io::Cursor::new(&cipher_buf[..n]);
                conn.read_tls(&mut cursor)?;
                conn.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }

            // Write if needed
            flush_tls(stream, conn).await?;
        } else {
            break;
        }
    }
    Ok(())
}

