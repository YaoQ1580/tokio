use std::io;
use std::env;
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

thread_local!(
    pub static CURRENT: std::cell::RefCell<Option<Runtime>> =
        const { std::cell::RefCell::new(None) };
);

#[derive(Debug)]
pub struct Runtime {
    local: tokio::task::LocalSet,
    rt: tokio::runtime::Runtime,
}

pub(crate) fn default_tokio_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

impl Runtime {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> std::io::Result<Self> {
        let rt = default_tokio_runtime()?;
        let rt = Runtime {
            rt,
            local: tokio::task::LocalSet::new(),
        };
        Ok(rt)
    }

    #[track_caller]
    pub fn spawn<F>(
        &self,
        future: F,
    ) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + 'static,
    {
        self.local.spawn_local(future)
    }

    pub fn tokio_runtime(&self) -> &tokio::runtime::Runtime { &self.rt }

    #[track_caller]
    pub fn block_on<F>(
        &self,
        f: F,
    ) -> F::Output
    where
        F: std::future::Future,
    {
        self.local.block_on(&self.rt, f)
    }
}

pub fn set_runtime(rt: Runtime) {
    CURRENT.with(|cell| {
        *cell.borrow_mut() = Some(rt);
    })
}

#[track_caller]
#[inline]
pub fn block_on<F>(f: F) -> F::Output
where
    F: std::future::Future,
{
    CURRENT.with(|cell| match *cell.borrow() {
        Some(ref rt) => rt.block_on(f),
        None => panic!("System is not running"),
    })
}

#[track_caller]
#[inline]
pub fn spawn<Fut>(f: Fut) -> tokio::task::JoinHandle<<Fut as std::future::Future>::Output>
where
    Fut: std::future::Future + 'static,
    Fut::Output: 'static,
{
    CURRENT.with(|cell| match *cell.borrow() {
        Some(ref rt) => rt.spawn(f),
        None => panic!("System is not running"),
    })
}

// #[tokio::main]
// async fn main() -> io::Result<()> {
//     println!("Connecting to 8.218.95.212:9999...");
    
//     // 连接到服务器
//     let stream = TcpStream::connect("8.218.95.212:9999").await?;
//     println!("Connected successfully!");
    
//     let mut reader = BufReader::new(stream);
//     let mut buffer = [0u8; 1024]; // 增大缓冲区用于读取字符数据
    
//     loop {
//         match reader.read(&mut buffer).await {
//             Ok(0) => {
//                 // 连接已关闭
//                 println!("Connection closed by server");
//                 break;
//             }
//             Ok(n) => {
//                 // 读取到n个字节
//                 let data = &buffer[..n];
                
//                 // 尝试转换为UTF-8字符串
//                 match std::str::from_utf8(data) {
//                     Ok(text) => {
//                         println!("Received text: {}", text);
//                     }
//                     Err(_) => {
//                         // 如果不是有效的UTF-8，打印原始字节
//                         println!("Received raw bytes: {:?}", data);
//                     }
//                 }
                
//                 println!("---");
//             }
//             Err(e) => {
//                 eprintln!("Error reading from server: {}", e);
//                 break;
//             }
//         }
//     }
    
//     println!("Connection closed.");
//     Ok(())
// }

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



fn main() {
    let mut args: Vec<String> = env::args().collect();
    let config_file = args.pop().expect("No config file");
    tokio::fstack_init(args.len(), args);

    let runtime = Runtime::new().expect("create runtime failed");
    set_runtime(runtime);
    
    block_on(async {
        // 1. symbol from CLI (default BTCUSDT)
        let symbol = env::args()
        .nth(1)
        .unwrap_or_else(|| "BTCUSDT".to_string())
        .to_uppercase();

        // 2. Connect TCP
        let addr = "api.binance.com:443";
        println!("Connecting to {} ...", addr);
        let mut stream = TcpStream::connect(addr).await?;
        println!("Connected successfully!");

        // 3. Build rustls config / connector (no tokio-dependent crates)
        let root_store = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        println!("Building rustls config...");
        let server_name = ServerName::try_from("api.binance.com")?;
        let mut conn = ClientConnection::new(Arc::new(config), server_name)?;
        println!("rustls config built!");

        // 4. Perform TLS handshake manually (async)
        println!("Performing TLS handshake...");
        tls_handshake(&mut stream, &mut conn).await?;
        println!("TLS handshake completed!");

        // 5. Send HTTP request
        let path = format!(
            "/api/v3/ticker/bookTicker?symbol={}",
            symbol
        );
        let http_req = format!(
            "GET {} HTTP/1.1\r\nHost: api.binance.com\r\nUser-Agent: rust-tokio-demo\r\nConnection: close\r\nAccept: */*\r\n\r\n",
            path
        );
        println!("Sending HTTP request...");
        conn.writer().write_all(http_req.as_bytes())?;
        println!("HTTP request sent!");

        println!("Flushing TLS...");
        flush_tls(&mut stream, &mut conn).await?;
        println!("TLS flushed!");

        // 6. Read the whole HTTP response
        let mut response_body = Vec::new();
        let mut plain_buf = [0u8; 4096];
        loop {
            // If TLS session wants to write encrypted frames → flush them.
            if conn.wants_write() {
                println!("Flushing TLS...");
                flush_tls(&mut stream, &mut conn).await?;
                println!("TLS flushed!");
            }

            // Read more ciphertext from socket
            let mut cipher_buf = [0u8; 4096];
            println!("Reading ciphertext from socket...");
            let n = stream.read(&mut cipher_buf).await?;
            println!("Ciphertext read!");
            if n == 0 {
                println!("Socket closed!");
                break; // socket closed
            }
            let mut cursor = io::Cursor::new(&cipher_buf[..n]);
            println!("Reading TLS...");
            conn.read_tls(&mut cursor)?;
            println!("TLS read!");
            conn.process_new_packets()?;
            println!("TLS processed!");

            // Drain decrypted plaintext
            while let Ok(n_plain) = conn.reader().read(&mut plain_buf) {
                if n_plain == 0 {
                    println!("No more plaintext to read!");
                    break;
                }
                response_body.extend_from_slice(&plain_buf[..n_plain]);
            }
        }

        // 7. Separate headers & body
        println!("Separating headers & body...");
        let resp_text = String::from_utf8_lossy(&response_body);
        let (_, body) = resp_text.split_once("\r\n\r\n").ok_or("Invalid HTTP")?;
        println!("Headers & body separated!");

        // 8. Parse JSON
        println!("Parsing JSON...");
        let ticker: BookTicker = serde_json::from_str(body.trim())?;
        println!("JSON parsed!");

        println!(
            "Symbol: {symbol}\n  Bid: {bid} ({bid_qty})\n  Ask: {ask} ({ask_qty})",
            symbol = ticker.symbol,
            bid = ticker.bid_price,
            bid_qty = ticker.bid_qty,
            ask = ticker.ask_price,
            ask_qty = ticker.ask_qty
        );

        Ok::<(), Box<dyn std::error::Error>>(())
    });

    tokio::fstack_stop_run();
}

