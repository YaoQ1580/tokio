use std::io;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::TcpStream;
use std::env;

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

fn main() {
    let mut args: Vec<String> = env::args().collect();
    let config_file = args.pop().expect("No config file");
    tokio::fstack_init(args.len(), args);

    let runtime = Runtime::new().expect("create runtime failed");
    set_runtime(runtime);
    
    block_on(async {
        println!("Connecting to 8.218.95.212:9999...");
    
        // 连接到服务器
        let stream = TcpStream::connect("8.218.95.212:9999").await?;
        println!("Connected successfully!");
        
        let mut reader = BufReader::new(stream);
        let mut buffer = [0u8; 1024]; // 增大缓冲区用于读取字符数据
        
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    // 连接已关闭
                    println!("Connection closed by server");
                    break;
                }
                Ok(n) => {
                    // 读取到n个字节
                    let data = &buffer[..n];
                    
                    // 尝试转换为UTF-8字符串
                    match std::str::from_utf8(data) {
                        Ok(text) => {
                            println!("Received text: {}", text);
                        }
                        Err(_) => {
                            // 如果不是有效的UTF-8，打印原始字节
                            println!("Received raw bytes: {:?}", data);
                        }
                    }
                    
                    println!("---");
                }
                Err(e) => {
                    eprintln!("Error reading from server: {}", e);
                    break;
                }
            }
        }
        
        println!("Connection closed.");
        Ok::<(), std::io::Error>(())
    });

    tokio::fstack_stop_run();
}
