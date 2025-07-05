use std::env;
use serde::{Deserialize, Serialize};

use std::fmt::Debug;
use std::net::Ipv4Addr;
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// Bring std::io Read/Write extension traits into scope for conn.reader()/writer()
use std::io::{Read as _, Write as _};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_kcp::{KcpConfig, KcpNoDelayConfig, KcpStream};

#[inline(always)]
pub fn now_ns_sys() -> u64 {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

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


// kcp related
pub struct ProxyClientConnection {
    pub remote_addr: String,
    local_ip: Option<Ipv4Addr>,

    stream: Option<KcpStream>,
    // 2M 的缓冲区
    buf: Vec<u8>,

    conn_id: String,
    pub write_update_id: u64,
    pub read_update_id: u64,
}

impl ProxyClientConnection {
    pub fn new(
        remote_addr: String,
        local_ip: Option<Ipv4Addr>,
        conn_id: Option<String>,
    ) -> Self {
        let conn_id = match conn_id {
            Some(id) => id,
            None => {
                let id: u64 = rand::random();
                id.to_string()
            }
        };
        ProxyClientConnection {
            remote_addr,
            local_ip,
            stream: None,
            buf: vec![0; 2048 * 1024],
            conn_id,
            read_update_id: 0,
            write_update_id: 0,
        }
    }

    pub async fn connect(&mut self) {
        println!(
            "proxy client datasource trying to connect {:?}",
            self.remote_addr
        );

        // Create KCP configuration with proper low-latency settings
        let mut config = KcpConfig::default();
        config.nodelay = KcpNoDelayConfig {
            nodelay: true,
            interval: 1, // 每 1ms 检查事件
            resend: 1,   // 极快重传
            nc: true,
        };
        config.wnd_size = (1024, 1024);
        config.flush_write = true;
        config.flush_acks_input = true;

        // 连接到服务器
        let mut stream = KcpStream::connect(&config, self.remote_addr.parse().unwrap()).await;
        if let Err(e) = stream {
            eprintln!("A client failed! Caused by {:?}", e);
            panic!("connect to {} failed", self.remote_addr);
        }
        let mut stream = stream.unwrap();

        // 向 send 发送第一条消息： conn-id:self.conn_id.to_string()
        let data = format!("conn-id:{}", self.conn_id);
        println!("send first message: conn-id: {}", data);
        let err = stream.write_all(data.as_bytes()).await;
        if let Err(e) = err {
            eprintln!("A client failed! Caused by {:?}", e);
            panic!("send first message failed");
        }
        stream.flush().await;

        self.stream = Some(stream);
        println!(
            "proxy client datasource connect {:?} success",
            self.remote_addr
        );
    }

    pub async fn read(&mut self) -> Option<&[u8]> {
        if self.stream.is_none() {
            eprintln!("proxy client connect is none");
            return None;
        }

        // 先读取4字节的长度头
        let mut len_buf = [0u8; 4];
        match self.stream.as_mut().unwrap().read_exact(&mut len_buf).await {
            Result::Ok(_) => {}
            Err(e) => {
                eprintln!("Failed to read length header: {}", e);
                return None;
            }
        }

        let data_len = u32::from_be_bytes(len_buf) as usize;

        // 验证长度是否合理
        if data_len == 0 || data_len > self.buf.len() {
            eprintln!("Invalid data length: {}", data_len);
            return None;
        }

        // 读取指定长度的数据
        match self
            .stream
            .as_mut()
            .unwrap()
            .read_exact(&mut self.buf[..data_len])
            .await
        {
            Result::Ok(_) => Some(&self.buf[..data_len]),
            Err(e) => {
                eprintln!("Failed to read data: {}", e);
                None
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum BkBaseError {
    #[error("Parse base string to Asset failed, invalid input: {0}")]
    InvalidAssetString(String),

    #[error("parse host to tls domain failed, invalid input: {0}")]
    TlsInvalidHostString(String),

    #[error("Invalid Ws address: {0}")]
    InvliadWebsocketAddress(String),

    #[error("fastwebsocekt crate error: {0:?}")]
    FastWebsocketError(String),

    #[error("Not support: {0}")]
    NotsupportError(String),

    #[error("Unexpect error: {0}")]
    UnexpectError(String),
}
impl From<anyhow::Error> for BkBaseError {
    fn from(err: anyhow::Error) -> Self {
        match err.downcast::<BkBaseError>() {
            std::result::Result::Ok(my_err) => my_err,
            std::result::Result::Err(err) => BkBaseError::UnexpectError(err.to_string()),
        }
    }
}

use bitcode::{Decode, Encode};
use std::fmt::{self, Display};
use std::str::FromStr;
use strum_macros::{Display, EnumIter, EnumString};

// Constants
pub const DEPTH_DATA_LENGTH: usize = 5;

#[derive(Encode, Decode, Debug)]
pub struct ProxyDataWrapper<T> {
    /// 行情数据
    pub data: T,
    /// bkmarket 写入共享内存时的本地时间戳，单位纳秒
    pub local_time_ns: u64,
    /// 更新 ID，用于判断丢包
    pub update_id: u64,
}

/// 深度单独档位信息
#[derive(Debug, Clone, Default, Copy, Encode, Decode)]
pub struct DepthRowData {
    pub price: f64,
    /// 无论是 bid 还是 ask，volume 都是正数
    pub volume: f64,
}

#[macro_export]
macro_rules! bkcurrency {
    ($value:expr) => {{
        let value_bytes = $value.as_bytes();
        let mut currency = [0; 15];
        let len = if value_bytes.len() < 15 {
            value_bytes.len()
        } else {
            15
        };
        let mut i = 0;
        while i < len {
            currency[i] = value_bytes[i];
            i += 1;
        }
        Currency {
            inner: currency,
            len: len as u8,
        }
    }};
}

// 定义一些常用货币
pub const CURRENCY_USD: Currency = bkcurrency!("USD");
pub const CURRENCY_BNB: Currency = bkcurrency!("BNB");
pub const CURRENCY_USDT: Currency = bkcurrency!("USDT");
pub const CURRENCY_USDC: Currency = bkcurrency!("USDC");
pub const CURRENCY_SHIB1000: Currency = bkcurrency!("1000SHIB");
pub const CURRENCY_BTC: Currency = bkcurrency!("BTC");
pub const CURRENCY_ETH: Currency = bkcurrency!("ETH");
pub const CURRENCY_SOL: Currency = bkcurrency!("SOL");

#[derive(Clone, PartialEq, Eq, Copy, Hash, Encode, Decode)]
/// 不处理 UTF-8，只接受 ASCII
pub struct BkString<const N: usize> {
    pub inner: [u8; N],
    pub len: u8,
}

impl<const N: usize> BkString<N> {
    pub fn as_str(&self) -> &str {
        // 我们假定字符串都是 ASCII 字符, 一定只占用 1 字节
        unsafe {
            let bytes: &[u8] = std::slice::from_raw_parts(self.inner.as_ptr(), self.len as usize);
            std::str::from_utf8_unchecked(bytes)
        }
    }

    pub fn from_u64(mut num: u64) -> Self {
        let mut currency = [0; N];
        let mut i = 0;
        loop {
            let c = (num & 0x0F) as u8 + 'a' as u8;
            currency[i] = c;
            i += 1;
            num = num >> 4;
            if num == 0 {
                break;
            }
        }

        BkString {
            inner: currency,
            len: i as u8,
        }
    }

    pub fn push_bkstring<const M: usize>(
        &mut self,
        b: &BkString<M>,
    ) {
        for i in 0..b.len as usize {
            self.inner[self.len as usize] = b.inner[i];
            self.len += 1;
        }
    }

    pub fn push_str(
        &mut self,
        b: &str,
    ) {
        let bytes = b.as_bytes();
        for i in 0..b.len() as usize {
            self.inner[self.len as usize] = bytes[i];
            self.len += 1;
        }
    }

    pub fn eq(
        &self,
        b: &str,
    ) -> bool {
        if self.len as usize != b.len() {
            return false;
        }
        let bytes = b.as_bytes();
        for i in 0..self.len as usize {
            if self.inner[i] != bytes[i] {
                return false;
            }
        }
        return true;
    }
}

impl<const N: usize> FromStr for BkString<N> {
    type Err = BkBaseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut currency = [0; N];
        for (i, c) in s.chars().enumerate() {
            currency[i] = c as u8;
        }

        Ok(BkString {
            inner: currency,
            len: s.len() as u8,
        })
    }
}

impl<const N: usize> From<String> for BkString<N> {
    fn from(s: String) -> Self {
        let mut currency = [0; N];
        for (i, c) in s.chars().enumerate() {
            currency[i] = c as u8;
        }

        BkString {
            inner: currency,
            len: s.len() as u8,
        }
    }
}

impl<const N: usize> Display for BkString<N> {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let mut result = String::new();
        for &ch in self.inner.iter().take(self.len as usize) {
            result.push(ch as char);
        }
        write!(f, "{}", result)
    }
}

impl<const N: usize> fmt::Debug for BkString<N> {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        // 获取 ASCII 字符串
        let ascii_str = self.as_str();
        // 使用 Debug 格式化字符串，添加引号
        write!(f, "{}", ascii_str)
    }
}

/// 币种/货币/资产单元
///
/// 默认使用 8 位定长字符来存储
pub type Currency = BkString<15>;

impl Serialize for Currency {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let balance_id = String::deserialize(deserializer)?;
        Currency::from_str(&balance_id).map_err(serde::de::Error::custom)
    }
}

/// 将币种转换为原始币种和倍数, 1000PEPE -> PEPE, 1000
impl Currency {
    pub fn into_origin_currency(&self) -> (Currency, f64) {
        if self.inner.starts_with(b"1000000") {
            let t = unsafe { std::str::from_utf8_unchecked(&self.inner[7..]) };
            return (Currency::from_str(t).unwrap(), 1000000.0);
        } else if self.inner.starts_with(b"100000") {
            let t = unsafe { std::str::from_utf8_unchecked(&self.inner[6..]) };
            return (Currency::from_str(t).unwrap(), 100000.0);
        } else if self.inner.starts_with(b"10000") {
            let t = unsafe { std::str::from_utf8_unchecked(&self.inner[5..]) };
            return (Currency::from_str(t).unwrap(), 10000.0);
        } else if self.inner.starts_with(b"1000") {
            let t = unsafe { std::str::from_utf8_unchecked(&self.inner[4..]) };
            return (Currency::from_str(t).unwrap(), 1000.0);
        } else {
            return (self.clone(), 1.0);
        }
    }
}

/// 交易所
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Copy,
    Hash,
    Display,
    EnumString,
    Encode,
    Decode,
    Deserialize,
    Serialize,
    EnumIter,
)]
pub enum Exchange {
    BINANCE,
    BYBIT,
    OKEX,
    BITGET,
    COINEXV2,
    NONE,
}

pub struct ExchangeMetaInfo {
    pub support_test_order: bool,
}

impl Exchange {
    pub fn get_meta(&self) -> ExchangeMetaInfo {
        let support_test_ordert = match self {
            Exchange::BITGET | Exchange::NONE => false,
            Exchange::BINANCE | Exchange::BYBIT | Exchange::OKEX | Exchange::COINEXV2 => true,
        };

        ExchangeMetaInfo {
            support_test_order: support_test_ordert,
        }
    }
}

/// 交易类型
#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash, Display, EnumString, Encode, Decode)]
pub enum AssetType {
    /// 现货交易
    SPOT,
    /// 永续合约交易
    SWAP,
}

/// 品种信息
///
/// 品种用来描述交易市场信息的标识
#[derive(Clone, PartialEq, Eq, Copy, Hash, Encode, Decode)]
#[repr(C)]
pub struct Asset {
    /// 交易对
    pub pair: (Currency, Currency),
    /// 交易所
    pub exchange: Exchange,
    /// 交易类型
    pub asset_type: AssetType,
}

impl Serialize for Asset {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Asset {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let balance_id = String::deserialize(deserializer)?;
        Asset::from_str(&balance_id).map_err(serde::de::Error::custom)
    }
}

impl Display for Asset {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let str = format!(
            "{}_{}_{}-{}",
            self.exchange,
            self.asset_type,
            self.pair.0.as_str(),
            self.pair.1.as_str()
        );
        write!(f, "{}", str)
    }
}

impl std::fmt::Debug for Asset {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let str = format!(
            "{}_{}_{}-{}",
            self.exchange,
            self.asset_type,
            self.pair.0.as_str(),
            self.pair.1.as_str()
        );
        write!(f, "{}", str)
    }
}

impl FromStr for Asset {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('_');
        let exchange = parts
            .next()
            .ok_or_else(|| BkBaseError::InvalidAssetString(s.to_string()))?;
        let exchange = Exchange::from_str(exchange)?;
        let asset_type = parts
            .next()
            .ok_or_else(|| BkBaseError::InvalidAssetString(s.to_string()))?;
        let asset_type = AssetType::from_str(asset_type)?;
        let pair = parts
            .next()
            .ok_or_else(|| BkBaseError::InvalidAssetString(s.to_string()))?;
        let mut parts = pair.split('-');
        let left = parts
            .next()
            .ok_or_else(|| BkBaseError::InvalidAssetString(s.to_string()))?;
        let left_currency = Currency::from_str(left)?;
        let right = parts
            .next()
            .ok_or_else(|| BkBaseError::InvalidAssetString(s.to_string()))?;
        let right_currency = Currency::from_str(right)?;

        Ok(Asset {
            pair: (left_currency, right_currency),
            exchange,
            asset_type,
        })
    }
}

#[derive(Debug, Clone, Encode, Decode)]
#[repr(C)]
pub struct DepthData {
    /// 深度品种
    pub asset: Asset,
    pub update_id: Option<u64>,
    pub bids: [Option<DepthRowData>; DEPTH_DATA_LENGTH],
    pub asks: [Option<DepthRowData>; DEPTH_DATA_LENGTH],
    /// 本地纳秒时间戳
    pub local_time_ns: u64,
    /// 服务器毫秒时间戳
    pub server_time: u64,
    /// match engine毫秒时间戳
    pub transaction_time: u64,
}

impl DepthData {
    #[inline]
    pub fn write(
        &mut self,
        depth_data: DepthData,
    ) {
        self.update_id = depth_data.update_id;
        self.bids = depth_data.bids;
        self.asks = depth_data.asks;
        self.local_time_ns = depth_data.local_time_ns;
        self.server_time = depth_data.server_time;
        self.transaction_time = depth_data.transaction_time;
        self.asset = depth_data.asset;
    }

    pub fn mid_price(&self) -> f64 {
        (self.bids[0].unwrap().price + self.asks[0].unwrap().price) / 2.0
    }

    pub fn is_ticker(&self) -> bool { self.bids[1].is_none() && self.asks[1].is_none() }
}

/// 成交信息
#[derive(Debug, Clone, Encode, Decode)]
#[repr(C)]
pub struct TradeData {
    pub asset: Asset,
    pub price: f64,
    /// 正负区分买卖
    pub volume: f64,
    /// 本地纳秒时间戳
    pub local_time_ns: u64,
    /// 服务器毫秒时间戳
    pub server_time: u64,
    /// match engine毫秒时间戳
    pub transaction_time: u64,
    /// trade id, 通常是一个自增 ID
    pub id: Option<u64>,
}

#[derive(Debug)]
pub struct ProxyMarketUpdateData {
    pub depth: Option<DepthData>,
    pub trade: Option<TradeData>,
}

pub const DEPTH_DATA_CODE: u8 = 4;
pub const TRADE_DATA_CODE: u8 = 5;

pub fn decode_data<T>(
    mut read_update_id: u64,
    payload: &[u8],
    result_opt: &mut Option<T>,
) -> u64
where
    T: for<'a> Decode<'a> + Debug,
{
    // print payload last byte
    // println!("[YQ DEBUG] client recv last byte: {:?}", payload[payload.len() -
    // 1]);

    let data: ProxyDataWrapper<T> =
        bitcode::decode(&payload[0..payload.len() - 1]).expect("decode data fail");
    read_update_id += 1;
    if read_update_id != data.update_id {
        eprintln!(
            "data update is not continous, self id:{} data id:{}",
            read_update_id,
            data.update_id
        );
        read_update_id = data.update_id;
    }

    println!(
        "client recv {:?} delay:{} ns",
        data,
        now_ns_sys() - data.local_time_ns
    );
    result_opt.replace(data.data);
    return read_update_id;
}

pub async fn read_market_data(
    client: &mut ProxyClientConnection,
    data: &mut ProxyMarketUpdateData,
) {
    let update_id = client.read_update_id;
    println!("read_market_data update_id:{}", update_id);
    let payload = client.read().await;
    println!("read_market_data finished");
    if payload.is_none() {
        client.connect().await;
        return;
    }
    let payload = payload.unwrap();
    let channel_tag = payload.last().expect("empty forwarding frame");
    match channel_tag {
        &DEPTH_DATA_CODE => {
            client.read_update_id = decode_data(update_id, &payload, &mut data.depth);
        }
        &TRADE_DATA_CODE => {
            client.read_update_id = decode_data(update_id, &payload, &mut data.trade);
        }
        _ => {
            eprintln!("unkown tag, {}", channel_tag);
        }
    }
}
// kcp related

fn main() {
    let mut args: Vec<String> = env::args().collect();
    tokio::fstack_init(args.len(), args);

    let runtime = Runtime::new().expect("create runtime failed");
    set_runtime(runtime);
    
    block_on(async {
        {
            // let core = unsafe { MARKET_CONFIG.as_ref().unwrap().core_id };
            // set_cpu_affinity(core);
    
            let _ = spawn(async move {
                // let mut tasks = vec![];
    
                // 18.183.90.189
                let remote_addr = "8.218.95.212:9999";
                println!("forwarding datasource trying to connect {:?}", remote_addr);
                let mut client = ProxyClientConnection::new(remote_addr.to_string(), None, None);
                
                println!("connect to {:?}", remote_addr);
                client.connect().await;
                println!("connect to {:?} SUCCESS", remote_addr);
    
                loop {
                    let mut proxy_data = ProxyMarketUpdateData {
                        depth: None,
                        trade: None,
                    };
                    read_market_data(&mut client, &mut proxy_data).await;
                    // debug
                    // println!("received proxy_data: {:?}", proxy_data);
                }
    
                // for t in tasks {
                //     t.await.unwrap().unwrap();
                // }
            })
            .await;
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    });

    tokio::fstack_stop_run();
}
