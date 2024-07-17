//! A library (and binaries) for tunneling UDP datagrams over a TCP stream.
//!
//! Some programs/protocols only work over UDP. And some networks only allow TCP. This is where
//! `udp-over-tcp` comes in handy. This library comes in two parts:
//!
//! * `udp2tcp` - Forwards incoming UDP datagrams over a TCP stream. The return stream
//!   is translated back to datagrams and sent back out over UDP again.
//!   This part can be easily used as both a library and a binary.
//!   So it can be run standalone, but can also easily be included in other
//!   Rust programs. The UDP socket is connected to the peer address of the first incoming
//!   datagram. So one [`Udp2Tcp`] instance can handle traffic from a single peer only.
//! * `tcp2udp` - Accepts connections over TCP and translates + forwards the incoming stream
//!   as UDP datagrams to the destination specified during setup / on the command line.
//!   Designed mostly to be a standalone executable to run on servers. But can be
//!   consumed as a Rust library as well.
//!   `tcp2udp` continues to accept new incoming TCP connections, and creates a new UDP socket
//!   for each. So a single `tcp2udp` server can be used to service many `udp2tcp` clients.
//!
//! # Protocol
//!
//! The format of the data inside the TCP stream is very simple. Each datagram is preceded
//! with a 16 bit unsigned integer in big endian byte order, specifying the length of the datagram.
//!
//! # tcp2udp server example
//!
//! Make the server listen for TCP connections that it can then forward to a local UDP service.
//! This will listen on `10.0.0.1:5001/TCP` and forward anything that
//! comes in to `127.0.0.1:51820/UDP`:
//! ```bash
//! user@server $ RUST_LOG=debug tcp2udp \
//!     --tcp-listen 10.0.0.0:5001 \
//!     --udp-forward 127.0.0.1:51820
//! ```
//!
//! `RUST_LOG` can be used to set logging level. See documentation for [`env_logger`] for
//! information. The crate must be built with the `env_logger` feature for this to be active.
//!
//! `REDACT_LOGS=1` can be set to redact the IPs of the peers using the service from the logs.
//! Allows having logging turned on but without storing potentially user sensitive data to disk.
//!
//! [`env_logger`]: https://crates.io/crates/env_logger
//!
//! # udp2tcp example
//!
//! This is one way you could integrate `udp2tcp` into your Rust program.
//! This will connect a TCP socket to `1.2.3.4:9000` and bind a UDP socket to a random port
//! on the loopback interface.
//! It will then connect the UDP socket to the socket addr of the first incoming datagram
//! and start forwarding all traffic to (and from) the TCP socket.
//!
//! ```no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # fn spin_up_some_udp_thing<T>(t: T) {}
//!
//! let udp_listen_addr = "127.0.0.1:0".parse().unwrap();
//! let tcp_forward_addr = "1.2.3.4:9000".parse().unwrap();
//!
//! // Create a UDP -> TCP forwarder. This will connect the TCP socket
//! // to `tcp_forward_addr`
//! let udp2tcp = udp_over_tcp::Udp2Tcp::new(
//!     udp_listen_addr,
//!     tcp_forward_addr,
//!     udp_over_tcp::TcpOptions::default(),
//! )
//! .await?;
//!
//! // Read out which address the UDP actually bound to. Useful if you specified port
//! // zero to get a random port from the OS.
//! let local_udp_addr = udp2tcp.local_udp_addr()?;
//!
//! spin_up_some_udp_thing(local_udp_addr);
//!
//! // Run the forwarder until the TCP socket disconnects or an error happens.
//! udp2tcp.run().await?;
//! # Ok(())
//! # }
//! ```
//!

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod tcp2udp;
pub mod udp2tcp;

pub use udp2tcp::{Udp2Tcp, Error};

mod exponential_backoff;
mod forward_traffic;
mod logging;
mod tcp_options;

pub use tcp_options::{ApplyTcpOptionsError, ApplyTcpOptionsErrorKind, TcpOptions};

use rustler::{Env, Term, NifMap, NifTuple, NifUnitEnum, NifTaggedEnum, NifUntaggedEnum, ResourceArc};
use tokio_util::sync::CancellationToken;
use std::sync::Mutex;

/// Helper trait for `Result<Infallible, E>` types. Allows getting the `E` value
/// in a way that is guaranteed to not panic.
pub trait NeverOkResult<E> {
    fn into_error(self) -> E;
}

impl<E> NeverOkResult<E> for Result<std::convert::Infallible, E> {
    fn into_error(self) -> E {
        self.expect_err("Result<Infallible, _> can't be Ok variant")
    }
}

#[derive(NifMap)]
struct MyMap {
    lhs: i32,
    rhs: i32,
}

#[derive(NifTuple)]
struct MyTuple {
    lhs: i32,
    rhs: i32,
}

#[derive(NifUnitEnum)]
enum UnitEnum {
    FooBar,
    Baz,
}

#[derive(NifTaggedEnum)]
enum TaggedEnum {
    Foo,
    Bar(String),
    Baz{ a: i32, b: i32 },
}

#[derive(NifUntaggedEnum)]
enum UntaggedEnum {
    Foo(u32),
    Bar(String),
}

#[rustler::nif(name = "add")]
fn add_nif(a: i64, b: i64) -> i64 {
    add(a, b)
}

fn add(a: i64, b: i64) -> i64 {
    a + b
}

#[rustler::nif(name = "my_map")]
fn my_map_nif() -> MyMap {
    my_map()
}

#[rustler::nif]
fn my_maps() -> Vec<MyMap> {
    vec![ my_map(), my_map()]
}

fn my_map() -> MyMap {
    MyMap { lhs: 33, rhs: 21 }
}

#[rustler::nif]
fn my_tuple() -> MyTuple {
    MyTuple { lhs: 33, rhs: 21 }
}

#[rustler::nif]
fn unit_enum_echo(unit_enum: UnitEnum) -> UnitEnum {
    unit_enum
}

#[rustler::nif]
fn tagged_enum_echo(tagged_enum: TaggedEnum) -> TaggedEnum {
    tagged_enum
}

#[rustler::nif]
fn untagged_enum_echo(untagged_enum: UntaggedEnum) -> UntaggedEnum {
    untagged_enum
}

fn load(env: Env, _: Term) -> bool {
    rustler::resource!(TokenResource, env);
    true
}

rustler::init!("udp_over_tcp",
               [ add_nif
                 , my_map_nif
                 , my_maps
                 , my_tuple
                 , unit_enum_echo
                 , tagged_enum_echo
                 , untagged_enum_echo
                 , udp2tcp_nif
                 , stop_nif
               ],
               load = load
);

#[cfg(test)]
mod tests {
    use crate::add;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

//#[tokio::main]
async fn tunnel(_target: i32, token: CancellationToken) {
//Result<(), udp2tcp::Error> {
    //let udp2tcp = udp_over_tcp::Udp2Tcp::new(
    println!("Spawnar");
    let cloned_token = token.clone();

    tokio::spawn(async move {
        _ = tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        println!("Sovit klart!");
        token.cancel();
    });
    println!("awaitar");
    let udp_listen_addr = "127.0.0.1:9999".parse().unwrap();
    let tcp_forward_addr = "127.0.0.1:10000".parse().unwrap();
    let udp2tcp = Udp2Tcp::new(
        udp_listen_addr,
        tcp_forward_addr,
        TcpOptions::default(),
        cloned_token
    ).await.unwrap();
    println!("Nu auker vi!");
    udp2tcp.run().await;
}

struct TokenResource {
    pub token: CancellationToken
}

#[rustler::nif(name = "udp2tcp", schedule = "DirtyIo")]
fn udp2tcp_nif(target: i32) -> Result<ResourceArc<TokenResource>, rustler::Error> {
    //let handle = tokio::runtime::Handle::current();
    //handle.enter();
    let token = CancellationToken::new();
    let cloned_token = token.clone();
    let _thread = std::thread::spawn(move || {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(tunnel(target, token));
    });
    //handle.block_on(tunnel(target));
    let arc = ResourceArc::new(TokenResource { token: cloned_token });
    Ok(arc)
}

#[rustler::nif(name = "stop")]
fn stop_nif(at: ResourceArc<TokenResource>) {
    at.token.cancel();
}
