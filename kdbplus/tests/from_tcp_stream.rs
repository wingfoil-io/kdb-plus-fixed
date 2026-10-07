//! `QStream::from_tcp_stream`, and `QStream::connect` over TCP, which goes through it, against a
//! listener that plays the q side of the handshake, so the tests need no q process.

#![cfg(feature = "ipc")]

use kdb_plus_fixed::ipc::*;
use kdb_plus_fixed::qattribute;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the handshake sends ahead of the null terminator: the credential and capability 3.
const HANDSHAKE: &[u8] = b"ideal:person\x03";

/// A listener on a free loopback port that accepts one connection, reads the handshake up to
/// its null terminator and hands back the bytes it read. It answers with capability 3 when
/// `accept` holds, and closes the connection otherwise, as q does on a bad credential.
async fn fake_q(accept: bool) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            socket.read_exact(&mut byte).await.unwrap();
            if byte[0] == 0 {
                break;
            }
            received.push(byte[0]);
        }
        if accept {
            socket.write_all(&[3]).await.unwrap();
        }
        received
    });
    (port, server)
}

#[tokio::test]
async fn a_caller_connected_stream_is_handshaken() {
    let (port, server) = fake_q(true).await;
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.set_nodelay(true).unwrap();

    let socket = QStream::from_tcp_stream(stream, "ideal:person").await;

    assert!(socket.is_ok(), "{:?}", socket.err());
    assert_eq!(server.await.unwrap(), HANDSHAKE);
    assert_eq!(socket.unwrap().get_connection_type(), "TCP");
}

#[tokio::test]
async fn a_refused_credential_is_an_authentication_failure() {
    let (port, server) = fake_q(false).await;
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let socket = QStream::from_tcp_stream(stream, "ideal:person").await;

    assert_eq!(server.await.unwrap(), HANDSHAKE);
    let error = socket.err().expect("the handshake fails");
    assert!(
        error.to_string().contains("authentication failure"),
        "{error}"
    );
}

#[tokio::test]
async fn connect_over_tcp_sends_the_same_handshake() {
    let (port, server) = fake_q(true).await;

    let socket = QStream::connect(ConnectionMethod::TCP, "127.0.0.1", port, "ideal:person").await;

    assert!(socket.is_ok(), "{:?}", socket.err());
    assert_eq!(server.await.unwrap(), HANDSHAKE);
}

#[tokio::test]
async fn an_ipv4_mapped_loopback_peer_is_local() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Reads the handshake, accepts it, and hands back the compression byte of the next header.
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut byte = [0u8; 1];
        while {
            socket.read_exact(&mut byte).await.unwrap();
            byte[0] != 0
        } {}
        socket.write_all(&[3]).await.unwrap();
        let mut header = [0u8; 8];
        socket.read_exact(&mut header).await.unwrap();
        header[2]
    });
    let stream = TcpStream::connect(("::ffff:127.0.0.1", port))
        .await
        .unwrap();
    assert!(stream.peer_addr().unwrap().is_ipv6());
    let mut socket = QStream::from_tcp_stream(stream, "ideal:person")
        .await
        .unwrap();

    // Zeros well past the 1992-byte threshold, so a remote peer would get them compressed.
    let large = K::new_long_list(vec![0; 1000], qattribute::NONE);
    socket.send_async_message(&large).await.unwrap();

    assert_eq!(
        server.await.unwrap(),
        0,
        "a local peer gets the message uncompressed"
    );
}
