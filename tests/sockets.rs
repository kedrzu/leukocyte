//! Socket facts, in their own test binary: the counts include every TCP socket of the test
//! process, so no other test may open one concurrently.

use std::net::{TcpListener, TcpStream};

use leukocyte::platform;

#[test]
fn listening_ports_and_inbound_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (_server, _) = listener.accept().unwrap();

    let pid = i32::try_from(std::process::id()).unwrap();
    let key = platform::base_info(pid).unwrap().key;
    let sockets = platform::sockets(key).unwrap();

    assert!(sockets.listening.contains(&port), "{sockets:?}");
    assert_eq!(sockets.inbound, 1, "{sockets:?}");
    assert_eq!(sockets.established, 2, "{sockets:?}");
}
