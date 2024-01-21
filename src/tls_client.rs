use std::{net::TcpStream, sync::Arc};

use rustls::pki_types::ServerName;

pub struct TlsClient {
    pub socket: TcpStream,
    pub tls_conn: rustls::ClientConnection,
}

impl TlsClient {
    pub fn new(
        sock: TcpStream,
        server_name: ServerName<'static>,
        cfg: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            socket: sock,
            tls_conn: rustls::ClientConnection::new(cfg, server_name).unwrap(),
        }
    }

    pub fn stream<'a>(&'a mut self) -> rustls::Stream<'a, rustls::ClientConnection, TcpStream> {
        rustls::Stream::new(&mut self.tls_conn, &mut self.socket)
    }
}