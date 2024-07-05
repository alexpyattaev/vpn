pub trait IntranetPacketInterface {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
}

pub trait ExtranetPacketInterface {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
}
use tokio::net::UdpSocket;
impl ExtranetPacketInterface for UdpSocket {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv(buf).await
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.send(buf).await
    }
}

use tokio_tun::Tun;
impl IntranetPacketInterface for Tun {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv(buf).await
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.send(buf).await
    }
}
