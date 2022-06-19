mod client;
mod ipc;
mod packets;

use client::Client;
use std::error::Error;
use tokio::net::{TcpListener, TcpStream};

fn handle_stream(stream: TcpStream) {
    tokio::spawn(async move {
        let mut client = Client {
            stream,
            encryption_key: None,
        };

        client.handle().await;
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    color_eyre::install()?;

    let listener = TcpListener::bind("0.0.0.0:42069").await?;
    loop {
        let (socket, _) = listener.accept().await?;
        handle_stream(socket);
    }
}
