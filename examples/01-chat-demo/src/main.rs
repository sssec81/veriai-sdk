use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let app = chat_demo::app();
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("VeriAI OpenAI Chat Completions Server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
