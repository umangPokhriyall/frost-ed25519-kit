pub mod routes;
use store::store::Store;
use poem::EndpointExt;

use poem::{IntoResponse, Route, Server, get , post , handler, listener::TcpListener, web::Path};
use crate::routes::routes::{create_wallet, sign_tx, send_tx};
use std::sync::{Arc, Mutex};

#[handler]
fn hello(Path(name): Path<String>) -> String {
    format!("hello: {}", name)
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let store = Arc::new(Mutex::new(Store::new().expect("DB connection failed")));
    let app = Route::new()
    .at("/hello/:name", get(hello))
    .at("/wallets", post(create_wallet))
    .at("/wallets/:id/send", post(send_tx))
    .at("/wallets/:id/sign", post(sign_tx))
    .data(store);


    println!("🚀 Orchestrator running on 127.0.0.1:3000");

    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .run(app)
        .await
}