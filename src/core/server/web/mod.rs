use std::net;
use std::sync::Arc;

use crate::cipher::RsaCipher;
use crate::core::server::web::service::VntsWebService;
use crate::core::store::cache::AppCache;
use crate::ConfigInfo;
use actix_files::Files;
use actix_web::web::Data;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};

mod service;
mod vo;

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {name}!")
}

#[get("/token")]
async fn token(service: Data<VntsWebService>) -> HttpResponse {
    let info = service.groups_info();
    HttpResponse::Ok().json(info)
}

pub async fn start(
    lst: net::TcpListener,
    cache: AppCache,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
) -> std::io::Result<()> {
    let web_service = VntsWebService::new(cache, config, rsa_cipher);
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(web_service.clone()))
            .service(greet)
            .service(token)
            .service(Files::new("/", "./static/").index_file("index.html"))
    })
    .listen(lst)?
    .run()
    .await
}
