use std::collections::HashMap;
use std::net;
use std::sync::Arc;

use crate::cipher::RsaCipher;
use crate::core::server::web::service::VntsWebService;
use crate::core::server::web::vo::ResponseMessage;
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

#[get("/group_list")]
async fn group_list(service: Data<VntsWebService>) -> HttpResponse {
    let info = service.group_list();
    HttpResponse::Ok().json(ResponseMessage::success(info))
}

#[get("/group_info")]
async fn group_info(
    service: Data<VntsWebService>,
    group: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    if let Some(group) = group.get("group") {
        let info = service.group_info(group.to_string());
        HttpResponse::Ok().json(ResponseMessage::success(info))
    } else {
        HttpResponse::Ok().json(ResponseMessage::fail("no group found".into()))
    }
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
            .service(group_list)
            .service(group_info)
            .service(Files::new("/", "./static/").index_file("index.html"))
    })
    .listen(lst)?
    .run()
    .await
}
