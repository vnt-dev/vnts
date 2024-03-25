use std::collections::{HashMap, HashSet};
use std::net;
use std::sync::Arc;

use actix_files::Files;
use actix_web::dev::Service;
use actix_web::web::Data;
use actix_web::{post, web, App, HttpRequest, HttpResponse, HttpServer};

use crate::cipher::RsaCipher;
use crate::core::server::web::service::VntsWebService;
use crate::core::server::web::vo::{LoginData, ResponseMessage};
use crate::core::store::cache::AppCache;
use crate::ConfigInfo;

mod service;
mod vo;

#[post("/login")]
async fn login(service: Data<VntsWebService>, data: web::Json<LoginData>) -> HttpResponse {
    match service.login(data.0).await {
        Ok(auth) => HttpResponse::Ok().json(ResponseMessage::success(auth)),
        Err(e) => HttpResponse::Ok().json(ResponseMessage::fail(e)),
    }
}

#[post("/group_list")]
async fn group_list(_req: HttpRequest, service: Data<VntsWebService>) -> HttpResponse {
    let info = service.group_list();
    HttpResponse::Ok().json(ResponseMessage::success(info))
}

#[post("/group_info")]
async fn group_info(
    _req: HttpRequest,
    service: Data<VntsWebService>,
    group: web::Json<HashMap<String, String>>,
) -> HttpResponse {
    if let Some(group) = group.get("group") {
        let info = service.group_info(group.to_string());
        HttpResponse::Ok().json(ResponseMessage::success(info))
    } else {
        HttpResponse::Ok().json(ResponseMessage::fail("no group found".into()))
    }
}

#[derive(Clone)]
struct AuthApi {
    api_set: Arc<HashSet<String>>,
}

fn auth_api_set() -> AuthApi {
    let mut api_set = HashSet::new();
    api_set.insert("/group_info".to_string());
    api_set.insert("/group_list".to_string());
    AuthApi {
        api_set: Arc::new(api_set),
    }
}

pub async fn start(
    lst: net::TcpListener,
    cache: AppCache,
    config: ConfigInfo,
    rsa_cipher: Option<RsaCipher>,
) -> std::io::Result<()> {
    let web_service = VntsWebService::new(cache, config, rsa_cipher);
    let auth_api = auth_api_set();
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(web_service.clone()))
            .app_data(Data::new(auth_api.clone()))
            .wrap_fn(|request, srv| {
                let auth_api: &Data<AuthApi> = request.app_data().unwrap();
                let path = request.path();
                if path == "/login" || !auth_api.api_set.contains(path) {
                    return srv.call(request);
                }
                let service: &Data<VntsWebService> = request.app_data().unwrap();
                if let Some(authorization) = request.headers().get("Authorization") {
                    if let Ok(auth) = authorization.to_str() {
                        if auth.starts_with("Bearer ") {
                            let auth = &auth["Bearer ".len()..];
                            if service.check_auth(&auth.to_string()) {
                                return srv.call(request);
                            }
                        }
                    }
                }
                Box::pin(async move {
                    Ok(request
                        .into_response(HttpResponse::Ok().json(ResponseMessage::unauthorized())))
                })
            })
            .service(login)
            .service(group_list)
            .service(group_info)
            .service(Files::new("/", "./static/").index_file("index.html"))
    })
    .listen(lst)?
    .run()
    .await
}
