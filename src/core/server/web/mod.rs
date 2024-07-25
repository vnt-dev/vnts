use std::collections::HashMap;
use std::net;

use actix_web::dev::Service;
use actix_web::web::Data;
use actix_web::{middleware, post, web, App, HttpRequest, HttpResponse, HttpServer};

use actix_web_static_files::ResourceFiles;

use crate::core::server::web::service::VntsWebService;
use crate::core::server::web::vo::req::{CreateWGData, LoginData, RemoveClientReq};

use crate::core::server::web::vo::ResponseMessage;
use crate::core::store::cache::AppCache;
use crate::ConfigInfo;

mod service;
mod vo;

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

#[post("/api/login")]
async fn login(service: Data<VntsWebService>, data: web::Json<LoginData>) -> HttpResponse {
    match service.login(data.0).await {
        Ok(auth) => HttpResponse::Ok().json(ResponseMessage::success(auth)),
        Err(e) => HttpResponse::Ok().json(ResponseMessage::fail(e)),
    }
}

#[post("/api/group_list")]
async fn group_list(_req: HttpRequest, service: Data<VntsWebService>) -> HttpResponse {
    let info = service.group_list();
    HttpResponse::Ok().json(ResponseMessage::success(info))
}
#[post("/api/remove_client")]
async fn remove_client(
    _req: HttpRequest,
    service: Data<VntsWebService>,
    data: web::Json<RemoveClientReq>,
) -> HttpResponse {
    service.remove_client(data.0);
    HttpResponse::Ok().json(ResponseMessage::success("success"))
}
#[post("/api/private_key")]
async fn private_key(_req: HttpRequest, service: Data<VntsWebService>) -> HttpResponse {
    let private_key = service.gen_wg_private_key();
    HttpResponse::Ok().json(ResponseMessage::success(private_key))
}
#[post("/api/create_wg_config")]
async fn create_wg_config(
    _req: HttpRequest,
    service: Data<VntsWebService>,
    data: web::Json<CreateWGData>,
) -> HttpResponse {
    match service.create_wg_config(data.0).await {
        Ok(wg_config) => HttpResponse::Ok().json(ResponseMessage::success(wg_config)),
        Err(e) => HttpResponse::Ok().json(ResponseMessage::fail(e.to_string())),
    }
}
#[post("/api/group_info")]
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

pub async fn start(
    lst: net::TcpListener,
    cache: AppCache,
    config: ConfigInfo,
) -> std::io::Result<()> {
    let web_service = VntsWebService::new(cache, config);
    HttpServer::new(move || {
        let generated = generate();
        App::new()
            .app_data(Data::new(web_service.clone()))
            .wrap_fn(|request, srv| {
                let path = request.path();
                if path == "/api/login" || !path.contains("/api/") {
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
            .wrap(middleware::Compress::default())
            .service(login)
            .service(remove_client)
            .service(private_key)
            .service(create_wg_config)
            .service(group_list)
            .service(group_info)
            .service(ResourceFiles::new("/", generated))
    })
    .listen(lst)?
    .run()
    .await
}
