use serde::{Deserialize, Serialize};

pub mod req;
pub mod res;
#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseMessage<V> {
    data: V,
    message: Option<String>,
    code: u32,
}

impl<V> ResponseMessage<V> {
    pub fn success(data: V) -> ResponseMessage<V> {
        Self {
            data,
            message: None,
            code: 200,
        }
    }
}

impl ResponseMessage<Option<()>> {}

impl ResponseMessage<Option<()>> {
    pub fn fail(message: String) -> ResponseMessage<Option<()>> {
        Self {
            data: Option::<()>::None,
            message: Some(message),
            code: 400,
        }
    }
    pub fn unauthorized() -> ResponseMessage<Option<()>> {
        Self {
            data: Option::<()>::None,
            message: Some("unauthorized".into()),
            code: 401,
        }
    }
}
