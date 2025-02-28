//! # Actix Allow Middleware
//!
//! This middleware allows requests from specific IP addresses or ranges.

use std::net::IpAddr;

use actix_service::{Service, Transform};
use actix_web::{
    body::{BoxBody, EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
};
use futures::future::{Ready, ok};
/// This struct represents a list of allowed IP addresses or ranges. Both IPv4 and IPv6 are supported.
#[derive(Debug, Clone)]
pub struct AllowList {
    allow_list: Vec<IpAddr>,
}

pub struct AllowListMiddleware<S> {
    service: S,
    allow_list: AllowList,
}

impl<S, B> Transform<S, ServiceRequest> for AllowList
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<BoxBody>>;
    type Error = actix_web::Error;
    type Transform = AllowListMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AllowListMiddleware {
            service,
            allow_list: self.clone(),
        })
    }
}
