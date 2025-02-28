//! # Actix Allow Middleware
//!
//! This middleware allows requests from specific IP addresses or ranges.

use std::{
    future::{Ready, ready},
    pin::Pin,
    str::FromStr,
};

use actix_service::{Service, Transform, forward_ready};
use actix_web::{
    Error,
    dev::{ServiceRequest, ServiceResponse},
};
use ipnet::IpNet;

/// This struct represents a list of allowed IP addresses or ranges. Both IPv4 and IPv6 are supported.
#[derive(Debug, Clone)]
pub struct AllowList {
    allow_list: Vec<IpNet>,
}

impl AllowList {
    pub fn allows(&self, ip: &str) -> bool {
        IpNet::from_str(ip)
            .map(|ip| self.allow_list.iter().any(|allowed| allowed.contains(&ip)))
            .unwrap_or(false)
    }
}

pub struct AllowListMiddleware<S> {
    service: S,
    allow_list: AllowList,
}

impl<S, B> Transform<S, ServiceRequest> for AllowList
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = AllowListMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AllowListMiddleware {
            service,
            allow_list: self.clone(),
        }))
    }
}

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + 'static>>;

impl<S, B> Service<ServiceRequest> for AllowListMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if let Some(actual_ip) = req.connection_info().realip_remote_addr() {
            if !self.allow_list.allows(actual_ip) {
                return Box::pin(async move {
                    Err(actix_web::error::ErrorForbidden(
                        "Could not find IP of client in allow list",
                    ))
                });
            }
        }
        let fut = self.service.call(req);
        Box::pin(fut)
    }
}
