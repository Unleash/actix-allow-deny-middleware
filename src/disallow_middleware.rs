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
pub struct DisAllowList {
    deny_list: Vec<IpNet>,
}

impl DisAllowList {
    pub fn denies(&self, ip: &str) -> bool {
        IpNet::from_str(ip)
            .map(|ip| self.deny_list.iter().any(|allowed| allowed.contains(&ip)))
            .unwrap_or(false)
    }
    /// Adds an IP address or range to the disallow list. Invalid IP addresses or ranges are ignored.
    pub fn add_ip_range(&mut self, ip: &str) {
        if let Ok(ipnet) = IpNet::from_str(ip) {
            self.deny_list.push(ipnet);
        }
    }

    /// Adds a list of IP addresses or ranges to the disallow list. Invalid IP addresses or ranges are ignored.
    pub fn add_ip_ranges(&mut self, ips: Vec<&str>) {
        for ip in ips {
            if let Ok(ip_net) = IpNet::from_str(ip) {
                self.deny_list.push(ip_net);
            }
        }
    }

    /// Builds a disallow list from a single IP address or range. Invalid IP addresses or ranges are ignored.
    pub fn with_denied_ip(ip: &str) -> Self {
        let mut deny_list = vec![];
        if let Ok(ip_net) = IpNet::from_str(ip) {
            deny_list.push(ip_net);
        }
        Self { deny_list }
    }

    /// Builds a disallow list from a list of IP addresses or ranges. Invalid IP addresses or ranges are ignored.
    pub fn with_denied_ips(ips: Vec<&str>) -> Self {
        let deny_list = ips
            .iter()
            .filter_map(|ip| IpNet::from_str(ip).ok())
            .collect();
        Self { deny_list }
    }
}

pub struct DisAllowListMiddleware<S> {
    service: S,
    dis_allow_list: DisAllowList,
}

impl<S, B> Transform<S, ServiceRequest> for DisAllowList
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = DisAllowListMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DisAllowListMiddleware {
            service,
            dis_allow_list: self.clone(),
        }))
    }
}

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + 'static>>;

impl<S, B> Service<ServiceRequest> for DisAllowListMiddleware<S>
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
            if self.dis_allow_list.denies(actual_ip) {
                return Box::pin(async move {
                    Err(actix_web::error::ErrorForbidden(
                        "IP address was found in the disallow list",
                    ))
                });
            }
        } else if let Some(peer_ip) = req.peer_addr() {
            if self.dis_allow_list.denies(&peer_ip.ip().to_string()) {
                return Box::pin(async move {
                    Err(actix_web::error::ErrorForbidden(
                        "IP address was found in the disallow list",
                    ))
                });
            }
        }
        let fut = self.service.call(req);
        Box::pin(fut)
    }
}
