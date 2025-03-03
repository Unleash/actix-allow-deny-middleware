//! # Actix Allow Middleware
//!
//! This middleware allows requests from specific IP addresses or ranges.

use std::{
    future::{Ready, ready},
    net::IpAddr,
    pin::Pin,
    str::FromStr,
};

use actix_service::{Service, Transform, forward_ready};
use actix_web::{
    Error,
    dev::{ServiceRequest, ServiceResponse},
};
use ipnet::IpNet;
use tracing::trace;

/// This should be loaded as the first middleware, as in, last in the sequence of wrap()
/// Actix loads middlewares in bottom up fashion, and if the request's IP address is not in the allow list, it will be denied, and there is no point in continuing to process the request.

/// # Examples
/// ```no_run
/// use actix_web::{web, App, HttpServer, HttpResponse, Error};
/// use actix_allow_deny_middleware::AllowList;
///
///
/// #[actix_web::main]
/// async fn main() -> std::io::Result<()> {
///     HttpServer::new(move || {
///         App::new()
///             // adds allow listing, allowing all ip addresses and ranges for both IPv4 and IPv6.
///             .wrap(AllowList::default())
///             .service(web::resource("/").to(|| async { HttpResponse::Ok().body("Hello, world!") }))
///     })
///     .bind(("127.0.0.1", 8080))?
///     .run()
///     .await
/// }
/// ```
///
/// ```no_run
/// use actix_web::{web, App, HttpServer, HttpResponse, Error};
/// use actix_allow_deny_middleware::AllowList;
///
///
/// #[actix_web::main]
/// async fn main() -> std::io::Result<()> {
///     HttpServer::new(move || {
///         App::new()
///             // adds allow listing, allowing typical local network addresses.
///             .wrap(AllowList::with_allowed_ips(vec!["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]))
///             .service(web::resource("/").to(|| async { HttpResponse::Ok().body("Hello, world!") }))
///     })
///     .bind(("127.0.0.1", 8080))?
///     .run()
///     .await
/// }
/// ```
///
#[derive(Debug, Clone)]
pub struct AllowList {
    allow_list: Vec<IpNet>,
}

impl Default for AllowList {
    /// A default list that allows all IP addresses and ranges for both IPv4 and IPv6.
    fn default() -> Self {
        AllowList {
            allow_list: vec![
                IpNet::from_str("0.0.0.0/0").unwrap(),
                IpNet::from_str("::/0").unwrap(),
            ],
        }
    }
}

impl AllowList {
    /// Takes an ip address and returns whether or not it is in any of the allowed ranges
    pub fn allows(&self, ip: &str) -> bool {
        !self.allow_list.is_empty()
            && ip
                .parse::<IpAddr>()
                .map(|ip| self.allow_list.iter().any(|allowed| allowed.contains(&ip)))
                .unwrap_or(false)
    }

    /// Adds an IP address or range to the allow list. Invalid IP addresses or ranges are ignored.
    pub fn add_ip_range(&mut self, ip: &str) {
        if let Ok(ipnet) = IpNet::from_str(ip) {
            self.allow_list.push(ipnet);
        }
    }

    /// Adds a list of IP addresses or ranges to the allow list. Invalid IP addresses or ranges are ignored.
    pub fn add_ip_ranges(&mut self, ips: Vec<&str>) {
        for ip in ips {
            if let Ok(ip_net) = IpNet::from_str(ip) {
                self.allow_list.push(ip_net);
            }
        }
    }

    /// Constructs an allow list with a single IP range. Invalid IP addresses or ranges are ignored.
    pub fn with_allowed_range(ip: &str) -> Self {
        let mut allow_list = vec![];
        if let Ok(ip_net) = IpNet::from_str(ip) {
            allow_list.push(ip_net);
        }
        Self { allow_list }
    }

    /// Builds an allow list from a list of IP ranges. Invalid IP ranges are ignored.
    pub fn with_allowed_ips(ips: Vec<&str>) -> Self {
        let allow_list = ips
            .iter()
            .filter_map(|ip| IpNet::from_str(ip).ok())
            .collect();
        Self { allow_list }
    }

    /// Builds an allow list from one valid IpNet
    pub fn with_allowed_ipnet(net: IpNet) -> Self {
        Self {
            allow_list: vec![net],
        }
    }
    /// Builds an allow list from multiple IpNets
    pub fn with_allowed_ipnets(nets: &[IpNet]) -> Self {
        Self {
            allow_list: nets.to_vec(),
        }
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
            if !self.allow_list.allows(&actual_ip) {
                trace!("Ip: {} was not in allow list. Denying", actual_ip);
                return Box::pin(async move {
                    Err(actix_web::error::ErrorForbidden(
                        "Could not find IP of client in allow list",
                    ))
                });
            }
        } else if let Some(peer_addr) = req.peer_addr() {
            if !self.allow_list.allows(&peer_addr.ip().to_string()) {
                trace!("Ip: {} was not in allow list. Denying", peer_addr.ip());
                return Box::pin(async move {
                    Err(actix_web::error::ErrorForbidden(
                        "Could not find IP of client in allow list",
                    ))
                });
            }
        } else {
            return Box::pin(async move {
                Err(actix_web::error::ErrorForbidden(
                    "You have activated the allow list middleware, but no IP could be found in connection_info or peer_addr",
                ))
            });
        }
        let fut = self.service.call(req);
        Box::pin(fut)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use actix_service::Service;
    use actix_web::{
        App, HttpResponse, Responder,
        test::{TestRequest, init_service},
        web,
    };

    use crate::allow_middleware::AllowList;

    async fn index() -> impl Responder {
        HttpResponse::Ok().body("abcd")
    }

    #[actix_web::test]
    async fn allows_localhost() {
        let localhost = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let allow_list = AllowList::with_allowed_ips(vec!["127.0.0.1/32", "::1"]);
        let app = init_service(App::new().wrap(allow_list).route("/", web::get().to(index))).await;
        let req = TestRequest::default()
            .uri("/")
            .peer_addr(localhost)
            .to_request();
        let resp = app.call(req).await;
        assert!(resp.is_ok());
    }

    #[actix_web::test]
    async fn errors_if_no_ip_can_be_found_from_the_request() {
        let allow_list = AllowList::with_allowed_ips(vec!["127.0.0.1/32", "::1"]);
        let app = init_service(App::new().wrap(allow_list).route("/", web::get().to(index))).await;
        let req = TestRequest::default().uri("/").to_request();
        let resp = app.call(req).await;
        assert!(resp.is_err());
    }

    #[actix_web::test]
    async fn blocks_all_ips_with_empty_list() {
        let local = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let allow_list = AllowList::with_allowed_ips(vec![]);
        let app = init_service(App::new().wrap(allow_list).route("/", web::get().to(index))).await;
        let req = TestRequest::default()
            .uri("/")
            .peer_addr(local)
            .to_request();
        let resp = app.call(req).await;
        assert!(resp.is_err());
    }

    #[actix_web::test]
    async fn allows_ranges() {
        let requesting_ip =
            std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 50, 133)), 80);
        let disallowed_ip =
            std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 49, 134)), 80);
        let allow_list = AllowList::with_allowed_ips(vec!["192.168.50.0/24"]);
        let app = init_service(App::new().wrap(allow_list).route("/", web::get().to(index))).await;
        let req = TestRequest::default()
            .uri("/")
            .peer_addr(requesting_ip)
            .to_request();
        let resp = app.call(req).await;
        assert!(resp.is_ok());

        let req = TestRequest::default()
            .uri("/")
            .peer_addr(disallowed_ip)
            .to_request();
        let resp = app.call(req).await;
        assert!(resp.is_err());
    }
}
