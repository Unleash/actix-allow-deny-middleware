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
/// Actix loads middlewares in bottom up fashion, and if the request's IP address is in the deny list, it will be denied, and there is no point in continuing to process the request.

/// # Examples
/// ```no_run
/// use actix_web::{web, App, HttpServer, HttpResponse, Error};
/// use actix_allow_deny_middleware::DenyList;
///
///
/// #[actix_web::main]
/// async fn main() -> std::io::Result<()> {
///     HttpServer::new(move || {
///         App::new()
///             // adds deny listing, Blocking all of 66.249.0.0 to 66.249.255.255
///             .wrap(DenyList::with_denied_range("66.249.0.0/16"))
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
/// use actix_allow_deny_middleware::DenyList;
///
///
/// #[actix_web::main]
/// async fn main() -> std::io::Result<()> {
///     HttpServer::new(move || {
///         App::new()
///             // adds deny listing, denying typical local network addresses. Not sure why you would do this. but at least it's an example.
///             .wrap(DenyList::with_denied_ranges(vec!["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]))
///             .service(web::resource("/").to(|| async { HttpResponse::Ok().body("Hello, world!") }))
///     })
///     .bind(("127.0.0.1", 8080))?
///     .run()
///     .await
/// }
/// ```
///
/// This struct represents a list of allowed IP addresses or ranges. Both IPv4 and IPv6 are supported.
#[derive(Debug, Clone)]
pub struct DenyList {
    deny_list: Vec<IpNet>,
}

impl DenyList {
    /// Takes an IP and checks if it is in any of the denied ranges
    pub fn denies(&self, ip: &str) -> bool {
        ip.parse::<IpAddr>()
            .map(|ip| self.deny_list.iter().any(|denied| denied.contains(&ip)))
            .unwrap_or(true)
    }
    /// Adds an IP address or range to the disallow list. Invalid IP addresses or ranges are ignored. If you want to add a single ip address, use `A.B.C.D/32`
    pub fn add_ip_range(&mut self, range: &str) {
        if let Ok(ipnet) = IpNet::from_str(range) {
            self.deny_list.push(ipnet);
        }
    }

    /// Adds a list of IP addresses or ranges to the disallow list. Invalid IP ranges are ignored.
    pub fn add_ip_ranges(&mut self, ranges: Vec<&str>) {
        for ip in ranges {
            if let Ok(ip_net) = IpNet::from_str(ip) {
                self.deny_list.push(ip_net);
            }
        }
    }

    /// Builds a disallow list from a single IP range. Invalid IP ranges are ignored.
    pub fn with_denied_range(ranges: &str) -> Self {
        let mut deny_list = vec![];
        if let Ok(ip_net) = IpNet::from_str(ranges) {
            deny_list.push(ip_net);
        }
        Self { deny_list }
    }

    /// Builds a disallow list from a list of IP ranges. Invalid IP ranges are ignored.
    pub fn with_denied_ranges(ranges: Vec<&str>) -> Self {
        let deny_list = ranges
            .iter()
            .filter_map(|ip| IpNet::from_str(ip).ok())
            .collect();
        Self { deny_list }
    }

    /// Builds a deny list from a single IpNet
    pub fn with_denied_ipnet(net: IpNet) -> Self {
        Self {
            deny_list: vec![net],
        }
    }

    /// Builds a deny list from a vec of IpNets
    pub fn with_denied_ipnets(nets: &[IpNet]) -> Self {
        Self {
            deny_list: nets.to_vec(),
        }
    }
}

pub struct DenyListMiddleware<S> {
    service: S,
    deny_list: DenyList,
}

impl<S, B> Transform<S, ServiceRequest> for DenyList
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = DenyListMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DenyListMiddleware {
            service,
            deny_list: self.clone(),
        }))
    }
}

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + 'static>>;

impl<S, B> Service<ServiceRequest> for DenyListMiddleware<S>
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
            if self.deny_list.denies(actual_ip) {
                trace!("Ip [{actual_ip}] was found in deny list. Blocking");
                return Box::pin(async move {
                    Err(actix_web::error::ErrorForbidden(
                        "IP address was found in the disallow list",
                    ))
                });
            }
        } else if let Some(peer_ip) = req.peer_addr() {
            if self.deny_list.denies(&peer_ip.ip().to_string()) {
                trace!("Ip [{}] was found in deny list. Blocking", peer_ip.ip());
                return Box::pin(async move {
                    Err(actix_web::error::ErrorForbidden(
                        "IP address was found in the disallow list",
                    ))
                });
            }
        }
        Box::pin(self.service.call(req))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use actix_service::Service;
    use actix_web::{
        App, HttpResponse, Responder,
        test::{TestRequest, init_service},
        web,
    };

    use crate::deny_middleware::DenyList;

    async fn index() -> impl Responder {
        HttpResponse::Ok().body("abcd")
    }

    #[actix_web::test]
    async fn denies_localhost() {
        let localhost = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let localhost6 =
            std::net::SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 80);
        let lan_ip = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 80);
        let deny_list = DenyList::with_denied_ranges(vec!["127.0.0.1/32", "::1/128"]);
        let app = init_service(App::new().wrap(deny_list).route("/", web::get().to(index))).await;
        let req = TestRequest::default()
            .uri("/")
            .peer_addr(localhost)
            .to_request();
        let resp = app.call(req).await;
        assert!(resp.is_err());
        let ipv6_req = TestRequest::default()
            .uri("/")
            .peer_addr(localhost6)
            .to_request();
        let resp = app.call(ipv6_req).await;
        assert!(resp.is_err());
        let lan_req = TestRequest::default()
            .uri("/")
            .peer_addr(lan_ip)
            .to_request();
        let resp = app.call(lan_req).await;
        assert!(resp.is_ok());
    }

    #[actix_web::test]
    async fn if_no_ip_can_be_found_from_the_request_there_is_nothing_to_deny() {
        let deny_list = DenyList::with_denied_ranges(vec!["127.0.0.1/32", "::1"]);
        let app = init_service(App::new().wrap(deny_list).route("/", web::get().to(index))).await;
        let req = TestRequest::default().uri("/").to_request();
        let resp = app.call(req).await;
        assert!(resp.is_ok());
    }

    #[actix_web::test]
    async fn allows_all_ips_with_empty_list() {
        let local = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let deny_list = DenyList::with_denied_ranges(vec![]);
        let app = init_service(App::new().wrap(deny_list).route("/", web::get().to(index))).await;
        let req = TestRequest::default()
            .uri("/")
            .peer_addr(local)
            .to_request();
        let resp = app.call(req).await;
        assert!(resp.is_ok());
    }

    #[actix_web::test]
    async fn denies_ranges() {
        let ip_in_deny_range =
            std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 50, 133)), 80);
        let ip_outside_deny_range =
            std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 49, 134)), 80);
        let deny_list = DenyList::with_denied_range("192.168.50.0/24");
        let app = init_service(App::new().wrap(deny_list).route("/", web::get().to(index))).await;
        let req = TestRequest::default()
            .uri("/")
            .peer_addr(ip_in_deny_range)
            .to_request();
        let resp = app.call(req).await;
        assert!(resp.is_err());

        let req = TestRequest::default()
            .uri("/")
            .peer_addr(ip_outside_deny_range)
            .to_request();
        let resp = app.call(req).await;
        assert!(resp.is_ok());
    }
}
