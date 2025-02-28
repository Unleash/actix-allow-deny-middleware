#![deny(missing_docs)]
#![deny(unsafe_code)]
//! # Actix middlewares
//!
//! This crate provides two middlewares for Actix web applications:
//! - `AllowMiddleware`: allows requests from specific IP addresses or ranges.
//! - `DisallowMiddleware`: disallows requests from specific IP addresses or ranges.
//!
mod allow_middleware;
mod disallow_middleware;
