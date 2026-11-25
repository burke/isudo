//! The pure decision logic of isudo.
//!
//! Everything here is a function of its inputs: no system calls, no clock,
//! no environment, no `unsafe`. The setuid binary supplies the facts and
//! performs the effects; this crate decides. That split is what lets the
//! same code run under the deterministic simulator and be the target of
//! property tests and proofs.

#![forbid(unsafe_code)]

pub mod args;
pub mod config;
pub mod env;
#[cfg(feature = "pairing")]
pub mod pairing;
pub mod plan;

#[cfg(test)]
mod fuzz_tests;
