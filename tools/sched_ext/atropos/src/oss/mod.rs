// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#[path = "../bpf/.output/atropos.skel.rs"]
mod atropos;
use std::str::FromStr;

use anyhow::bail;
pub use atropos::*;
use slog::o;
use slog::Drain;
use slog::Level;

pub mod atropos_sys;

pub fn setup_logger(level: &str) -> anyhow::Result<slog::Logger> {
    let log_level = match Level::from_str(level) {
        Ok(l) => l,
        Err(()) => bail!("Failed to parse \"{}\" as a log level", level),
    };
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain)
        .build()
        .filter_level(log_level)
        .fuse();
    Ok(slog::Logger::root(drain, o!()))
}
