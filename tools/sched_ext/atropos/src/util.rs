// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

// Shim between facebook types and open source types.
//
// The type interfaces and module hierarchy should be identical on
// both "branches". And since we glob import, all the submodules in
// this crate will inherit our name bindings and can use generic paths,
// eg `crate::logging::setup(..)`.
#[macro_export]
macro_rules! oss_shim {
    () => {
        #[cfg(fbcode_build)]
        mod facebook;
        #[cfg(fbcode_build)]
        use facebook::*;
        #[cfg(not(fbcode_build))]
        mod oss;
        #[cfg(not(fbcode_build))]
        use oss::*;
    };
}
