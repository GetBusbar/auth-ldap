// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **AD/LDAP auth module as a droppable busbar plugin**: the logic crate re-exported whole, and
//! its door (`busbar_auth_ldap::door::door`, a `plugin_door!` over the auth kind's table) exported
//! as this image's ONE symbol, `busbar_plugin_door` (`export_door!`), unconditionally. A build that
//! links the module names `busbar_auth_ldap::door::door` from the logic crate, which exports
//! nothing.
//!
//! This crate is `deny`, not `forbid`: the export macro's `#[unsafe(no_mangle)]` is the one
//! reviewed exemption (a `forbid` cannot be lifted for it). No other `unsafe` exists here.
#![deny(unsafe_code)]

pub use busbar_auth_ldap::*;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_auth_ldap::door::door);
}
