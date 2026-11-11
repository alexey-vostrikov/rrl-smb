//! DCE/RPC over the named pipes of IPC$ (C706 chapter 12, MS-RPCE 2.1.1.2).

use std::sync::atomic::{AtomicU32, Ordering};

pub(crate) mod association;
pub(crate) mod ndr;
pub(crate) mod pdu;
pub(crate) mod pipe;
pub(crate) mod srvsvc;

/// The pipe IPC$ serves for share enumeration, as a CREATE names it.
pub(crate) const SRVSVC_PIPE: &str = "srvsvc";

/// The pipe a domain member's join opens first: LSA, where it asks what domain it reached.
pub(crate) const LSARPC_PIPE: &str = "lsarpc";

/// The pipe it opens second, to create its machine account: SAM.
pub(crate) const SAMR_PIPE: &str = "samr";

/// The pipe a member opens once its account exists, to prove it holds the machine password and then
/// read the domain's description of itself: netlogon.
pub(crate) const NETLOGON_PIPE: &str = "netlogon";

pub(crate) mod lsarpc;
pub(crate) mod netlogon;
pub(crate) mod samr;

/// Source of association group ids for binds that ask for a new group.
static NEXT_ASSOC_GROUP: AtomicU32 = AtomicU32::new(1);

/// A new association group id, never 0 (C706 12.6.3.6).
pub(crate) fn new_assoc_group() -> u32 {
    loop {
        let id = NEXT_ASSOC_GROUP.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}
