//! Embedded NFS for authenticated ESP streams. The transport must authorize a
//! peer before constructing a session; RPC AUTH_SYS is not authentication.
mod filesystem;
mod protocol;
mod store;
pub(crate) mod xdr;
pub(crate) use protocol::Server;
