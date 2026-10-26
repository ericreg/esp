//! Shared endpoint construction for serving networks and temporary join clients.

use iroh::{
    Endpoint, RelayMode, SecretKey,
    endpoint::{Builder, presets},
};

/// Keep discovery, relay, and future DNS policy identical for every ESP endpoint.
/// Return the builder so callers can choose their inbound protocols, and tests can
/// replace public infrastructure with local services before binding.
pub(super) fn endpoint_builder(secret_key: SecretKey) -> Builder {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(RelayMode::Default)
}
