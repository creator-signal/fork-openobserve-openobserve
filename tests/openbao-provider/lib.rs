// Compile and exercise the production source directly without the unrelated
// DataFusion/browser/enterprise dependency graph or a copied implementation.
include!("../../src/config/src/openbao.rs");

// Compile the actual S3 response observer with the same provider interface.
extern crate self as config;
pub mod openbao {
    pub use super::trigger_auth_refresh;
}
#[cfg(test)]
#[path = "../../src/infra/src/storage/openbao_transport.rs"]
mod storage_transport;

#[cfg(test)]
#[path = "../../src/config/src/openbao_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../vendor/chromiumoxide-fetcher/src/browser/zip.rs"]
mod archive;
