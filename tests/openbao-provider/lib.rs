// Compile and exercise the production source directly without the unrelated
// DataFusion/browser/enterprise dependency graph or a copied implementation.
include!("../../src/config/src/openbao.rs");

#[cfg(test)]
#[path = "../../src/config/src/openbao_tests.rs"]
mod tests;
