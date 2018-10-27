/* 
 * IoT Edge Module Workload API
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * OpenAPI spec version: 2018-06-28
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */


#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityCertificateRequest {
  /// Subject common name
  #[serde(rename = "commonName", skip_serializing_if="Option::is_none")]
  common_name: Option<String>,
  /// Certificate expiration date-time (ISO 8601)
  #[serde(rename = "expiration", skip_serializing_if="Option::is_none")]
  expiration: Option<String>
}

impl IdentityCertificateRequest {
  pub fn new() -> IdentityCertificateRequest {
    IdentityCertificateRequest {
      common_name: None,
      expiration: None
    }
  }

  pub fn set_common_name(&mut self, common_name: String) {
    self.common_name = Some(common_name);
  }

  pub fn with_common_name(mut self, common_name: String) -> IdentityCertificateRequest {
    self.common_name = Some(common_name);
    self
  }

  pub fn common_name(&self) -> Option<&String> {
    self.common_name.as_ref()
  }

  pub fn reset_common_name(&mut self) {
    self.common_name = None;
  }

  pub fn set_expiration(&mut self, expiration: String) {
    self.expiration = Some(expiration);
  }

  pub fn with_expiration(mut self, expiration: String) -> IdentityCertificateRequest {
    self.expiration = Some(expiration);
    self
  }

  pub fn expiration(&self) -> Option<&String> {
    self.expiration.as_ref()
  }

  pub fn reset_expiration(&mut self) {
    self.expiration = None;
  }

}


