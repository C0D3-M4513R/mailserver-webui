use askama::Template;
use pkcs1::der::Encode;
use crate::rocket::auth::session::Permission;

#[derive(Template)]
#[template(path = "authenticated/domain/index.html")]
pub struct DomainIndex<'a> {
    pub domain: &'a str,
    pub permissions: &'a Permission,
    pub rename: Option<DomainName>,
    pub accounts: Vec<DomainAccount>,
    pub dkim: Option<Vec<Dkim>>,
}

pub struct DomainAccount{
    pub id: i64,
    pub true_owner: bool,
    pub email: String,
    pub domain: String,
}
pub struct DomainName{
    pub self_name: String,
    pub super_name: String,
}

pub struct Dkim{
    pub selector: String,
    pub domain: String,
    pub key: Result<DkimKey, String>,
    pub active: bool,
}
impl Dkim {
    pub fn to_dns_name(&self) -> String {
        format!(r#"{}._domainkey.{}. "#, self.selector, self.domain)
    }
    fn to_dns_value(&self) -> Result<String, String> {
        match &self.key { 
            Ok(v) => Ok(v.to_dns_value()),
            Err(v) => Err(v.clone()),
        }
    }
}
pub enum DkimKey {
    RSA(Vec<u8>)
}
impl DkimKey {
    pub fn from_data(private_key_data: &[u8]) -> Result<Self, String> {
        use pkcs8::der::Decode;
        let der = pkcs8::PrivateKeyInfo::from_der(private_key_data).map_err(|e|e.to_string())?;
        match der.algorithm.oid {
            pkcs1::ALGORITHM_OID => Ok(Self::RSA(
                pkcs1::RsaPrivateKey::from_der(der.private_key).map_err(|v|v.to_string())?
                    .public_key().to_der().map_err(|v|v.to_string())?
            )),
            id => Err(format!("Unrecognised key type: {id}")),
        }
    }
    pub fn to_dns_value(&self) -> String {
        use base64::Engine;
        match self {
            Self::RSA(rsa) => format!(r#""v=DKIM1; k=rsa; p={}""#, base64::engine::general_purpose::STANDARD.encode(rsa.as_slice())),
        }
    }
}