#![cfg(feature = "sha-crypt")]
use password_hash::{Ident, ParamsString, PasswordHash, Salt};

pub const SHA256_CRYPT:password_hash::Ident<'static> = password_hash::Ident::new_unwrap("5");
pub const SHA512_CRYPT:password_hash::Ident<'static> = password_hash::Ident::new_unwrap("6");
const ROUNDS_DEFAULT:u32 = sha_crypt::ROUNDS_DEFAULT as u32;
pub struct Sha512{
    params: Sha512Params
}
impl Sha512 {
    pub const fn new(params: Sha512Params) -> Self {
        Self{
            params,
        }
    }
}
#[derive(Debug, Clone)]
pub struct Sha512Params{
    params: sha_crypt::Sha512Params,
    rounds: u32,
}
impl Default for Sha512Params{
    fn default() -> Self {
        Self{
            params: sha_crypt::Sha512Params::default(),
            rounds: ROUNDS_DEFAULT,
        }
    }
}
impl<'a> TryFrom<&'a PasswordHash<'a>> for Sha512Params {
    type Error = password_hash::Error;

    fn try_from(value: &'a PasswordHash<'a>) -> Result<Self, Self::Error> {
        let rounds = value.params.get("rounds")
            .map(|v|v.decimal())
            .transpose()?
            .unwrap_or(ROUNDS_DEFAULT);
        if sha_crypt::ROUNDS_MIN > rounds as usize {
            return Err(password_hash::Error::ParamValueInvalid(password_hash::errors::InvalidValue::TooShort));
        }
        if rounds as usize > sha_crypt::ROUNDS_MAX {
            return Err(password_hash::Error::ParamValueInvalid(password_hash::errors::InvalidValue::TooLong));
        }

        let params = match sha_crypt::Sha512Params::new(rounds as usize) {
            Ok(v) => v,
            Err(_) => return Err(password_hash::Error::ParamValueInvalid(password_hash::errors::InvalidValue::Malformed)),
        };

        Ok(Sha512Params{
            params,
            rounds,
        })
    }
}
impl TryFrom<Sha512Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(value: Sha512Params) -> Result<Self, Self::Error> {
        let mut out = Self::new();
        match value.rounds {
            ROUNDS_DEFAULT => {}
            rounds => {
                out.add_decimal("rounds", rounds)?;
            },
        }

        Ok(out)
    }
}
impl password_hash::PasswordHasher for Sha512 {
    type Params = Sha512Params;

    fn hash_password_customized<'a>(&self, password: &[u8], algorithm: Option<Ident<'a>>, version: Option<password_hash::Decimal>, params: Self::Params, salt: impl Into<Salt<'a>>) -> password_hash::Result<PasswordHash<'a>> {
        if version.is_some() {
            return Err(password_hash::Error::Version)
        }
        match algorithm {
            Some(SHA512_CRYPT) => {},
            None => {},
            _ => return Err(password_hash::Error::Algorithm),
        }

        let salt = salt.into();
        let hash = match sha_crypt::sha512_crypt(password, salt.as_str().as_bytes(), &params.params){
            Ok(v) => v,
            Err(_) => return Err(password_hash::Error::Crypto),
        };
        Ok(password_hash::PasswordHash{
            algorithm: SHA512_CRYPT,
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(password_hash::Output::new_with_encoding(&hash, password_hash::Encoding::ShaCrypt)?),
        })
    }
    fn hash_password<'a>(&self, password: &[u8], salt: impl Into<Salt<'a>>) -> password_hash::Result<PasswordHash<'a>> {
        let salt = salt.into();
        let hash = match sha_crypt::sha512_crypt(password, salt.as_str().as_bytes(), &self.params.params){
            Ok(v) => v,
            Err(_) => return Err(password_hash::Error::Crypto),
        };
        Ok(password_hash::PasswordHash{
            algorithm: SHA512_CRYPT,
            version: None,
            params: self.params.clone().try_into()?,
            salt: Some(salt),
            hash: Some(password_hash::Output::new_with_encoding(&hash, password_hash::Encoding::ShaCrypt)?),
        })
    }
}
pub struct Sha256{
    params: Sha256Params
}
impl Sha256 {
    pub const fn new(params: Sha256Params) -> Self {
        Self{
            params,
        }
    }
}
#[derive(Debug, Clone)]
pub struct Sha256Params{
    params: sha_crypt::Sha256Params,
    rounds: u32,
}
impl Default for Sha256Params{
    fn default() -> Self {
        Self{
            params: sha_crypt::Sha256Params::default(),
            rounds: ROUNDS_DEFAULT,
        }
    }
}
impl<'a> TryFrom<&'a PasswordHash<'a>> for Sha256Params {
    type Error = password_hash::Error;

    fn try_from(value: &'a PasswordHash<'a>) -> Result<Self, Self::Error> {
        let rounds = value.params.get("rounds")
            .map(|v|v.decimal())
            .transpose()?
            .unwrap_or(ROUNDS_DEFAULT);

        if sha_crypt::ROUNDS_MIN > rounds as usize {
            return Err(password_hash::Error::ParamValueInvalid(password_hash::errors::InvalidValue::TooShort));
        }
        if rounds as usize > sha_crypt::ROUNDS_MAX {
            return Err(password_hash::Error::ParamValueInvalid(password_hash::errors::InvalidValue::TooLong));
        }

        let params = match sha_crypt::Sha256Params::new(rounds as usize) {
            Ok(v) => v,
            Err(_) => return Err(password_hash::Error::ParamValueInvalid(password_hash::errors::InvalidValue::Malformed)),
        };

        Ok(Sha256Params{
            params,
            rounds,
        })
    }
}
impl TryFrom<Sha256Params> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(value: Sha256Params) -> Result<Self, Self::Error> {
        let mut out = Self::new();
        match value.rounds {
            ROUNDS_DEFAULT => {},
            rounds => {
                out.add_decimal("rounds", rounds)?;
            },
        }

        Ok(out)
    }
}
impl password_hash::PasswordHasher for Sha256 {
    type Params = Sha256Params;

    fn hash_password_customized<'a>(&self, password: &[u8], algorithm: Option<Ident<'a>>, version: Option<password_hash::Decimal>, params: Self::Params, salt: impl Into<Salt<'a>>) -> password_hash::Result<PasswordHash<'a>> {
        if version.is_some() {
            return Err(password_hash::Error::Version)
        }
        match algorithm {
            Some(SHA256_CRYPT) => {},
            None => {},
            _ => return Err(password_hash::Error::Algorithm),
        }

        let salt = salt.into();
        let hash = match sha_crypt::sha256_crypt(password, salt.as_str().as_bytes(), &params.params){
            Ok(v) => v,
            Err(_) => return Err(password_hash::Error::Crypto),
        };
        Ok(password_hash::PasswordHash{
            algorithm: SHA256_CRYPT,
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(password_hash::Output::new_with_encoding(&hash, password_hash::Encoding::ShaCrypt)?),
        })
    }
    fn hash_password<'a>(&self, password: &[u8], salt: impl Into<Salt<'a>>) -> password_hash::Result<PasswordHash<'a>> {
        let salt = salt.into();
        let hash = match sha_crypt::sha256_crypt(password, salt.as_str().as_bytes(), &self.params.params){
            Ok(v) => v,
            Err(_) => return Err(password_hash::Error::Crypto),
        };
        Ok(password_hash::PasswordHash{
            algorithm: SHA512_CRYPT,
            version: None,
            params: self.params.clone().try_into()?,
            salt: Some(salt),
            hash: Some(password_hash::Output::new_with_encoding(&hash, password_hash::Encoding::ShaCrypt)?),
        })
    }
}