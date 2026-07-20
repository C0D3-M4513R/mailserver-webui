use password_hash::phc::{Ident, ParamsString, PasswordHash, Salt};
use password_hash::{PasswordHasher, Version};

pub const BCRYPT_A:Ident = Ident::new_unwrap("2a");

super::check_password::ident!(pub BcryptAlgorithm,
    A, BCRYPT_A
);
pub struct Bcrypt{
    params: BcryptParams,
}
impl Bcrypt {
    #[inline]
    pub const fn new(params: BcryptParams) -> Self {
        Self{
            params,
        }
    }
}
const DEFAULT_ROUNDS: u32 = 5_000;
#[derive(Debug, Clone)]
pub struct BcryptParams{
    rounds: u32,
    output_length: usize,
    algorithm: Ident
}
impl TryFrom<&'_ PasswordHash> for BcryptParams {
    type Error = password_hash::Error;

    fn try_from(value: &'_ PasswordHash) -> Result<Self, Self::Error> {
        let rounds = value.params.get("rounds").map_or(Ok(DEFAULT_ROUNDS), |v| v.decimal())?;
        let len = match value.hash {
            None => return Err(password_hash::Error::ParamsInvalid),
            Some(v) => v.len()
        };

        Ok(BcryptParams {
            rounds,
            output_length: len,
            algorithm: value.algorithm.clone(),
        })
    }
}
impl TryFrom<&'_ BcryptParams> for ParamsString {
    type Error = password_hash::phc::Error;

    fn try_from(value: &'_ BcryptParams) -> Result<Self, Self::Error> {
        let mut out = Self::new();
        match value.rounds {
            DEFAULT_ROUNDS => {},
            v => out.add_decimal("rounds", v)?,
        }
        Ok(out)
    }
}
impl Default for BcryptParams {
    fn default() -> Self {
        Self{
            rounds: 5_000,
            output_length: 32,
            algorithm: BCRYPT_A,
        }
    }
}
impl password_hash::PasswordHasher<PasswordHash> for Bcrypt {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> password_hash::Result<PasswordHash> {
        let mut out = Vec::with_capacity(self.params.output_length);
        out.resize(self.params.output_length, 0);
        let salt = salt.into();
        match bcrypt_pbkdf::bcrypt_pbkdf(password, salt, self.params.rounds, out.as_mut_slice()) {
            Ok(()) => {},
            Err(_) => return Err(password_hash::Error::Crypto),
        }

        Ok(PasswordHash{
            algorithm: BCRYPT_A,
            version: None,
            params: (&self.params).try_into()?,
            salt: Some(Salt::new(salt)?),
            hash: Some(password_hash::phc::Output::new(out.as_slice())?),
        })
    }
}
pub struct BCryptVerifier{}
impl password_hash::CustomizedPasswordHasher<PasswordHash> for BCryptVerifier {
    type Params = BcryptParams;

    fn hash_password_customized(&self, password: &[u8], salt: &[u8], algorithm: Option<&str>, _: Option<Version>, params: Self::Params) -> password_hash::Result<PasswordHash> {
        if let Some(algo) = algorithm {
            if !params.algorithm.eq_ignore_ascii_case(algo) {
                return Err(password_hash::Error::ParamsInvalid);
            }
        }
        Bcrypt::new(params).hash_password_with_salt(password, salt)
    }
}