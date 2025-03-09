use password_hash::{Decimal, Ident, ParamsString, PasswordHash, Salt};

pub const BCRYPT_A:password_hash::Ident<'static> = password_hash::Ident::new_unwrap("2a");
pub const BCRYPT_Y:password_hash::Ident<'static> = password_hash::Ident::new_unwrap("2y");
super::check_password::ident!(pub BcryptAlgorithm,
    A, BCRYPT_A,
    Y, BCRYPT_Y
);
pub struct Bcrypt{
    params: BcryptParams,
}
impl Bcrypt {
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
}
impl TryFrom<&'_ PasswordHash<'_>> for BcryptParams {
    type Error = password_hash::Error;

    fn try_from(value: &'_ PasswordHash<'_>) -> Result<Self, Self::Error> {
        let rounds = value.params.get("rounds").map_or(Ok(DEFAULT_ROUNDS), |v| v.decimal())?;
        let len = match value.hash {
            None => return Err(password_hash::Error::PhcStringField),
            Some(v) => v.len()
        };

        Ok(BcryptParams {
            rounds,
            output_length: len,
        })
    }
}
impl TryFrom<BcryptParams> for ParamsString {
    type Error = password_hash::Error;

    fn try_from(value: BcryptParams) -> Result<Self, Self::Error> {
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
        }
    }
}
impl password_hash::PasswordHasher for Bcrypt {
    type Params = BcryptParams;

    fn hash_password_customized<'a>(&self, password: &[u8], algorithm: Option<Ident<'a>>, version: Option<Decimal>, params: Self::Params, salt: impl Into<Salt<'a>>) -> password_hash::Result<PasswordHash<'a>> {
        if version.is_some() {
            return Err(password_hash::Error::Version)
        }
        if let Some(algorithm) = algorithm{
            let _br = BcryptAlgorithm::try_from(algorithm)?;
        }


        let mut out = Vec::with_capacity(params.output_length);
        out.resize(params.output_length, 0);
        let salt = salt.into();
        match bcrypt_pbkdf::bcrypt_pbkdf(password, salt.as_str().as_bytes(), params.rounds, out.as_mut_slice()) {
            Ok(()) => {},
            Err(_) => return Err(password_hash::Error::Crypto),
        }

        Ok(PasswordHash{
            algorithm: BCRYPT_Y,
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(password_hash::Output::new(out.as_slice())?),
        })
    }
    fn hash_password<'a>(&self, password: &[u8], salt: impl Into<Salt<'a>>) -> password_hash::Result<PasswordHash<'a>> {
        let mut out = Vec::with_capacity(self.params.output_length);
        out.resize(self.params.output_length, 0);
        let salt = salt.into();
        match bcrypt_pbkdf::bcrypt_pbkdf(password, salt.as_str().as_bytes(), self.params.rounds, out.as_mut_slice()) {
            Ok(()) => {},
            Err(_) => return Err(password_hash::Error::Crypto),
        }

        Ok(PasswordHash{
            algorithm: BCRYPT_Y,
            version: None,
            params: self.params.clone().try_into()?,
            salt: Some(salt),
            hash: Some(password_hash::Output::new(out.as_slice())?),
        })
    }
}