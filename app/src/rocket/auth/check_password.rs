#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error Getting Password from DB: {0}")]
    GetPassword(sqlx::Error),
    #[error("Error Parsing Password Hash or Parameters: {0}")]
    ParsePassword(password_hash::Error),
    #[error("Error Verifying Password: {0}")]
    VerifyPassword(password_hash::Error),
    #[error("Error Verifying Password. Panicked: {0}")]
    VerifyPasswordPanic(tokio::task::JoinError),
    #[error("Error Hashing new Password: {0}")]
    HashNewPassword(password_hash::Error),
    #[error("Error hashing new Password. Panicked: {0}")]
    HashNewPasswordPanic(tokio::task::JoinError),
    #[error("Error Setting new Password-Hash: {0}")]
    SetNewPassword(sqlx::Error),
    #[error("Didn't set new Password-Hash, because the user doesn't have permission to change it.")]
    NoPermissionToChangePassword,
}
const ARGON2_ALGO: argon2::Algorithm = argon2::Algorithm::Argon2id;
const ARGON2_VERSION: argon2::Version = argon2::Version::V0x13;
const ARGON2_PARAMS: argon2::Params = match argon2::Params::new(
    256*1024,
    2,
    8,
    Some(password_hash::Output::MAX_LENGTH)
){
    Ok(v) => v,
    Err(_) => panic!("Error creating argon2 params")
};
// const ARGON2_PARAMS: argon2::Params = argon2::Params::DEFAULT;

pub async fn check_password(db: sqlx::PgPool, user_id: i64, slf_user_id: i64, password: String, new_password: Option<String>) -> Result<(), Error> {
    // let mut transaction = db.begin().await.map_err(|e| Error::TransactionBegin(e))?;
    let password_hash = sqlx::query!(r#"
SELECT
    password AS "password!"
FROM virtual_users
WHERE id = $1
"#, user_id)
        .fetch_one(&db)
        .await.map_err(|err|Error::GetPassword(err))?.password;
    log::debug!("got Password-Hash: {password_hash:?}");

    let encoding = {
        #[cfg(feature = "sha-crypt")]
        {
            if password_hash.starts_with(format!("${}",super::sha::SHA256_CRYPT.as_str()).as_str()) ||
                password_hash.starts_with(format!("${}",super::sha::SHA512_CRYPT.as_str()).as_str())
            {
                password_hash::Encoding::ShaCrypt
            } else {
                password_hash::Encoding::B64
            }
        }
        #[cfg(not(feature = "sha-crypt"))]
        password_hash::Encoding::B64
    };

    if verify_password(password_hash, encoding, password.clone()).await? {
        set_password(db, Ok(user_id), slf_user_id, password).await?;
    } else if let Some(new_password) = new_password {
        set_password(db, Ok(user_id), slf_user_id, new_password).await?;
    }

    // transaction.commit().await.map_err(|err|Error::TransactionCommit(err))?;

    Ok(())
}

pub async fn get_password_hash(password: String) -> Result<String, Error> {
    tokio::task::spawn_blocking(move||{
        let salt = argon2::password_hash::SaltString::generate(&mut password_hash::rand_core::OsRng);
        use argon2::password_hash::PasswordHasher;

        let argon = argon2::Argon2::new(ARGON2_ALGO, ARGON2_VERSION, ARGON2_PARAMS);
        Ok(argon.hash_password(password.as_bytes(), salt.as_salt()).map_err(|err|Error::HashNewPassword(err))?.to_string())
    }).await.unwrap_or_else(|e|Err(Error::HashNewPasswordPanic(e)))
}

pub async fn set_password(db: sqlx::PgPool, user: Result<i64, (&str, i64)>, slf_user_id: i64, password: String) -> Result<(), Error> {
    let hash = get_password_hash(password).await?;
    match match user {
        Ok(v) => {
            sqlx::query!("SELECT set_user_password($1, $2, '{ARGON2ID}', $3) as id", v, hash, slf_user_id)
                .fetch_optional(&db).await.map(|v|v.map(|v|v.id).flatten())
        },
        Err((email, domain_id)) => {
            sqlx::query!("SELECT set_user_password(users.id, $3, '{ARGON2ID}', $4) as id FROM users WHERE users.email = $1 AND users.domain_id = $2 ", email, domain_id, hash, slf_user_id)
                .fetch_optional(&db).await.map(|v|v.map(|v|v.id).flatten())
        }
    } {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(Error::NoPermissionToChangePassword),
        Err(err) => Err(Error::SetNewPassword(err))
    }
}

/**
* Return bool is set, if the password should be re-hashed.
*/
async fn verify_password(password_hash: String, encoding: password_hash::Encoding, password: String) -> Result<bool, Error> {
    tokio::task::spawn_blocking(move ||{
    let password_hash = password_hash;
    let password_hash = password_hash::PasswordHash::parse(password_hash.as_str(), encoding)
        .map_err(|err|Error::ParsePassword(err))?;
    let password_hash = &password_hash;
    log::debug!("decoded Password-Hash: {password_hash:?}");

    use password_hash::PasswordVerifier;
    match Algorithms::try_from(password_hash.algorithm) {
        Ok(Algorithms::Argon(algorithm)) => {
            log::debug!("argon algorithm: {algorithm:?}");

            let params = argon2::Params::try_from(password_hash).map_err(|e|Error::VerifyPassword(e))?;
            log::debug!("argon params: {params:?}");

            let version = password_hash.version
                .map(argon2::Version::try_from)
                .transpose().map_err(|e|Error::VerifyPassword(e.into()))?
                .unwrap_or_default();
            log::debug!("argon version: {version:?}");

            let needs_rehash = algorithm != ARGON2_ALGO || version != ARGON2_VERSION || params != ARGON2_PARAMS;
            argon2::Argon2::new(algorithm, version, params).verify_password(password.as_bytes(), password_hash).map_err(|e|Error::VerifyPassword(e))?;
            Ok(needs_rehash)
        }
        Ok(Algorithms::Bcrypt(_)) => {
            let params = super::bcrypt::BcryptParams::try_from(password_hash).map_err(|e|Error::VerifyPassword(e))?;
            log::debug!("bcrypt params: {params:?}");
            super::bcrypt::Bcrypt::new(params).verify_password(password.as_bytes(), password_hash).map_err(|e|Error::VerifyPassword(e))?;
            Ok(true)
        }
        #[cfg(feature = "sha-crypt")]
        Ok(Algorithms::Sha256) => {
            let params = super::sha::Sha256Params::try_from(password_hash).map_err(|e|Error::VerifyPassword(e))?;
            log::debug!("sha256 params: {params:?}");
            super::sha::Sha256::new(params).verify_password(password.as_bytes(), password_hash).map_err(|e|Error::VerifyPassword(e))?;
            Ok(true)
        }
        #[cfg(feature = "sha-crypt")]
        Ok(Algorithms::Sha512) => {
            let params = super::sha::Sha512Params::try_from(password_hash).map_err(|e|Error::VerifyPassword(e))?;
            log::debug!("sha512 params: {params:?}");
            super::sha::Sha512::new(params).verify_password(password.as_bytes(), password_hash).map_err(|e|Error::VerifyPassword(e))?;
            Ok(true)
        }
        Err(_) => Err(Error::VerifyPassword(password_hash::Error::Algorithm)),
    }
    }).await.map_or_else(|e|Err(Error::VerifyPasswordPanic(e)), |v|v)
}

macro_rules! ident {
    ($vis:vis $ident: ident, $($name:ident, $value:path),*) => {
$vis enum $ident{
    $($name),*
}
$crate::rocket::auth::check_password::ident!(impl, $ident, $(Self::$name, $value),*);
    };
    (impl, $ident: ident, $($name:expr, $value:path),*) => {
impl<'a> TryFrom<password_hash::Ident<'a>> for $ident {
    type Error = password_hash::Error;

    fn try_from(value: password_hash::Ident<'a>) -> Result<Self, Self::Error> {
        match value {
            $($value => Ok($name ),)*
            _ => Err(password_hash::Error::Algorithm),
        }
    }
}
    };
}
pub(super) use ident;
ident!(impl, Algorithms,
    Self::Argon(argon2::Algorithm::Argon2i), argon2::ARGON2I_IDENT,
    Self::Argon(argon2::Algorithm::Argon2d), argon2::ARGON2D_IDENT,
    Self::Argon(argon2::Algorithm::Argon2id), argon2::ARGON2ID_IDENT,
    Self::Bcrypt(super::bcrypt::BcryptAlgorithm::A), super::bcrypt::BCRYPT_A,
    Self::Bcrypt(super::bcrypt::BcryptAlgorithm::Y), super::bcrypt::BCRYPT_Y
    // Self::Sha512, super::sha::SHA512_CRYPT
    // Self::Sha256, super::sha::SHA256_CRYPT
);
enum Algorithms {
    Argon(argon2::Algorithm),
    #[allow(dead_code)]
    Bcrypt(super::bcrypt::BcryptAlgorithm),
    #[cfg(feature = "sha-crypt")] Sha512,
    #[cfg(feature = "sha-crypt")] Sha256
}