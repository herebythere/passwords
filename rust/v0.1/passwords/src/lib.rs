use rand_core::OsRng;

use argon2::{Argon2, Params};

use argon2::password_hash::{Error, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

pub fn create_password_argon2<'a>(
    password: &str,
    salt: SaltString,
    params: &Option<Params>,
) -> Result<String, Error> {
    let password_bytes = password.as_bytes();

    let argon2 = match params {
        Some(p) => Argon2::from(p),
        _ => Argon2::default(),
    };

    // Hash password to PHC string ($argon2id$v=19$...)
    match argon2.hash_password(password_bytes, &salt) {
        Ok(r) => Ok(r.to_string()),
        Err(e) => Err(e),
    }
}

pub fn verify_password_argon2(
    password: &str,
    hash: &str,
    params: &Option<Params>,
) -> Result<(), String> {
    let argon2 = match params {
        Some(p) => Argon2::from(p),
        _ => Argon2::default(),
    };

    let pwh = match PasswordHash::new(hash) {
        Ok(p) => p,
        Err(e) => return Err(e.to_string()),
    };

    let password_bytes = password.as_bytes(); // Bad password; don't actually use!
    match argon2.verify_password(password_bytes, &pwh) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
