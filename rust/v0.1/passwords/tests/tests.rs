use argon2::password_hash::{Error, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use passwords::{create_password_argon2, verify_password_argon2};
use rand_core::OsRng;

#[test]
fn verifiy_password_default() {
    let salt = SaltString::generate(&mut OsRng);
    let hash = match create_password_argon2(salt, &"bad_password_1", &None) {
        Ok(h) => h,
        Err(e) => return assert!(false),
    };

    let is_not_verified = verify_password_argon2(&"bas_password", &hash, &None);
    assert_eq!(is_not_verified.is_err(), true);

    let is_verified = verify_password_argon2(&"bad_password_1", &hash, &None);
    assert_eq!(is_verified.is_ok(), true);
}
