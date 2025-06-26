use grapple_pwd::{
    hash_content, is_salt_required, validate_content, ContentToHash, Result, SchemeStatus,
};

#[tokio::main]
async fn main() -> Result<()> {
    // HASH PASSWORD
    // Get user password
    let pwd = "my_password".to_string();

    // Hash the password
    let content_to_hash = ContentToHash::with_random_salt(&pwd);
    let pwd_hashed = hash_content("pwd", content_to_hash).await?;

    println!("pwd_hashed: {pwd_hashed}");

    if is_salt_required()? {
        // Save salt into db
    } else {
        // Insert empty salt into db
    }

    // VALIDATE THE PASSWORD
    // Read salt and hash from db
    let to_hash = ContentToHash {
        content: pwd.to_string(),
        salt: None, // Since it is argon2, then salt is empty in db
    };

    match validate_content("pwd", to_hash, &pwd_hashed).await? {
        SchemeStatus::Ok => println!("Password is valid"),
        SchemeStatus::Outdated => {
            // If scheme in db is outdated, then we need to rehash the password and update the db
            println!("Password is outdated");

            // Rehash the password and update the db
            // ...
        }
    }

    Ok(())
}
