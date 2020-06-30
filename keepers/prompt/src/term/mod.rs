//
//
use rpassword::prompt_password_stderr;
use std::io::{self, Write};

/// Get password from terminal.
/// If password is non-empty, returns Some(p), otherwise, prints error message and returns None.
///
/// Single prompt- for use with existing vaults. For new password entry, use
/// get_password_with_confirm.
pub fn get_password(prompt: &str) -> Option<String> {
    if let Ok(p) = prompt_password_stderr(prompt) {
        if p.len() > 0 {
            return Some(p);
        }
        println!("Password may not be empty.")
    }
    None
}

/// Get password from terminal. Prompts for confirmation.
/// If password is non-empty and confirmation matches, returns Some(p),
/// otherwise, prints error message and returns None.
pub fn get_password_with_confirm(prompt: &str, confirm_prompt: &str) -> Option<String> {
    if let Some(p1) = get_password(prompt) {
        if let Some(p2) = get_password(confirm_prompt) {
            if p1 == p2 {
                return Some(p2);
            }
            println!("Passwords did not match.");
            return None;
        }
    }
    println!("Cancelled.");
    None
}

/// Get a user input string with prompt.
/// Unlike get_password* functions, this does not mask typed chars.
pub fn prompt_string(prompt: &str) -> Result<String, io::Error> {
    print!("{}", prompt);
    let mut s = String::new();
    io::stdout().flush()?;
    let _ = io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}
