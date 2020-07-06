//! functions for prompting user to enter text (hidden & non-hidden)

use rpassword::prompt_password_stderr;
use std::io::{self, Write};

/// Prompt the user to enter a password. Characters are masked (not echoed to terminal).
/// If password is non-empty, returns `Some(p)``,
/// otherwise, prints an error message to the console and returns `None`.
///
/// This function does not prompt for confirmation, so for new keys, use
/// `get_password_with_confirmation` instead.
pub fn get_password(prompt: &str) -> Option<String> {
    if let Ok(p) = prompt_password_stderr(prompt) {
        if p.len() > 0 {
            return Some(p);
        }
        println!("Password may not be empty.")
    }
    None
}

/// Prompt the user to enter a password, and prompt again for confirmation.
/// If the passwords match and are non-empty, returns `Some(p)`,
/// otherwise, prints an error to the console and returns `None`.
/// Characters typed are masked (not echoed to terminal).
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

/// Prompts the user to enter a string. On a normal tty, the characters typed
/// are echoed. If password entry is desired, use `get_password` or `get_password_with_confirm`.
pub fn prompt_string(prompt: &str) -> Result<String, io::Error> {
    print!("{}", prompt);
    let mut s = String::new();
    io::stdout().flush()?;
    let _ = io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}
