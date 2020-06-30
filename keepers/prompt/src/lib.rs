mod prompt;
pub use prompt::PromptKeeper;

pub mod term;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
