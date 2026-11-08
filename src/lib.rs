pub mod capabilities;
pub mod cli;
pub mod code;
pub mod git;
mod interrupt;
pub mod output;
pub mod runner;
pub mod sandbox;
#[cfg(feature = "scanner")]
pub mod scanner;
pub mod session;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into()).into()
}
