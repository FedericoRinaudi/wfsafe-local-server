use rocket::tokio::task::JoinError;
use std::error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum EbpfError {
    LibbpfError(libbpf_rs::Error),
    JoinError(JoinError),
    FigmentError(rocket::figment::Error),
    Err(String),
}

impl From<libbpf_rs::Error> for EbpfError {
    fn from(error: libbpf_rs::Error) -> Self {
        EbpfError::LibbpfError(error)
    }
}

impl From<JoinError> for EbpfError {
    fn from(error: JoinError) -> Self {
        EbpfError::JoinError(error)
    }
}

impl From<rocket::figment::Error> for EbpfError {
    fn from(error: rocket::figment::Error) -> Self {
        EbpfError::FigmentError(error)
    }
}

impl Display for EbpfError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EbpfError::LibbpfError(e) => write!(f, "LibbpfError: {}", e),
            EbpfError::JoinError(e) => write!(f, "JoinError: {}", e),
            EbpfError::FigmentError(e) => write!(f, "FigmentError: {}", e),
            EbpfError::Err(e) => write!(f, "Error: {}", e),
        }
    }
}

impl error::Error for EbpfError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(match self {
            EbpfError::LibbpfError(e) => e,
            EbpfError::JoinError(e) => e,
            EbpfError::FigmentError(e) => e,
            EbpfError::Err(_) => return None,
        })
    }
}
