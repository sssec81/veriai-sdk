use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("Failed to load model weights: {0}")]
    ModelLoadFailed(String),

    #[error("Inference execution failed: {0}")]
    InferenceFailed(String),

    #[error("Out of memory on the device")]
    OutOfMemory,

    #[error("Invalid request or prompt structure: {0}")]
    InvalidContext(String),

    #[error("Feature not implemented: {0}")]
    NotImplemented(String),
}
