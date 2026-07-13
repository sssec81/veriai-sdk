use crate::{InferenceRuntime, error::RuntimeError};
use async_trait::async_trait;
use std::path::PathBuf;
use veriai_types::openai::{InferenceRequest, InferenceResult, RuntimeMetadata};

pub struct LlamaCppRuntime {
    pub model_path: PathBuf,
}

impl LlamaCppRuntime {
    pub fn new(model_path: PathBuf) -> Self {
        Self { model_path }
    }
}

#[async_trait]
impl InferenceRuntime for LlamaCppRuntime {
    async fn generate(&self, _request: InferenceRequest) -> Result<InferenceResult, RuntimeError> {
        Err(RuntimeError::NotImplemented("llama.cpp adapter is not configured in this build".to_string()))
    }

    fn metadata(&self) -> RuntimeMetadata {
        RuntimeMetadata {
            model: "llama-3-8b-gguf".to_string(),
            runtime: "llama.cpp".to_string(),
            version: "0.1.0".to_string(),
            quantization: Some("Q4_K_M".to_string()),
        }
    }

    fn id(&self) -> &'static str {
        "llama_cpp"
    }
}
