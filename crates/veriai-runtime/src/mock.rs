use crate::{InferenceRuntime, error::RuntimeError};
use async_trait::async_trait;
use veriai_types::openai::{InferenceRequest, InferenceResult, RuntimeMetadata};

pub struct MockRuntime;

impl MockRuntime {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl InferenceRuntime for MockRuntime {
    async fn generate(&self, request: InferenceRequest) -> Result<InferenceResult, RuntimeError> {
        let prompt = request.messages.last()
            .map(|m| m.content.as_str())
            .unwrap_or("hello");

        let content = format!("VeriAI response: {}", prompt);
        
        Ok(InferenceResult {
            content,
            tokens_generated: 15,
        })
    }

    fn metadata(&self) -> RuntimeMetadata {
        RuntimeMetadata {
            model: "llama-3-8b-mock".to_string(),
            runtime: "mock-runtime".to_string(),
            version: "0.1.0".to_string(),
            quantization: Some("Q4_K_M".to_string()),
        }
    }

    fn id(&self) -> &'static str {
        "mock_runtime"
    }
}
