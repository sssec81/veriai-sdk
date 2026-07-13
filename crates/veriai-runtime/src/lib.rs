pub mod error;
pub mod llama_cpp;
pub mod mock;

use crate::error::RuntimeError;
use async_trait::async_trait;
use veriai_types::openai::{InferenceRequest, InferenceResult, RuntimeMetadata};

#[async_trait]
pub trait InferenceRuntime: Send + Sync {
    /// Execute prompt chat completions asynchronously.
    async fn generate(&self, request: InferenceRequest) -> Result<InferenceResult, RuntimeError>;

    /// Returns structured metadata details of the runtime.
    fn metadata(&self) -> RuntimeMetadata;

    /// Unique identifier for telemetry and billing tracking.
    fn id(&self) -> &'static str;
}
