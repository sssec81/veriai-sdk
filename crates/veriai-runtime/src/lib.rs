pub mod error;
pub mod mock;
pub mod llama_cpp;

use async_trait::async_trait;
use veriai_types::openai::{InferenceRequest, InferenceResult, RuntimeMetadata};
use crate::error::RuntimeError;

#[async_trait]
pub trait InferenceRuntime: Send + Sync {
    /// Execute prompt chat completions asynchronously.
    async fn generate(&self, request: InferenceRequest) -> Result<InferenceResult, RuntimeError>;

    /// Returns structured metadata details of the runtime.
    fn metadata(&self) -> RuntimeMetadata;

    /// Unique identifier for telemetry and billing tracking.
    fn id(&self) -> &'static str;
}
