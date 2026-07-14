use crate::{InferenceRuntime, error::RuntimeError};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use veriai_types::openai::{InferenceRequest, InferenceResult, RuntimeMetadata};

pub struct LlamaCppRuntime {
    pub binary_path: PathBuf,
    pub model_path: PathBuf,
    pub max_tokens: u32,
    pub context_size: u32,
}

impl LlamaCppRuntime {
    pub fn new(model_path: PathBuf) -> Self {
        Self {
            binary_path: PathBuf::from("llama-cli"),
            model_path,
            max_tokens: 256,
            context_size: 4096,
        }
    }

    pub fn with_binary(model_path: PathBuf, binary_path: PathBuf) -> Self {
        Self {
            binary_path,
            ..Self::new(model_path)
        }
    }

    fn prompt(request: &InferenceRequest) -> Result<String, RuntimeError> {
        if request.messages.is_empty() {
            return Err(RuntimeError::InvalidContext(
                "at least one message is required".to_string(),
            ));
        }

        let mut prompt = String::new();
        for message in &request.messages {
            if message.role.trim().is_empty() {
                return Err(RuntimeError::InvalidContext(
                    "message roles must not be empty".to_string(),
                ));
            }
            prompt.push_str("<|im_start|>");
            prompt.push_str(&message.role);
            prompt.push('\n');
            prompt.push_str(&message.content);
            prompt.push_str("<|im_end|>\n");
        }
        prompt.push_str("<|im_start|>assistant\n");
        Ok(prompt)
    }
}

#[async_trait]
impl InferenceRuntime for LlamaCppRuntime {
    async fn generate(&self, request: InferenceRequest) -> Result<InferenceResult, RuntimeError> {
        if !Path::new(&self.model_path).is_file() {
            return Err(RuntimeError::ModelLoadFailed(format!(
                "model file does not exist: {}",
                self.model_path.display()
            )));
        }

        let prompt = Self::prompt(&request)?;
        let temperature = request.temperature.unwrap_or(0.7).clamp(0.0, 2.0);
        let output = Command::new(&self.binary_path)
            .arg("-m")
            .arg(&self.model_path)
            .arg("-p")
            .arg(prompt)
            .arg("-n")
            .arg(self.max_tokens.to_string())
            .arg("--ctx-size")
            .arg(self.context_size.to_string())
            .arg("--temp")
            .arg(temperature.to_string())
            // The API supplies a complete prompt and expects one response.
            // llama.cpp otherwise auto-enables interactive conversation mode
            // for models with chat templates and keeps the subprocess alive.
            .arg("--no-conversation")
            .arg("--single-turn")
            .arg("--simple-io")
            .arg("--no-display-prompt")
            .arg("--no-show-timings")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .await
            .map_err(|e| RuntimeError::ProcessFailed(format!("failed to start llama-cli: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RuntimeError::InferenceFailed(format!(
                "llama-cli exited with {}: {}",
                output.status,
                stderr.trim()
            )));
        }

        let raw_output = String::from_utf8(output.stdout).map_err(|e| {
            RuntimeError::InferenceFailed(format!("llama-cli returned invalid UTF-8: {e}"))
        })?;
        let content = extract_completion(&raw_output);
        if content.is_empty() {
            return Err(RuntimeError::InferenceFailed(
                "llama-cli returned an empty completion".to_string(),
            ));
        }

        Ok(InferenceResult {
            tokens_generated: content.split_whitespace().count() as u32,
            content,
        })
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

fn extract_completion(raw_output: &str) -> String {
    let mut output = raw_output;

    // Some llama.cpp builds still print the interactive prompt even with
    // --no-display-prompt. The generated text follows the prompt's blank line.
    if let Some(prompt_start) = output.rfind("\n> ") {
        output = &output[prompt_start + 3..];
        if let Some(completion_start) = output.find("\n\n") {
            output = &output[completion_start + 2..];
        }
    }

    if let Some(timing_start) = output.find("\n\n[ Prompt:") {
        output = &output[..timing_start];
    }
    if let Some(exit_start) = output.find("\n\nExiting...") {
        output = &output[..exit_start];
    }

    output.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::extract_completion;

    #[test]
    fn extracts_completion_from_cli_ui_output() {
        let raw = "Loading model...\n\n> prompt\n\nhello world\n\n[ Prompt: 1 t/s ]\n\nExiting...";
        assert_eq!(extract_completion(raw), "hello world");
    }
}
