use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use codex_protocol::ToolName;
use serde_json::Value as JsonValue;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::runtime::ExecuteRequest;
use crate::runtime::RuntimeResponse;
use crate::runtime::WaitRequest;

const ANDROID_UNSUPPORTED_MESSAGE: &str =
    "exec is unavailable in Android builds because the V8 runtime is disabled";

#[async_trait]
pub trait CodeModeTurnHost: Send + Sync {
    async fn invoke_tool(
        &self,
        tool_name: ToolName,
        input: Option<JsonValue>,
        cancellation_token: CancellationToken,
    ) -> Result<JsonValue, String>;

    async fn notify(&self, call_id: String, cell_id: String, text: String) -> Result<(), String>;
}

pub struct CodeModeService {
    stored_values: Arc<Mutex<HashMap<String, JsonValue>>>,
}

impl CodeModeService {
    pub fn new() -> Self {
        Self {
            stored_values: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn stored_values(&self) -> HashMap<String, JsonValue> {
        self.stored_values.lock().await.clone()
    }

    pub async fn replace_stored_values(&self, values: HashMap<String, JsonValue>) {
        *self.stored_values.lock().await = values;
    }

    pub async fn execute(&self, request: ExecuteRequest) -> Result<RuntimeResponse, String> {
        let ExecuteRequest {
            tool_call_id,
            enabled_tools,
            source,
            stored_values,
            yield_time_ms,
            max_output_tokens,
        } = request;
        let _ = (
            tool_call_id,
            enabled_tools,
            source,
            stored_values,
            yield_time_ms,
            max_output_tokens,
        );
        Err(ANDROID_UNSUPPORTED_MESSAGE.to_string())
    }

    pub async fn wait(&self, request: WaitRequest) -> Result<RuntimeResponse, String> {
        let WaitRequest {
            cell_id,
            yield_time_ms,
            terminate,
        } = request;
        let _ = (cell_id, yield_time_ms, terminate);
        Err(ANDROID_UNSUPPORTED_MESSAGE.to_string())
    }

    pub fn start_turn_worker(&self, _host: Arc<dyn CodeModeTurnHost>) -> CodeModeTurnWorker {
        CodeModeTurnWorker
    }
}

impl Default for CodeModeService {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CodeModeTurnWorker;
