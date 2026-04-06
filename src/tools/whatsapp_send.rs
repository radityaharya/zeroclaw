use super::traits::{Tool, ToolResult};
use crate::config::Config;
use crate::security::policy::ToolOperation;
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

/// Agent tool: outbound WhatsApp text via [`crate::channels::send_message_to_channel`].
pub struct WhatsappSendTool {
    security: Arc<SecurityPolicy>,
    config: Arc<Config>,
}

impl WhatsappSendTool {
    pub fn new(security: Arc<SecurityPolicy>, config: Arc<Config>) -> Self {
        Self { security, config }
    }
}

#[async_trait]
impl Tool for WhatsappSendTool {
    fn name(&self) -> &str {
        "whatsapp_send"
    }

    fn description(&self) -> &str {
        "Send a plain-text WhatsApp message to a recipient using the configured WhatsApp channel (Meta Cloud API or WhatsApp Web). Recipient: E.164 (+countrycode) for Cloud API; phone digits or full JID for Web. WhatsApp Web needs an active daemon session; allowed_numbers must include the target or \"*\"."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "to": {
                    "type": "string",
                    "description": "Recipient phone (E.164 like +15551234567, or digits) or WhatsApp JID (e.g. 1234567890@s.whatsapp.net) for Web."
                },
                "message": {
                    "type": "string",
                    "description": "Message text to send."
                }
            },
            "required": ["to", "message"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        if let Err(e) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, "whatsapp_send")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Action blocked: {e}")),
            });
        }

        let to = match args
            .get("to")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s) => s.to_string(),
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing or empty 'to'".into()),
                });
            }
        };

        let message = match args
            .get("message")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s) => s.to_string(),
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing or empty 'message'".into()),
                });
            }
        };

        match crate::channels::send_message_to_channel(&self.config, "whatsapp", &to, &message)
            .await
        {
            Ok(()) => Ok(ToolResult {
                success: true,
                output: format!("Sent WhatsApp message to {to}."),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e.to_string()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::AutonomyLevel;

    fn test_security(level: AutonomyLevel, max_actions_per_hour: u32) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: level,
            max_actions_per_hour,
            workspace_dir: std::env::temp_dir(),
            ..SecurityPolicy::default()
        })
    }

    #[test]
    fn whatsapp_send_tool_name() {
        let cfg = Arc::new(Config::default());
        let tool = WhatsappSendTool::new(test_security(AutonomyLevel::Full, 100), cfg);
        assert_eq!(tool.name(), "whatsapp_send");
    }

    #[test]
    fn whatsapp_send_parameters_require_to_and_message() {
        let cfg = Arc::new(Config::default());
        let tool = WhatsappSendTool::new(test_security(AutonomyLevel::Full, 100), cfg);
        let schema = tool.parameters_schema();
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::Value::String("to".into())));
        assert!(required.contains(&serde_json::Value::String("message".into())));
    }
}
