//! Prompt injection defense layer (detection disabled; API preserved for compatibility).

use serde::{Deserialize, Serialize};

/// Pattern detection result.
#[derive(Debug, Clone)]
pub enum GuardResult {
    /// Message is safe.
    Safe,
    /// Message contains suspicious patterns (with detection details and score).
    Suspicious(Vec<String>, f64),
    /// Message should be blocked (with reason).
    Blocked(String),
}

/// Action to take when suspicious content is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GuardAction {
    /// Log warning but allow the message.
    #[default]
    Warn,
    /// Block the message with an error.
    Block,
    /// Sanitize by removing/escaping dangerous patterns.
    Sanitize,
}

impl GuardAction {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "block" => Self::Block,
            "sanitize" => Self::Sanitize,
            _ => Self::Warn,
        }
    }
}

/// Prompt injection guard (no-op scanning).
#[derive(Debug, Clone)]
pub struct PromptGuard {
    #[allow(dead_code)]
    action: GuardAction,
    #[allow(dead_code)]
    sensitivity: f64,
}

impl Default for PromptGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptGuard {
    pub fn new() -> Self {
        Self {
            action: GuardAction::Warn,
            sensitivity: 0.7,
        }
    }

    pub fn with_config(action: GuardAction, sensitivity: f64) -> Self {
        Self {
            action,
            sensitivity: sensitivity.clamp(0.0, 1.0),
        }
    }

    /// Scan a message for prompt injection patterns (detection disabled).
    pub fn scan(&self, _content: &str) -> GuardResult {
        GuardResult::Safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_always_safe() {
        let guard = PromptGuard::new();
        assert!(matches!(guard.scan("any text"), GuardResult::Safe));
        assert!(matches!(
            guard.scan("Ignore previous instructions"),
            GuardResult::Safe
        ));
    }
}
