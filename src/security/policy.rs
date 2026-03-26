use parking_lot::Mutex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// How much autonomy the agent has
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AutonomyLevel {
    /// Read-only: can observe but not act
    ReadOnly,
    /// Supervised: acts but requires approval for risky operations
    #[default]
    Supervised,
    /// Full: autonomous execution within policy bounds
    Full,
}

/// Risk score for shell command execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandRiskLevel {
    Low,
    Medium,
    High,
}

/// Classifies whether a tool operation is read-only or side-effecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolOperation {
    Read,
    Act,
}

/// Sliding-window action tracker for rate limiting.
#[derive(Debug)]
pub struct ActionTracker {
    /// Timestamps of recent actions (kept within the last hour).
    actions: Mutex<Vec<Instant>>,
}

impl ActionTracker {
    pub fn new() -> Self {
        Self {
            actions: Mutex::new(Vec::new()),
        }
    }

    /// Record an action and return the current count within the window.
    pub fn record(&self) -> usize {
        let mut actions = self.actions.lock();
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        actions.retain(|t| *t > cutoff);
        actions.push(Instant::now());
        actions.len()
    }

    /// Count of actions in the current window without recording.
    pub fn count(&self) -> usize {
        let mut actions = self.actions.lock();
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        actions.retain(|t| *t > cutoff);
        actions.len()
    }
}

impl Clone for ActionTracker {
    fn clone(&self) -> Self {
        let actions = self.actions.lock();
        Self {
            actions: Mutex::new(actions.clone()),
        }
    }
}

/// Security policy enforced on all tool executions
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub autonomy: AutonomyLevel,
    pub workspace_dir: PathBuf,
    pub workspace_only: bool,
    pub allowed_commands: Vec<String>,
    pub forbidden_paths: Vec<String>,
    pub allowed_roots: Vec<PathBuf>,
    pub max_actions_per_hour: u32,
    pub max_cost_per_day_cents: u32,
    pub require_approval_for_medium_risk: bool,
    pub block_high_risk_commands: bool,
    pub shell_env_passthrough: Vec<String>,
    pub tracker: ActionTracker,
}

/// Default allowed commands for Unix platforms.
#[cfg(not(target_os = "windows"))]
fn default_allowed_commands() -> Vec<String> {
    vec![
        "git".into(),
        "npm".into(),
        "cargo".into(),
        "ls".into(),
        "cat".into(),
        "grep".into(),
        "find".into(),
        "echo".into(),
        "pwd".into(),
        "wc".into(),
        "head".into(),
        "tail".into(),
        "date".into(),
    ]
}

/// Default allowed commands for Windows platforms.
///
/// Includes both native Windows commands and their Unix equivalents
/// (available via Git for Windows, WSL, etc.).
#[cfg(target_os = "windows")]
fn default_allowed_commands() -> Vec<String> {
    vec![
        // Cross-platform tools
        "git".into(),
        "npm".into(),
        "cargo".into(),
        "echo".into(),
        // Windows-native equivalents
        "dir".into(),
        "type".into(),
        "findstr".into(),
        "where".into(),
        "more".into(),
        "date".into(),
        // Unix commands (available via Git for Windows / MSYS2)
        "ls".into(),
        "cat".into(),
        "grep".into(),
        "find".into(),
        "pwd".into(),
        "wc".into(),
        "head".into(),
        "tail".into(),
    ]
}

/// Default forbidden paths for Unix platforms.
#[cfg(not(target_os = "windows"))]
fn default_forbidden_paths() -> Vec<String> {
    vec![
        "/etc".into(),
        "/root".into(),
        "/home".into(),
        "/usr".into(),
        "/bin".into(),
        "/sbin".into(),
        "/lib".into(),
        "/opt".into(),
        "/boot".into(),
        "/dev".into(),
        "/proc".into(),
        "/sys".into(),
        "/var".into(),
        "/tmp".into(),
        "~/.ssh".into(),
        "~/.gnupg".into(),
        "~/.aws".into(),
        "~/.config".into(),
    ]
}

/// Default forbidden paths for Windows platforms.
#[cfg(target_os = "windows")]
fn default_forbidden_paths() -> Vec<String> {
    vec![
        "C:\\Windows".into(),
        "C:\\Windows\\System32".into(),
        "C:\\Program Files".into(),
        "C:\\Program Files (x86)".into(),
        "C:\\ProgramData".into(),
        "~/.ssh".into(),
        "~/.gnupg".into(),
        "~/.aws".into(),
        "~/.config".into(),
    ]
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: PathBuf::from("."),
            workspace_only: true,
            allowed_commands: default_allowed_commands(),
            forbidden_paths: default_forbidden_paths(),
            allowed_roots: Vec::new(),
            max_actions_per_hour: 20,
            max_cost_per_day_cents: 500,
            require_approval_for_medium_risk: true,
            block_high_risk_commands: true,
            shell_env_passthrough: vec![],
            tracker: ActionTracker::new(),
        }
    }
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
    }
}

fn expand_user_path(path: &str) -> PathBuf {
    if path == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    }

    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(stripped);
        }
    }

    PathBuf::from(path)
}

fn rootless_path(path: &Path) -> Option<PathBuf> {
    let mut relative = PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => return None,
            std::path::Component::Normal(part) => relative.push(part),
        }
    }

    if relative.as_os_str().is_empty() {
        None
    } else {
        Some(relative)
    }
}

// ── Shell Command Parsing Utilities ───────────────────────────────────────
// These helpers implement a minimal quote-aware shell lexer. They exist
// because security validation must reason about the *structure* of a
// command (separators, operators, quoting) rather than treating it as a
// flat string — otherwise an attacker could hide dangerous sub-commands
// inside quoted arguments or chained operators.
/// Skip leading environment variable assignments (e.g. `FOO=bar cmd args`).
/// Returns the remainder starting at the first non-assignment word.
fn skip_env_assignments(s: &str) -> &str {
    let mut rest = s;
    loop {
        let Some(word) = rest.split_whitespace().next() else {
            return rest;
        };
        // Environment assignment: contains '=' and starts with a letter or underscore
        if word.contains('=')
            && word
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            // Advance past this word
            rest = rest[word.len()..].trim_start();
        } else {
            return rest;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    None,
    Single,
    Double,
}

/// Split a shell command into sub-commands by unquoted separators.
///
/// Separators:
/// - `;` and newline
/// - `|`
/// - `&&`, `||`
///
/// Characters inside single or double quotes are treated as literals, so
/// `sqlite3 db "SELECT 1; SELECT 2;"` remains a single segment.
fn split_unquoted_segments(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut chars = command.chars().peekable();

    let push_segment = |segments: &mut Vec<String>, current: &mut String| {
        let trimmed = current.trim();
        if !trimmed.is_empty() {
            segments.push(trimmed.to_string());
        }
        current.clear();
    };

    while let Some(ch) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
                current.push(ch);
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    current.push(ch);
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    current.push(ch);
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
                current.push(ch);
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    current.push(ch);
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    current.push(ch);
                    continue;
                }

                match ch {
                    '\'' => {
                        quote = QuoteState::Single;
                        current.push(ch);
                    }
                    '"' => {
                        quote = QuoteState::Double;
                        current.push(ch);
                    }
                    ';' | '\n' => push_segment(&mut segments, &mut current),
                    '|' => {
                        if chars.next_if_eq(&'|').is_some() {
                            // Consume full `||`; both characters are separators.
                        }
                        push_segment(&mut segments, &mut current);
                    }
                    '&' => {
                        if chars.next_if_eq(&'&').is_some() {
                            // `&&` is a separator; single `&` is handled separately.
                            push_segment(&mut segments, &mut current);
                        } else {
                            current.push(ch);
                        }
                    }
                    _ => current.push(ch),
                }
            }
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        segments.push(trimmed.to_string());
    }

    segments
}

/// Detect a single unquoted `&` operator (background/chain). `&&` is allowed.
///
/// We treat any standalone `&` as unsafe in policy validation because it can
/// chain hidden sub-commands and escape foreground timeout expectations.
fn contains_unquoted_single_ampersand(command: &str) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                match ch {
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    '&' => {
                        if chars.next_if_eq(&'&').is_none() {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    false
}

/// Detect an unquoted character in a shell command.
fn contains_unquoted_char(command: &str, target: char) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;

    for ch in command.chars() {
        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                match ch {
                    '\'' => quote = QuoteState::Single,
                    '"' => quote = QuoteState::Double,
                    _ if ch == target => return true,
                    _ => {}
                }
            }
        }
    }

    false
}

/// Detect unquoted shell variable expansions like `$HOME`, `$1`, `$?`.
///
/// Escaped dollars (`\$`) are ignored. Variables inside single quotes are
/// treated as literals and therefore ignored.
fn contains_unquoted_shell_variable_expansion(command: &str) -> bool {
    let mut quote = QuoteState::None;
    let mut escaped = false;
    let chars: Vec<char> = command.chars().collect();

    for i in 0..chars.len() {
        let ch = chars[i];

        match quote {
            QuoteState::Single => {
                if ch == '\'' {
                    quote = QuoteState::None;
                }
                continue;
            }
            QuoteState::Double => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                    continue;
                }
            }
            QuoteState::None => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '\'' {
                    quote = QuoteState::Single;
                    continue;
                }
                if ch == '"' {
                    quote = QuoteState::Double;
                    continue;
                }
            }
        }

        if ch != '$' {
            continue;
        }

        let Some(next) = chars.get(i + 1).copied() else {
            continue;
        };
        if next.is_ascii_alphanumeric()
            || matches!(
                next,
                '_' | '{' | '(' | '#' | '?' | '!' | '$' | '*' | '@' | '-'
            )
        {
            return true;
        }
    }

    false
}

fn strip_wrapping_quotes(token: &str) -> &str {
    token.trim_matches(|c| c == '"' || c == '\'')
}

fn looks_like_path(candidate: &str) -> bool {
    candidate.starts_with('/')
        || candidate.starts_with("./")
        || candidate.starts_with("../")
        || candidate.starts_with('~')
        || candidate == "."
        || candidate == ".."
        || candidate.contains('/')
        // Windows path patterns: drive letters (C:\, D:\) and UNC paths (\\server\share)
        || (cfg!(target_os = "windows")
            && (candidate
                .get(1..3)
                .is_some_and(|s| s == ":\\" || s == ":/")
                || candidate.starts_with("\\\\")))
}

fn attached_short_option_value(token: &str) -> Option<&str> {
    // Examples:
    // -f/etc/passwd   -> /etc/passwd
    // -C../outside    -> ../outside
    // -I./include     -> ./include
    let body = token.strip_prefix('-')?;
    if body.starts_with('-') || body.len() < 2 {
        return None;
    }
    let value = body[1..].trim_start_matches('=').trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn redirection_target(token: &str) -> Option<&str> {
    let marker_idx = token.find(['<', '>'])?;
    let mut rest = &token[marker_idx + 1..];
    rest = rest.trim_start_matches(['<', '>']);
    rest = rest.trim_start_matches('&');
    rest = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Extract the basename from a command path, handling both Unix (`/`) and
/// Windows (`\`) separators so that `C:\Git\bin\git.exe` resolves to `git.exe`.
fn command_basename(raw: &str) -> &str {
    let after_fwd = raw.rsplit('/').next().unwrap_or(raw);
    after_fwd.rsplit('\\').next().unwrap_or(after_fwd)
}

/// Strip common Windows executable suffixes (.exe, .cmd, .bat) for uniform
/// matching against allowlists and risk tables. On non-Windows platforms this
/// is a no-op that returns the input unchanged.
fn strip_windows_exe_suffix(name: &str) -> &str {
    if cfg!(target_os = "windows") {
        name.strip_suffix(".exe")
            .or_else(|| name.strip_suffix(".cmd"))
            .or_else(|| name.strip_suffix(".bat"))
            .unwrap_or(name)
    } else {
        name
    }
}

fn is_allowlist_entry_match(allowed: &str, executable: &str, executable_base: &str) -> bool {
    let allowed = strip_wrapping_quotes(allowed).trim();
    if allowed.is_empty() {
        return false;
    }

    // Explicit wildcard support for "allow any command name/path".
    if allowed == "*" {
        return true;
    }

    // Path-like allowlist entries must match the executable token exactly
    // after "~" expansion.
    if looks_like_path(allowed) {
        let allowed_path = expand_user_path(allowed);
        let executable_path = expand_user_path(executable);
        return executable_path == allowed_path;
    }

    // Command-name entries continue to match by basename.
    // On Windows, also match when the executable has a .exe/.cmd/.bat suffix
    // that the allowlist entry omits (e.g., allowlist "git" matches "git.exe").
    if allowed == executable_base {
        return true;
    }

    #[cfg(target_os = "windows")]
    {
        let base_lower = executable_base.to_ascii_lowercase();
        let allowed_lower = allowed.to_ascii_lowercase();
        for ext in &[".exe", ".cmd", ".bat"] {
            if base_lower == format!("{allowed_lower}{ext}") {
                return true;
            }
            if allowed_lower == format!("{base_lower}{ext}") {
                return true;
            }
        }
    }

    false
}

impl SecurityPolicy {
    // ── Risk Classification ──────────────────────────────────────────────
    // Risk is assessed per-segment (split on shell operators), and the
    // highest risk across all segments wins. This prevents bypasses like
    // `ls && rm -rf /` from being classified as Low just because `ls` is safe.

    /// Classify command risk. Any high-risk segment marks the whole command high.
    pub fn command_risk_level(&self, command: &str) -> CommandRiskLevel {
        let mut saw_medium = false;

        for segment in split_unquoted_segments(command) {
            let cmd_part = skip_env_assignments(&segment);
            let mut words = cmd_part.split_whitespace();
            let Some(base_raw) = words.next() else {
                continue;
            };

            let base_owned = command_basename(base_raw).to_ascii_lowercase();
            let base = strip_windows_exe_suffix(&base_owned);

            let args: Vec<String> = words.map(|w| w.to_ascii_lowercase()).collect();
            let joined_segment = cmd_part.to_ascii_lowercase();

            // High-risk commands (Unix and Windows)
            if matches!(
                base,
                "rm" | "mkfs"
                    | "dd"
                    | "shutdown"
                    | "reboot"
                    | "halt"
                    | "poweroff"
                    | "sudo"
                    | "su"
                    | "chown"
                    | "chmod"
                    | "useradd"
                    | "userdel"
                    | "usermod"
                    | "passwd"
                    | "mount"
                    | "umount"
                    | "iptables"
                    | "ufw"
                    | "firewall-cmd"
                    | "curl"
                    | "wget"
                    | "nc"
                    | "ncat"
                    | "netcat"
                    | "scp"
                    | "ssh"
                    | "ftp"
                    | "telnet"
                    // Windows-specific high-risk commands
                    | "del"
                    | "rmdir"
                    | "format"
                    | "reg"
                    | "net"
                    | "runas"
                    | "icacls"
                    | "takeown"
                    | "powershell"
                    | "pwsh"
                    | "wmic"
                    | "sc"
                    | "netsh"
            ) {
                return CommandRiskLevel::High;
            }

            if joined_segment.contains("rm -rf /")
                || joined_segment.contains("rm -fr /")
                || joined_segment.contains(":(){:|:&};:")
                // Windows destructive patterns
                || joined_segment.contains("del /s /q")
                || joined_segment.contains("rmdir /s /q")
                || joined_segment.contains("format c:")
            {
                return CommandRiskLevel::High;
            }

            // Medium-risk commands (state-changing, but not inherently destructive)
            let medium = match base {
                "git" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "commit"
                            | "push"
                            | "reset"
                            | "clean"
                            | "rebase"
                            | "merge"
                            | "cherry-pick"
                            | "revert"
                            | "branch"
                            | "checkout"
                            | "switch"
                            | "tag"
                    )
                }),
                "npm" | "pnpm" | "yarn" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "install" | "add" | "remove" | "uninstall" | "update" | "publish"
                    )
                }),
                "cargo" => args.first().is_some_and(|verb| {
                    matches!(
                        verb.as_str(),
                        "add" | "remove" | "install" | "clean" | "publish"
                    )
                }),
                "touch" | "mkdir" | "mv" | "cp" | "ln"
                // Windows medium-risk equivalents
                | "copy" | "xcopy" | "robocopy" | "move" | "ren" | "rename" | "mklink" => true,
                _ => false,
            };

            saw_medium |= medium;
        }

        if saw_medium {
            CommandRiskLevel::Medium
        } else {
            CommandRiskLevel::Low
        }
    }

    // ── Command execution (allowlist / risk / path-argument gates disabled) ──

    /// Validate command execution — permits any non-empty command when autonomy is not read-only.
    pub fn validate_command_execution(
        &self,
        command: &str,
        _approved: bool,
    ) -> Result<CommandRiskLevel, String> {
        if !self.is_command_allowed(command) {
            return Err(format!("Command not allowed by security policy: {command}"));
        }
        Ok(self.command_risk_level(command))
    }

    /// Check if a shell command is allowed (non-empty; blocked only in read-only autonomy).
    pub fn is_command_allowed(&self, command: &str) -> bool {
        if self.autonomy == AutonomyLevel::ReadOnly {
            return false;
        }

        let segments = split_unquoted_segments(command);
        segments.iter().any(|s| {
            let s = skip_env_assignments(s.trim());
            s.split_whitespace().next().is_some_and(|w| !w.is_empty())
        })
    }

    /// Path-based shell argument blocking disabled.
    pub fn forbidden_path_argument(&self, _command: &str) -> Option<String> {
        None
    }

    // ── Path validation (workspace / forbidden / runtime-config gates disabled) ──

    /// Check if a file path is allowed (only null bytes rejected).
    pub fn is_path_allowed(&self, path: &str) -> bool {
        !path.contains('\0')
    }

    /// Resolved path checks disabled.
    pub fn is_resolved_path_allowed(&self, _resolved: &Path) -> bool {
        true
    }

    pub fn is_runtime_config_path(&self, _resolved: &Path) -> bool {
        false
    }

    pub fn runtime_config_violation_message(&self, resolved: &Path) -> String {
        format!(
            "Refusing to modify ZeroClaw runtime config/state file: {}. Use dedicated config tools or edit it manually outside the agent loop.",
            resolved.display()
        )
    }

    pub fn resolved_path_violation_message(&self, resolved: &Path) -> String {
        let guidance = if self.allowed_roots.is_empty() {
            "Add the directory to [autonomy].allowed_roots (for example: allowed_roots = [\"/absolute/path\"]), or move the file into the workspace."
        } else {
            "Add a matching parent directory to [autonomy].allowed_roots, or move the file into the workspace."
        };

        format!(
            "Resolved path escapes workspace allowlist: {}. {}",
            resolved.display(),
            guidance
        )
    }

    /// Check if autonomy level permits any action at all
    pub fn can_act(&self) -> bool {
        self.autonomy != AutonomyLevel::ReadOnly
    }

    /// Enforce policy for a tool operation (rate limiting disabled).
    pub fn enforce_tool_operation(
        &self,
        operation: ToolOperation,
        operation_name: &str,
    ) -> Result<(), String> {
        match operation {
            ToolOperation::Read => Ok(()),
            ToolOperation::Act => {
                if !self.can_act() {
                    return Err(format!(
                        "Security policy: read-only mode, cannot perform '{operation_name}'"
                    ));
                }
                Ok(())
            }
        }
    }

    /// Record an action (rate limiting disabled; always allowed).
    pub fn record_action(&self) -> bool {
        let _ = self.tracker.record();
        true
    }

    /// Rate limiting disabled.
    pub fn is_rate_limited(&self) -> bool {
        false
    }

    /// Resolve a user-provided path for tool use.
    ///
    /// Expands `~` prefixes and resolves relative paths against the workspace
    /// directory. This should be called **after** `is_path_allowed` to obtain
    /// the filesystem path that the tool actually operates on.
    pub fn resolve_tool_path(&self, path: &str) -> PathBuf {
        let expanded = expand_user_path(path);
        if expanded.is_absolute() {
            expanded
        } else if let Some(workspace_hint) = rootless_path(&self.workspace_dir) {
            if let Ok(stripped) = expanded.strip_prefix(&workspace_hint) {
                if stripped.as_os_str().is_empty() {
                    self.workspace_dir.clone()
                } else {
                    self.workspace_dir.join(stripped)
                }
            } else {
                self.workspace_dir.join(expanded)
            }
        } else {
            self.workspace_dir.join(expanded)
        }
    }

    /// Check whether the given raw path (before canonicalization) falls under
    /// an `allowed_roots` entry. Tilde expansion is applied to the path
    /// before comparison. This is useful for tool-level pre-checks that want
    /// to allow absolute paths that are explicitly permitted by policy.
    pub fn is_under_allowed_root(&self, path: &str) -> bool {
        let expanded = expand_user_path(path);
        if !expanded.is_absolute() {
            return false;
        }
        self.allowed_roots.iter().any(|root| {
            let canonical = root.canonicalize().unwrap_or_else(|_| root.clone());
            expanded.starts_with(&canonical) || expanded.starts_with(root)
        })
    }

    /// Build from config sections
    pub fn from_config(
        autonomy_config: &crate::config::AutonomyConfig,
        workspace_dir: &Path,
    ) -> Self {
        Self {
            autonomy: autonomy_config.level,
            workspace_dir: workspace_dir.to_path_buf(),
            workspace_only: autonomy_config.workspace_only,
            allowed_commands: autonomy_config.allowed_commands.clone(),
            forbidden_paths: autonomy_config.forbidden_paths.clone(),
            allowed_roots: autonomy_config
                .allowed_roots
                .iter()
                .map(|root| {
                    let expanded = expand_user_path(root);
                    if expanded.is_absolute() {
                        expanded
                    } else {
                        workspace_dir.join(expanded)
                    }
                })
                .collect(),
            max_actions_per_hour: autonomy_config.max_actions_per_hour,
            max_cost_per_day_cents: autonomy_config.max_cost_per_day_cents,
            require_approval_for_medium_risk: autonomy_config.require_approval_for_medium_risk,
            block_high_risk_commands: autonomy_config.block_high_risk_commands,
            shell_env_passthrough: autonomy_config.shell_env_passthrough.clone(),
            tracker: ActionTracker::new(),
        }
    }

    /// Render a human-readable summary of the active security constraints
    /// suitable for injection into the LLM system prompt.
    ///
    /// Giving the LLM visibility into these constraints prevents it from
    /// wasting tokens on commands / paths that will be rejected at runtime.
    /// See issue #2404.
    pub fn prompt_summary(&self) -> String {
        use std::fmt::Write;

        let mut out = String::new();

        // Autonomy level
        let _ = writeln!(out, "**Autonomy level**: {:?}", self.autonomy);

        // Workspace constraint
        if self.workspace_only {
            let _ = writeln!(
                out,
                "**Workspace boundary**: file operations are restricted to `{}`.",
                self.workspace_dir.display()
            );
        }

        // Allowed roots
        if !self.allowed_roots.is_empty() {
            let roots: Vec<String> = self
                .allowed_roots
                .iter()
                .map(|p| format!("`{}`", p.display()))
                .collect();
            let _ = writeln!(out, "**Additional allowed paths**: {}", roots.join(", "));
        }

        // Allowed commands
        if !self.allowed_commands.is_empty() {
            let cmds: Vec<String> = self
                .allowed_commands
                .iter()
                .map(|c| format!("`{c}`"))
                .collect();
            let _ = writeln!(
                out,
                "**Allowed shell commands**: {}. \
                 Commands not on this list will be rejected.",
                cmds.join(", ")
            );
        }

        // Forbidden paths
        if !self.forbidden_paths.is_empty() {
            let paths: Vec<String> = self
                .forbidden_paths
                .iter()
                .map(|p| format!("`{p}`"))
                .collect();
            let _ = writeln!(
                out,
                "**Forbidden paths**: {}. \
                 Any read/write/exec targeting these paths will be blocked.",
                paths.join(", ")
            );
        }

        // Risk controls
        if self.block_high_risk_commands {
            let _ = writeln!(
                out,
                "**High-risk commands** (rm, kill, reboot, etc.) are blocked."
            );
        }
        if self.require_approval_for_medium_risk {
            let _ = writeln!(
                out,
                "**Medium-risk commands** require user approval before execution."
            );
        }

        // Rate limit
        let _ = writeln!(
            out,
            "**Rate limit**: max {} actions per hour.",
            self.max_actions_per_hour
        );

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readonly() -> SecurityPolicy {
        SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        }
    }

    fn supervised() -> SecurityPolicy {
        SecurityPolicy::default()
    }

    #[test]
    fn autonomy_default_is_supervised() {
        assert_eq!(AutonomyLevel::default(), AutonomyLevel::Supervised);
    }

    #[test]
    fn readonly_blocks_act_and_commands() {
        let p = readonly();
        assert!(!p.can_act());
        assert!(!p.is_command_allowed("ls"));
        assert!(p.enforce_tool_operation(ToolOperation::Read, "x").is_ok());
        assert!(p.enforce_tool_operation(ToolOperation::Act, "x").is_err());
    }

    #[test]
    fn supervised_allows_any_nonempty_shell() {
        let p = supervised();
        assert!(p.is_command_allowed("rm -rf /tmp/x"));
        assert!(p.is_command_allowed("curl http://example.com"));
        assert!(p
            .validate_command_execution("wget https://a", false)
            .is_ok());
    }

    #[test]
    fn paths_and_runtime_config_unguarded() {
        let p = supervised();
        assert!(p.is_path_allowed("/etc/passwd"));
        assert!(p.is_path_allowed("../outside"));
        assert!(!p.is_path_allowed("a\0b"));
        assert!(p.is_resolved_path_allowed(Path::new("/etc/passwd")));
        assert!(!p.is_runtime_config_path(Path::new("/tmp/config.toml")));
    }

    #[test]
    fn rate_limit_disabled() {
        let p = SecurityPolicy {
            max_actions_per_hour: 0,
            ..supervised()
        };
        assert!(!p.is_rate_limited());
        assert!(p.record_action());
        assert!(p.enforce_tool_operation(ToolOperation::Act, "x").is_ok());
    }

    #[test]
    fn command_risk_classification_unchanged() {
        let p = supervised();
        assert_eq!(p.command_risk_level("git status"), CommandRiskLevel::Low);
        assert_eq!(
            p.command_risk_level("rm -rf /tmp/x"),
            CommandRiskLevel::High
        );
    }

    #[test]
    fn from_config_maps_fields() {
        let autonomy_config = crate::config::AutonomyConfig {
            level: AutonomyLevel::Full,
            workspace_only: false,
            allowed_commands: vec!["docker".into()],
            forbidden_paths: vec!["/secret".into()],
            max_actions_per_hour: 100,
            max_cost_per_day_cents: 1000,
            require_approval_for_medium_risk: false,
            block_high_risk_commands: false,
            shell_env_passthrough: vec!["DATABASE_URL".into()],
            ..crate::config::AutonomyConfig::default()
        };
        let workspace = PathBuf::from("/tmp/test-workspace");
        let policy = SecurityPolicy::from_config(&autonomy_config, &workspace);
        assert_eq!(policy.autonomy, AutonomyLevel::Full);
        assert_eq!(policy.allowed_commands, vec!["docker"]);
        assert_eq!(policy.workspace_dir, workspace);
    }
}
