//! Rewrite rules: match/replace over the plaintext payload at the SSL
//! boundary, plus the Advise/Enforce mode switch.
//!
//! This is the standalone-process stand-in for the future TransformSpec
//! protocol (`RegisterRewriteRule` over UDS). The engine consumes a
//! [`RuleSet`]; Advise mode counts matches but never modifies memory.

use serde::{Deserialize, Serialize};

use crate::error::{Result, RewriteError};

/// Deployment mode of the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Observe only: hits are counted and logged, payloads pass through.
    Advise,
    /// Rewrite payloads matched by rules.
    Enforce,
}

/// One match/replace rule applied to the plaintext payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteRule {
    pub name: String,
    /// Rewrite when the payload contains this exact substring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_contains: Option<String>,
    /// Rewrite when the payload equals this string exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_equals: Option<String>,
    /// Replacement payload (variable length, both shorter and longer).
    pub replace: String,
}

impl RewriteRule {
    fn matches(&self, payload: &[u8]) -> bool {
        if let Ok(s) = std::str::from_utf8(payload) {
            if let Some(needle) = &self.match_contains {
                return s.contains(needle.as_str());
            }
            if let Some(exact) = &self.match_equals {
                return s == exact;
            }
        }
        false
    }
}

/// Ordered rule list + mode. First matching rule wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub mode: Mode,
    pub rules: Vec<RewriteRule>,
}

impl RuleSet {
    /// Parse a rule file (JSON).
    pub fn from_json(text: &str) -> Result<RuleSet> {
        let set: RuleSet =
            serde_json::from_str(text).map_err(|e| RewriteError::Config(e.to_string()))?;
        set.validate()?;
        Ok(set)
    }

    fn validate(&self) -> Result<()> {
        for r in &self.rules {
            if r.match_contains.is_none() && r.match_equals.is_none() {
                return Err(RewriteError::Config(format!(
                    "rule {:?} must set match_contains or match_equals",
                    r.name
                )));
            }
        }
        Ok(())
    }

    /// Apply the first matching rule. `None` means pass-through.
    pub fn apply(&self, payload: &[u8]) -> Option<Vec<u8>> {
        if self.mode != Mode::Enforce {
            return None;
        }
        self.rules
            .iter()
            .find(|r| r.matches(payload))
            .map(|r| r.replace.as_bytes().to_vec())
    }

    /// Compute in-place patches for the payload: byte offsets and equal-length
    /// replacement bytes. Returns `None` when no rule matches. This is the
    /// preferred rewrite mode on real runtimes: patching the matched substring
    /// at its actual position keeps the surrounding bytes (HTTP request line,
    /// headers, JSON structure) and the Content-Length framing intact, and
    /// needs no remote allocation.
    pub fn patches_in_place(&self, payload: &[u8]) -> Option<Vec<(usize, Vec<u8>)>> {
        if self.mode != Mode::Enforce {
            return None;
        }
        let text = std::str::from_utf8(payload).ok()?;
        let mut out = Vec::new();
        for r in &self.rules {
            let needle: &str = match (r.match_contains.as_deref(), r.match_equals.as_deref()) {
                (Some(n), _) => n,
                (None, Some(e)) => e,
                _ => continue,
            };
            let repl = r.replace.as_bytes();
            let mut from = 0usize;
            while let Some(pos) = text[from..].find(needle) {
                let at = from + pos;
                if repl.len() != needle.len() {
                    // Unequal length cannot be patched in place without
                    // breaking framing; skip to the next rule (the caller's
                    // remote-buffer mode handles variable length).
                    break;
                }
                out.push((at, repl.to_vec()));
                from = at + needle.len();
            }
            if !out.is_empty() {
                break; // first matching rule wins, consistent with `apply`
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    /// Whether a payload would match in Enforce mode (used for Advise logs).
    pub fn would_match(&self, payload: &[u8]) -> bool {
        self.rules.iter().any(|r| r.matches(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(mode: Mode) -> RuleSet {
        RuleSet {
            mode,
            rules: vec![
                RewriteRule {
                    name: "redact-secret".into(),
                    match_contains: Some("sk-secret123".into()),
                    match_equals: None,
                    replace: "[REDACTED]".into(),
                },
                RewriteRule {
                    name: "expand-ping".into(),
                    match_contains: None,
                    match_equals: Some("ping".into()),
                    replace: "ping-expanded-payload-longer-than-the-original".into(),
                },
            ],
        }
    }

    #[test]
    fn enforce_applies_first_matching_rule() {
        let s = set(Mode::Enforce);
        let out = s
            .apply(b"token: sk-secret123 do-not-leak")
            .expect("rewrite");
        assert_eq!(out, b"[REDACTED]");
        let out = s.apply(b"ping").expect("rewrite");
        assert!(out.len() > 4, "expansion rule produces longer payload");
        assert_eq!(s.apply(b"nothing here"), None);
    }

    #[test]
    fn patches_hit_exact_positions_and_keep_framing() {
        let s = RuleSet {
            mode: Mode::Enforce,
            rules: vec![RewriteRule {
                name: "mask".into(),
                match_contains: Some("sk-secret123".into()),
                match_equals: None,
                replace: "REDACTEDXXXX".into(), // exactly 12 = needle len
            }],
        };
        let payload = b"POST /x HTTP/1.1\r\n\r\n{\"c\":\"token: sk-secret123 do-not-leak\"}";
        let patches = s.patches_in_place(payload).expect("patches");
        let mut patched = payload.to_vec();
        for (at, bytes) in &patches {
            patched[*at..*at + bytes.len()].copy_from_slice(bytes);
        }
        let out = String::from_utf8(patched).unwrap_or_default();
        assert!(
            out.starts_with("POST /x HTTP/1.1"),
            "request line preserved"
        );
        assert!(out.contains("REDACTED"), "secret replaced in place");
        assert!(!out.contains("sk-secret123"));
        assert_eq!(payload.len(), out.len(), "equal length keeps framing");
        assert!(s.patches_in_place(b"clean").is_none());
    }

    #[test]
    fn unequal_length_patch_rejected_for_in_place() {
        let s = set(Mode::Enforce);
        // expansion rule alone cannot be patched in place
        let bare = RuleSet {
            mode: Mode::Enforce,
            rules: vec![RewriteRule {
                name: "expand".into(),
                match_contains: None,
                match_equals: Some("ping".into()),
                replace: "ping-longer".into(),
            }],
        };
        assert!(bare.patches_in_place(b"ping").is_none());
        let _ = s;
    }

    #[test]
    fn advise_never_rewrites_but_reports_matches() {
        let s = set(Mode::Advise);
        assert_eq!(s.apply(b"token: sk-secret123"), None);
        assert!(s.would_match(b"token: sk-secret123"));
        assert!(!s.would_match(b"clean"));
    }

    #[test]
    fn parses_json_rule_file() {
        let s = RuleSet::from_json(
            r#"{"mode":"advise","rules":[{"name":"a","match_contains":"x","replace":"y"}]}"#,
        )
        .expect("valid config");
        assert_eq!(s.mode, Mode::Advise);
        assert_eq!(s.rules.len(), 1);
    }

    #[test]
    fn rejects_rule_without_matcher() {
        let err = RuleSet::from_json(r#"{"mode":"enforce","rules":[{"name":"a","replace":"y"}]}"#);
        assert!(err.is_err());
    }

    #[test]
    fn rejects_unknown_mode() {
        assert!(RuleSet::from_json(r#"{"mode":"turbo","rules":[]}"#).is_err());
    }
}
