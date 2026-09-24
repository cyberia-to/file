//! Kind from magic bytes. Not a spark — just what the bytes look like.

/// What the bytes appear to be. Spark resolve starts here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    Json,
    ImagePng,
    ImageJpeg,
    ImageGif,
    ImageWebp,
    Opaque,
}

pub fn sniff(data: &[u8]) -> Kind {
    if data.len() >= 8 && data.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Kind::ImagePng;
    }
    if data.len() >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff {
        return Kind::ImageJpeg;
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Kind::ImageGif;
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Kind::ImageWebp;
    }
    if looks_like_text(data) {
        if looks_like_json(data) {
            return Kind::Json;
        }
        return Kind::Text;
    }
    Kind::Opaque
}

/// Whole-buffer structural check, not a parser: a single top-level `{...}`
/// or `[...]` with balanced, string-aware brackets and nothing but
/// whitespace outside them. An object also needs at least one quoted key
/// (unless it is empty), so ordinary prose that merely opens with `{`
/// does not sniff as JSON; a bare array of numbers still does, since
/// `[1, 2, 3]` has no string to require.
fn looks_like_json(data: &[u8]) -> bool {
    let s = match core::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let trimmed = s.trim_start();
    let first = match trimmed.as_bytes().first() {
        Some(b @ (b'{' | b'[')) => *b,
        _ => return false,
    };

    let mut stack: Vec<u8> = Vec::new();
    let mut in_string = false;
    let mut escape = false;
    let mut saw_string = false;
    let mut close_idx = None;

    for (i, c) in trimmed.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                saw_string = true;
            }
            '{' => stack.push(b'{'),
            '[' => stack.push(b'['),
            '}' => {
                if stack.pop() != Some(b'{') {
                    return false;
                }
            }
            ']' => {
                if stack.pop() != Some(b'[') {
                    return false;
                }
            }
            _ => {}
        }
        if stack.is_empty() && (c == '}' || c == ']') {
            close_idx = Some(i + c.len_utf8());
            break;
        }
    }

    let Some(close_idx) = close_idx else {
        return false;
    };
    if in_string || !trimmed[close_idx..].trim().is_empty() {
        return false;
    }
    let inner = trimmed[1..close_idx - 1].trim();
    if first == b'{' && !inner.is_empty() && !saw_string {
        return false;
    }
    true
}

fn looks_like_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    if core::str::from_utf8(data).is_err() {
        return false;
    }
    let mut weird = 0usize;
    for &b in data {
        if b < 0x09 || (b > 0x0d && b < 0x20 && b != 0x1b) {
            weird += 1;
        }
    }
    weird * 20 < data.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_with_string_key_is_json() {
        assert_eq!(sniff(br#"{"particle": "hemera", "n": 3}"#), Kind::Json);
    }

    #[test]
    fn nested_object_is_json() {
        assert_eq!(sniff(br#" { "a": [1, 2, {"b": "c\"d"}], "e": null} "#), Kind::Json);
    }

    #[test]
    fn empty_object_and_array_are_json() {
        assert_eq!(sniff(b"{}"), Kind::Json);
        assert_eq!(sniff(b"[]"), Kind::Json);
    }

    #[test]
    fn bare_numeric_array_is_json() {
        assert_eq!(sniff(b"[1, 2, 3]"), Kind::Json);
    }

    #[test]
    fn object_without_any_string_stays_text() {
        assert_eq!(sniff(b"{ this is not json, just a note }"), Kind::Text);
    }

    #[test]
    fn unbalanced_braces_stay_text() {
        assert_eq!(sniff(br#"{"a": 1"#), Kind::Text);
    }

    #[test]
    fn trailing_content_after_object_stays_text() {
        assert_eq!(sniff(br#"{"a": 1} and then some prose"#), Kind::Text);
    }

    #[test]
    fn plain_prose_stays_text() {
        assert_eq!(sniff(b"a line of words"), Kind::Text);
    }
}
