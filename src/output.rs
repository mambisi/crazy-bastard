use std::io::{self, Read, Write};
pub const MAX_OUTPUT: usize = 8 * 1024 * 1024;
pub fn escape(bytes: &[u8]) -> String {
    let mut output = String::new();
    for c in String::from_utf8_lossy(bytes).chars() {
        if (c.is_control() && c != '\n' && c != '\t')
            || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            output.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            output.push(c);
        }
    }
    output
}
pub fn relay(mut input: impl Read, mut output: impl Write) -> io::Result<()> {
    let mut total = 0;
    let mut buffer = [0u8; 8192];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            return Ok(());
        }
        total += n;
        if total > MAX_OUTPUT {
            return Err(io::Error::other("child output exceeded 8 MiB"));
        }
        output.write_all(escape(&buffer[..n]).as_bytes())?;
        output.flush()?;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_controls_become_visible_text() {
        let s = escape(b"\x1b]52;c;dGVzdA==\x07\rhello\n");
        for c in ['\x1b', '\x07', '\r'] {
            assert!(!s.contains(c));
        }
        assert!(s.contains("hello\n"));
    }
    #[test]
    fn bidi_controls_are_escaped() {
        assert_eq!(escape("a\u{202e}b".as_bytes()), "a\\u{202e}b");
    }
}
