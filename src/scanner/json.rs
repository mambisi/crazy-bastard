//! Small, bounded JSON/JSONC reader and JSON writer used only by the scanner.
use std::{collections::BTreeMap, fmt, ops::Index};
const MAX_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}
impl Value {
    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        if let Self::Object(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        if let Self::Array(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.as_object()?.get(key)
    }
    pub fn pointer(&self, pointer: &str) -> Option<&Self> {
        let mut value = self;
        for key in pointer.strip_prefix('/')?.split('/') {
            value = value.get(key)?;
        }
        Some(value)
    }
}
impl Index<&str> for Value {
    type Output = Value;
    fn index(&self, k: &str) -> &Value {
        self.get(k).unwrap_or(&Value::Null)
    }
}
impl Index<usize> for Value {
    type Output = Value;
    fn index(&self, k: usize) -> &Value {
        self.as_array()
            .and_then(|v| v.get(k))
            .unwrap_or(&Value::Null)
    }
}
impl PartialEq<&str> for Value {
    fn eq(&self, v: &&str) -> bool {
        self.as_str() == Some(*v)
    }
}
impl PartialEq<i32> for Value {
    fn eq(&self, v: &i32) -> bool {
        matches!(self, Self::Number(n) if *n==v.to_string())
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Self::String(v.into())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}
impl From<usize> for Value {
    fn from(v: usize) -> Self {
        Self::Number(v.to_string())
    }
}
impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Self::Array(v)
    }
}
pub(super) fn object<const N: usize>(items: [(&str, Value); N]) -> Value {
    Value::Object(items.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(v) => write!(f, "{v}"),
            Self::Number(v) => f.write_str(v),
            Self::String(v) => quote(v, f),
            Self::Array(v) => {
                f.write_str("[")?;
                for (i, v) in v.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Self::Object(v) => {
                f.write_str("{")?;
                for (i, (k, v)) in v.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    quote(k, f)?;
                    write!(f, ":{v}")?;
                }
                f.write_str("}")
            }
        }
    }
}
fn quote(v: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("\"")?;
    for c in v.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            c if c.is_control()
                || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
            {
                write!(f, "\\u{:04x}", c as u32)?
            }
            _ => write!(f, "{c}")?,
        }
    }
    f.write_str("\"")
}

#[derive(Debug)]
pub struct ParseError;
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid, ambiguous or unbounded JSON")
    }
}
impl std::error::Error for ParseError {}
pub fn parse(bytes: &[u8], jsonc: bool) -> Result<Value, ParseError> {
    parse_inner(bytes, jsonc).map_err(|_| ParseError)
}
fn parse_inner(bytes: &[u8], jsonc: bool) -> Result<Value, ()> {
    if bytes.len() > MAX_BYTES {
        return Err(());
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut p = Parser {
        bytes,
        at: 0,
        jsonc,
        nodes: 0,
    };
    let value = p.value(0)?;
    p.space()?;
    if p.at != bytes.len() {
        return Err(());
    }
    Ok(value)
}
struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    jsonc: bool,
    nodes: usize,
}
impl Parser<'_> {
    fn space(&mut self) -> Result<(), ()> {
        loop {
            while self
                .bytes
                .get(self.at)
                .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
            {
                self.at += 1;
            }
            if !self.jsonc {
                return Ok(());
            }
            match self.bytes.get(self.at..self.at + 2) {
                Some(b"//") => {
                    self.at += 2;
                    while self.at < self.bytes.len() && self.bytes[self.at] != b'\n' {
                        self.at += 1;
                    }
                }
                Some(b"/*") => {
                    self.at += 2;
                    while self.at + 1 < self.bytes.len()
                        && &self.bytes[self.at..self.at + 2] != b"*/"
                    {
                        self.at += 1;
                    }
                    if self.at + 1 >= self.bytes.len() {
                        return Err(());
                    }
                    self.at += 2;
                }
                _ => return Ok(()),
            }
        }
    }
    fn take(&mut self, b: u8) -> bool {
        if self.bytes.get(self.at) == Some(&b) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, ()> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return Err(());
        }
        self.space()?;
        match self.bytes.get(self.at).copied().ok_or(())? {
            b'"' => Ok(Value::String(self.string()?)),
            b'{' => {
                self.at += 1;
                self.space()?;
                let mut map = BTreeMap::new();
                if self.take(b'}') {
                    return Ok(Value::Object(map));
                }
                loop {
                    self.space()?;
                    let key = self.string()?;
                    self.space()?;
                    if !self.take(b':') {
                        return Err(());
                    }
                    let value = self.value(depth + 1)?;
                    if map.insert(key, value).is_some() {
                        return Err(());
                    }
                    self.space()?;
                    if self.take(b'}') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(());
                    }
                    self.space()?;
                    if self.jsonc && self.take(b'}') {
                        break;
                    }
                }
                Ok(Value::Object(map))
            }
            b'[' => {
                self.at += 1;
                self.space()?;
                let mut values = Vec::new();
                if self.take(b']') {
                    return Ok(Value::Array(values));
                }
                loop {
                    values.push(self.value(depth + 1)?);
                    self.space()?;
                    if self.take(b']') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(());
                    }
                    self.space()?;
                    if self.jsonc && self.take(b']') {
                        break;
                    }
                }
                Ok(Value::Array(values))
            }
            b't' => {
                self.literal(b"true")?;
                Ok(Value::Bool(true))
            }
            b'f' => {
                self.literal(b"false")?;
                Ok(Value::Bool(false))
            }
            b'n' => {
                self.literal(b"null")?;
                Ok(Value::Null)
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(()),
        }
    }
    fn literal(&mut self, text: &[u8]) -> Result<(), ()> {
        if self.bytes.get(self.at..self.at + text.len()) != Some(text) {
            return Err(());
        }
        self.at += text.len();
        Ok(())
    }
    fn number(&mut self) -> Result<Value, ()> {
        let start = self.at;
        self.take(b'-');
        if !self.take(b'0') {
            if !self
                .bytes
                .get(self.at)
                .is_some_and(|b| matches!(b, b'1'..=b'9'))
            {
                return Err(());
            }
            self.digits();
        }
        if self.take(b'.') {
            let before = self.at;
            self.digits();
            if before == self.at {
                return Err(());
            }
        }
        if self.take(b'e') || self.take(b'E') {
            if !self.take(b'+') {
                self.take(b'-');
            }
            let before = self.at;
            self.digits();
            if before == self.at {
                return Err(());
            }
        }
        Ok(Value::Number(
            std::str::from_utf8(&self.bytes[start..self.at])
                .map_err(|_| ())?
                .to_owned(),
        ))
    }
    fn digits(&mut self) {
        while self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
            self.at += 1;
        }
    }
    fn hex(&mut self) -> Result<u32, ()> {
        let bytes = self.bytes.get(self.at..self.at + 4).ok_or(())?;
        if !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| ())?;
        let n = u32::from_str_radix(text, 16).map_err(|_| ())?;
        self.at += 4;
        Ok(n)
    }
    fn string(&mut self) -> Result<String, ()> {
        if !self.take(b'"') {
            return Err(());
        }
        let mut result = String::new();
        let mut start = self.at;
        loop {
            let b = *self.bytes.get(self.at).ok_or(())?;
            if b == b'"' || b == b'\\' {
                result.push_str(std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| ())?);
                self.at += 1;
                if b == b'"' {
                    return Ok(result);
                }
                let escape = *self.bytes.get(self.at).ok_or(())?;
                self.at += 1;
                let c = match escape {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{8}',
                    b'f' => '\u{c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => {
                        let first = self.hex()?;
                        let scalar = if (0xd800..=0xdbff).contains(&first) {
                            self.literal(b"\\u")?;
                            let second = self.hex()?;
                            if !(0xdc00..=0xdfff).contains(&second) {
                                return Err(());
                            }
                            0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                        } else {
                            first
                        };
                        char::from_u32(scalar).ok_or(())?
                    }
                    _ => return Err(()),
                };
                result.push(c);
                start = self.at;
            } else {
                if b < 0x20 {
                    return Err(());
                }
                self.at += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jsonc_preserves_strings_comments_trailing_commas_and_unicode() {
        let v=parse(br#"{/* comment */ "url":"https://example.invalid/a//b", "quote":"\"//", "list":[1,],"unicode":"\ud83d\ude00", // comment
        }"#,true).unwrap();
        assert_eq!(v["url"], "https://example.invalid/a//b");
        assert_eq!(v["quote"], "\"//");
        assert_eq!(v["list"][0], 1);
        assert_eq!(v["unicode"], "😀");
        assert_eq!(parse(v.to_string().as_bytes(), false).unwrap(), v);
    }
    #[test]
    fn ambiguous_malformed_and_unbounded_json_is_rejected() {
        for bytes in [
            br#"{"a":1,"\u0061":2}"#.as_slice(),
            b"{}{}",
            b"{/*",
            b"[1,,]",
            b"{\"tasks\":[,]}",
            b"{\"key\":,}",
            b"\xff",
            br#""\ud800""#,
            br#""\udc00""#,
            br#""\ud800\u0041""#,
            br#""\x01""#,
            br#""\u+001""#,
            b"01",
            b"-",
            b"1.",
            b"1e+",
            b"+1",
            b"[true false]",
            b"[\x0b]",
            b"\"\n\"",
        ] {
            assert!(parse(bytes, true).is_err(), "{bytes:?}");
        }
        for bytes in [b"{/*x*/}".as_slice(), b"[1,]", b"{\"a\":1,}"] {
            assert!(parse(bytes, false).is_err());
        }
        assert!(
            parse(
                format!("{}0{}", "[".repeat(100), "]".repeat(100)).as_bytes(),
                false
            )
            .is_err()
        );
        assert!(parse(&vec![b' '; MAX_BYTES + 1], false).is_err());
        assert!(
            parse(
                format!("[{}]", vec!["0"; MAX_NODES].join(",")).as_bytes(),
                false
            )
            .is_err()
        );
    }
    #[test]
    fn json_round_trips_all_ascii_controls_and_lossless_numbers() {
        let text: String = (0..=127).filter_map(char::from_u32).collect();
        let v = Value::String(text);
        assert_eq!(parse(v.to_string().as_bytes(), false).unwrap(), v);
        for n in [
            "0",
            "-0",
            "1.25e-10",
            "1E+99",
            "123456789012345678901234567890",
        ] {
            let v = parse(n.as_bytes(), false).unwrap();
            assert_eq!(v.to_string(), n);
        }
    }
}
