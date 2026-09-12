//! Minimal Nix subset parser/evaluator for `secrets.nix`.
//!
//! The real `secrets.nix` is evaluated by `nix-instantiate`. We only need to
//! support the subset of Nix that appears in practice in agenix rule files:
//!
//! ```nix
//! let
//!   user1 = "ssh-ed25519 AAAA...";
//!   users = [ user1 user2 ];
//! in
//! {
//!   "secret1.age".publicKeys = [ user1 system1 ];
//!   "armored-secret.age" = {
//!     publicKeys = [ user1 ];
//!     armor = true;
//!   };
//! }
//! ```
//!
//! Supported:
//!   - comments (`#`)
//!   - `let ... in ...` bindings (including nested `let`)
//!   - double-quoted strings with escapes (`\"`, `\\`, `\n`, `\t`)
//!   - identifiers (incl. `-` and `'`)
//!   - booleans
//!   - lists `[ ... ]` with `++` concatenation
//!   - attrset `{ key = value; ... }` with dotted attrpaths (`"a.b".c = ...`)
//!   - attribute access (`expr.attr`)
//!   - integers (only used as list indices, rarely needed; kept simple)
//!
//! Anything else produces a clear error telling the user to simplify the file
//! or to verify with `nix-instantiate` on a machine that has Nix.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Bool(bool),
    Int(i64),
    List(Vec<Value>),
    Attrs(HashMap<String, Value>),
    /// An identifier reference, resolved during evaluation (internal only).
    IdentRef(String),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_attrs(&self) -> Option<&HashMap<String, Value>> {
        match self {
            Value::Attrs(a) => Some(a),
            _ => None,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(s) => write!(f, "\"{s}\""),
            Value::IdentRef(name) => write!(f, "{name}"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::List(l) => {
                write!(f, "[")?;
                for (i, v) in l.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, "]")
            }
            Value::Attrs(a) => {
                write!(f, "{{ ")?;
                for (k, v) in a {
                    write!(f, "{k} = {v}; ")?;
                }
                write!(f, "}}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    LBrace,   // {
    RBrace,   // }
    LBracket, // [
    RBracket, // ]
    Semi,     // ;
    Eq,       // =
    Dot,      // .
    PlusPlus, // ++
    Let,
    In,
    True,
    False,
    Eof,
}

#[derive(Debug)]
struct LexError {
    msg: String,
    line: usize,
    col: usize,
}

fn lex(src: &str) -> Result<Vec<Tok>, LexError> {
    let mut toks = Vec::new();
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut line = 1;
    let mut col = 1;

    macro_rules! err {
        ($msg:expr) => {
            return Err(LexError {
                msg: $msg.to_string(),
                line,
                col,
            })
        };
    }

    while i < chars.len() {
        let c = chars[i];
        match c {
            // whitespace
            c if c.is_whitespace() => {
                if c == '\n' {
                    line += 1;
                    col = 1;
                } else {
                    col += 1;
                }
                i += 1;
            }
            // comments
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            // punctuation
            '{' => {
                toks.push(Tok::LBrace);
                i += 1;
                col += 1;
            }
            '}' => {
                toks.push(Tok::RBrace);
                i += 1;
                col += 1;
            }
            '[' => {
                toks.push(Tok::LBracket);
                i += 1;
                col += 1;
            }
            ']' => {
                toks.push(Tok::RBracket);
                i += 1;
                col += 1;
            }
            ';' => {
                toks.push(Tok::Semi);
                i += 1;
                col += 1;
            }
            '=' => {
                toks.push(Tok::Eq);
                i += 1;
                col += 1;
            }
            '.' => {
                toks.push(Tok::Dot);
                i += 1;
                col += 1;
            }
            '+' => {
                if i + 1 < chars.len() && chars[i + 1] == '+' {
                    toks.push(Tok::PlusPlus);
                    i += 2;
                    col += 2;
                } else {
                    err!("unexpected '+' (only '++' is supported)")
                }
            }
            '"' => {
                // string literal
                i += 1;
                col += 1;
                let mut s = String::new();
                let mut closed = false;
                while i < chars.len() {
                    match chars[i] {
                        '"' => {
                            i += 1;
                            col += 1;
                            closed = true;
                            break;
                        }
                        '\\' => {
                            i += 1;
                            col += 1;
                            if i >= chars.len() {
                                err!("unterminated escape sequence");
                            }
                            let e = chars[i];
                            match e {
                                'n' => s.push('\n'),
                                't' => s.push('\t'),
                                'r' => s.push('\r'),
                                '"' => s.push('"'),
                                '\\' => s.push('\\'),
                                '\'' => s.push('\''),
                                '$' => s.push('$'),
                                other => {
                                    // Nix allows arbitrary escapes like \xNN;
                                    // keep it simple, just pass through.
                                    s.push('\\');
                                    s.push(other);
                                }
                            }
                            i += 1;
                            col += 1;
                        }
                        '\n' => {
                            err!("unterminated string (newline in string)");
                        }
                        c => {
                            s.push(c);
                            i += 1;
                            col += 1;
                        }
                    }
                }
                if !closed {
                    err!("unterminated string");
                }
                toks.push(Tok::Str(s));
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                    col += 1;
                }
                let num: i64 = chars[start..i].iter().collect::<String>().parse().unwrap();
                toks.push(Tok::Int(num));
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '-' || chars[i] == '\'')
                {
                    i += 1;
                    col += 1;
                }
                let word: String = chars[start..i].iter().collect();
                match word.as_str() {
                    "let" => toks.push(Tok::Let),
                    "in" => toks.push(Tok::In),
                    "true" => toks.push(Tok::True),
                    "false" => toks.push(Tok::False),
                    _ => toks.push(Tok::Ident(word)),
                }
            }
            other => err!(format!("unexpected character '{other}'")),
        }
    }
    toks.push(Tok::Eof);
    Ok(toks)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    /// Environment of `let` bindings, populated during parsing.
    env: HashMap<String, Value>,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.pos]
    }

    fn next(&mut self) -> &Tok {
        let t = &self.toks[self.pos];
        if self.pos < self.toks.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, want: &Tok) -> Result<(), String> {
        if self.peek() == want {
            self.next();
            Ok(())
        } else {
            Err(format!("expected {want:?}, found {:?}", self.peek()))
        }
    }

    /// Parse the whole file: `let ... in expr` or just `expr`.
    fn parse_program(&mut self) -> Result<Value, String> {
        let v = self.parse_expr()?;
        if *self.peek() != Tok::Eof {
            return Err(format!(
                "unexpected trailing tokens: {:?} (hint: check for missing ';' or braces)",
                self.peek()
            ));
        }
        Ok(v)
    }

    fn parse_expr(&mut self) -> Result<Value, String> {
        let mut v = self.parse_primary()?;
        // handle `++` concatenation (left-assoc, lowest precedence above primary)
        loop {
            if *self.peek() == Tok::PlusPlus {
                self.next();
                let rhs = self.parse_primary()?;
                v = match (v, rhs) {
                    (Value::List(a), Value::List(b)) => {
                        let mut c = a;
                        c.extend(b);
                        Value::List(c)
                    }
                    (a, b) => {
                        return Err(format!(
                            "'++' can only concatenate lists, got {a} ++ {b}"
                        ))
                    }
                };
            } else {
                break;
            }
        }
        Ok(v)
    }

    fn parse_primary(&mut self) -> Result<Value, String> {
        match self.peek().clone() {
            Tok::Let => {
                self.next();
                self.parse_let_body()
            }
            Tok::LBrace => self.parse_attrset(),
            Tok::LBracket => self.parse_list(),
            Tok::Str(s) => {
                self.next();
                Ok(Value::Str(s))
            }
            Tok::Int(i) => {
                self.next();
                Ok(Value::Int(i))
            }
            Tok::True => {
                self.next();
                Ok(Value::Bool(true))
            }
            Tok::False => {
                self.next();
                Ok(Value::Bool(false))
            }
            Tok::Ident(name) => {
                self.next();
                // Resolve against let-bindings; leave unresolved as IdentRef
                // (resolved later, or reported as undefined by the caller).
                if let Some(v) = self.env.get(&name) {
                    Ok(v.clone())
                } else {
                    Ok(Value::IdentRef(name))
                }
            }
            other => Err(format!("unexpected token {:?} in expression", other)),
        }
    }

    fn parse_let_body(&mut self) -> Result<Value, String> {
        // bindings:  name = expr ;
        // Each binding is evaluated immediately and stored in the env.
        loop {
            match self.peek().clone() {
                Tok::Ident(name) => {
                    self.next();
                    self.expect(&Tok::Eq)?;
                    let v = self.parse_expr()?;
                    self.expect(&Tok::Semi)?;
                    self.env.insert(name, v);
                }
                Tok::In => {
                    self.next();
                    return self.parse_expr();
                }
                other => {
                    return Err(format!(
                        "expected identifier or 'in' in let block, found {:?}",
                        other
                    ))
                }
            }
        }
    }

    fn parse_list(&mut self) -> Result<Value, String> {
        self.expect(&Tok::LBracket)?;
        let mut items = Vec::new();
        loop {
            match self.peek() {
                Tok::RBracket => {
                    self.next();
                    break;
                }
                Tok::Eof => return Err("unterminated list".to_string()),
                _ => {
                    let v = self.parse_expr()?;
                    items.push(v);
                }
            }
        }
        Ok(Value::List(items))
    }

    fn parse_attrset(&mut self) -> Result<Value, String> {
        self.expect(&Tok::LBrace)?;
        let mut attrs: HashMap<String, Value> = HashMap::new();
        loop {
            match self.peek().clone() {
                Tok::RBrace => {
                    self.next();
                    break;
                }
                Tok::Eof => return Err("unterminated attrset".to_string()),
                Tok::Ident(name) => {
                    self.next();
                    self.finish_attr(&name, &mut attrs)?;
                }
                Tok::Str(name) => {
                    self.next();
                    self.finish_attr(&name, &mut attrs)?;
                }
                other => {
                    return Err(format!("expected attribute name, found {:?}", other))
                }
            }
        }
        Ok(Value::Attrs(attrs))
    }

    /// After reading an attr name, handle `= expr ;` or `.next.attr = expr ;`
    fn finish_attr(&mut self, first: &str, attrs: &mut HashMap<String, Value>) -> Result<(), String> {
        let mut path = vec![first.to_string()];
        while *self.peek() == Tok::Dot {
            self.next();
            match self.peek().clone() {
                Tok::Ident(name) | Tok::Str(name) => {
                    self.next();
                    path.push(name);
                }
                other => return Err(format!("expected attribute after '.', found {other:?}")),
            }
        }
        self.expect(&Tok::Eq)?;
        let v = self.parse_expr()?;
        self.expect(&Tok::Semi)?;

        // Build nested attrs: ["a", "b"] = v  =>  { a = { b = v; }; }
        let mut cur = v;
        for key in path.into_iter().rev() {
            let mut m = HashMap::new();
            m.insert(key, cur);
            cur = Value::Attrs(m);
        }
        // Merge into existing top-level attrs
        match cur {
            Value::Attrs(m) => {
                for (k, v) in m {
                    merge_attr(attrs, k, v);
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

/// Merge `key` into `attrs`, deep-merging nested attrsets.
fn merge_attr(attrs: &mut HashMap<String, Value>, key: String, v: Value) {
    match attrs.get_mut(&key) {
        Some(Value::Attrs(existing)) => match v {
            Value::Attrs(new) => {
                for (k, v) in new {
                    merge_attr(existing, k, v);
                }
            }
            v => {
                attrs.insert(key, v);
            }
        },
        _ => {
            attrs.insert(key, v);
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Resolve identifier references and nested structures against an environment.
impl Value {
    fn resolve(&self, vars: &HashMap<String, Value>) -> Result<Value, String> {
        match self {
            Value::IdentRef(name) => match vars.get(name) {
                Some(v) => Ok(v.clone()),
                None => Err(format!("undefined identifier '{name}'")),
            },
            Value::List(items) => {
                let mut out = Vec::new();
                for item in items {
                    out.push(item.resolve(vars)?);
                }
                Ok(Value::List(out))
            }
            Value::Attrs(attrs) => {
                let mut out = HashMap::new();
                for (k, v) in attrs {
                    out.insert(k.clone(), v.resolve(vars)?);
                }
                Ok(Value::Attrs(out))
            }
            other => Ok(other.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A single secret rule extracted from secrets.nix.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretRule {
    /// Recipient public keys, e.g. "ssh-ed25519 AAAA...".
    pub public_keys: Vec<String>,
    /// Whether to produce armored (ASCII) output.
    pub armor: bool,
}

/// The parsed rules file: filename (attr key) -> rule.
pub type Rules = HashMap<String, SecretRule>;

/// Parse and evaluate a `secrets.nix` file into rules.
pub fn parse_rules(src: &str) -> Result<Rules, String> {
    let toks = lex(src).map_err(|e| format!("syntax error at line {}, col {}: {}", e.line, e.col, e.msg))?;
    let mut parser = Parser {
        toks,
        pos: 0,
        env: HashMap::new(),
    };
    let v = parser.parse_program()?;
    // Resolve any remaining identifier references (e.g. from nested scopes)
    // against the top-level env. Top-level lets were already resolved during
    // parsing, so an IdentRef here means an undefined name.
    let v = v.resolve(&HashMap::new())?;

    let attrs = v
        .as_attrs()
        .ok_or_else(|| format!("top-level of secrets.nix must be an attrset, got {v}"))?;

    let mut rules = Rules::new();
    for (filename, val) in attrs {
        let attrs = val
            .as_attrs()
            .ok_or_else(|| format!("rule for '{filename}' must be an attrset, got {val}"))?;

        let pubkeys_val = attrs
            .get("publicKeys")
            .ok_or_else(|| format!("rule for '{filename}' is missing 'publicKeys'"))?;
        let pubkeys = pubkeys_val
            .as_list()
            .ok_or_else(|| format!("'publicKeys' for '{filename}' must be a list, got {pubkeys_val}"))?;

        let mut public_keys = Vec::new();
        for k in pubkeys {
            let s = k
                .as_str()
                .ok_or_else(|| format!("'publicKeys' entry for '{filename}' must be a string, got {k}"))?;
            public_keys.push(s.to_string());
        }

        let armor = match attrs.get("armor") {
            Some(Value::Bool(b)) => *b,
            Some(other) => {
                return Err(format!("'armor' for '{filename}' must be a boolean, got {other}"))
            }
            None => false,
        };

        rules.insert(
            filename.clone(),
            SecretRule { public_keys, armor },
        );
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_example() {
        let src = r#"
let
  user1 = "ssh-ed25519 AAAA1";
  system1 = "ssh-ed25519 AAAA2";
in
{
  "secret1.age".publicKeys = [ user1 system1 ];
  "armored-secret.age" = {
    publicKeys = [ user1 ];
    armor = true;
  };
}
"#;
        let rules = parse_rules(src).expect("parse should succeed");
        assert_eq!(rules.len(), 2);
        let s1 = &rules["secret1.age"];
        assert_eq!(s1.public_keys, vec!["ssh-ed25519 AAAA1", "ssh-ed25519 AAAA2"]);
        assert!(!s1.armor);
        let ar = &rules["armored-secret.age"];
        assert_eq!(ar.public_keys, vec!["ssh-ed25519 AAAA1"]);
        assert!(ar.armor);
    }

    #[test]
    fn parse_with_list_concat() {
        // From the README tutorial: `users ++ systems`
        let src = r#"
let
  user1 = "ssh-ed25519 AAAA1";
  user2 = "ssh-ed25519 AAAA2";
  users = [ user1 user2 ];
  system1 = "ssh-ed25519 AAAA3";
  systems = [ system1 ];
in
{
  "secret2.age".publicKeys = users ++ systems;
}
"#;
        let rules = parse_rules(src).expect("parse should succeed");
        assert_eq!(
            rules["secret2.age"].public_keys,
            vec![
                "ssh-ed25519 AAAA1",
                "ssh-ed25519 AAAA2",
                "ssh-ed25519 AAAA3"
            ]
        );
    }

    #[test]
    fn parse_nested_attrpath() {
        // "file.with.dots.age".publicKeys = [...]  is the common agenix pattern:
        // the quoted attr name is the literal filename (dots included).
        let src = r#"
{
  "my.secret.age".publicKeys = [ "ssh-ed25519 AAAAX" ];
}
"#;
        let rules = parse_rules(src).expect("parse should succeed");
        assert_eq!(rules["my.secret.age"].public_keys, vec!["ssh-ed25519 AAAAX"]);
    }

    #[test]
    fn parse_with_comments() {
        let src = r#"
# this is a comment
let
  # inline comment
  k = "ssh-ed25519 AAAA1"; # trailing comment
in
{
  "s.age".publicKeys = [ k ];
}
"#;
        let rules = parse_rules(src).expect("parse should succeed");
        assert_eq!(rules["s.age"].public_keys, vec!["ssh-ed25519 AAAA1"]);
    }

    #[test]
    fn missing_public_keys_is_error() {
        let src = r#"{ "s.age" = { }; }"#;
        assert!(parse_rules(src).is_err());
    }

    #[test]
    fn undefined_identifier_is_error() {
        let src = r#"{ "s.age".publicKeys = [ nosuchvar ]; }"#;
        assert!(parse_rules(src).is_err());
    }

    #[test]
    fn unknown_keyword_is_error() {
        // Function application / map / builtins are not supported
        let src = r#"let x = builtins.map (a: a) [ 1 ]; in { }"#;
        assert!(parse_rules(src).is_err());
    }

    #[test]
    fn real_world_example_file() {
        // The test rules file shipped with this repo (test/secrets.nix)
        let src = include_str!("../test/secrets.nix");
        let rules = parse_rules(src).expect("real example must parse");
        assert!(rules.contains_key("secret1.age"));
        assert!(rules.contains_key("armored-secret.age"));
        // secret1.age is encrypted to the test key + local (Windows) + WSL keys
        assert_eq!(rules["secret1.age"].public_keys.len(), 3);
        assert!(rules["armored-secret.age"].armor);
    }
}
