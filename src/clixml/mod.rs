//! CLIXML (MS-PSRP §2.2.5) — types and (de)serialization.
//!
//! This module owns every CLIXML value that `psrp-rs` can emit or parse.
//! Scope:
//!
//! * Full primitive set from MS-PSRP §2.2.5.1 — `<S>`, `<C>`, `<B>`,
//!   `<DT>`, `<TS>`, `<By>`/`<SB>`, `<U16>`/`<I16>`, `<U32>`/`<I32>`,
//!   `<U64>`/`<I64>`, `<Sg>`/`<Db>`, `<D>`, `<BA>`, `<G>`, `<URI>`,
//!   `<Version>`, `<XD>`, `<SBK>`, `<SS>`, `<Nil/>`.
//! * Complex types — `<Obj>` with member sets (`<MS>` / `<Props>`),
//!   `<LST>` / `<IE>` / `<QUE>` / `<STK>`, `<DCT>`.
//! * Reference resolution — `<Ref>` and `<TNRef>` look up previously
//!   seen ids in the current `parse_clixml` call.
//!
//! Unknown or unsupported XML is skipped on decode rather than failing.

pub(crate) mod decode;
pub(crate) mod encode;

pub use decode::{DEFAULT_MAX_DECODED_SIZE, MAX_NESTING_DEPTH, parse_clixml};
pub use encode::{RefIdAllocator, escape, ps_enum, ps_host_info_null, to_clixml};

use indexmap::IndexMap;
use uuid::Uuid;

/// A decoded CLIXML value.
///
/// Variants cover the full MS-PSRP primitive set plus complex types.
/// Integer, floating-point, and date/time types are distinct so that
/// round-tripping through PowerShell preserves the exact CLIXML tag.
///
/// `Debug` prints every variant as a derive would, except
/// [`SecureString`](Self::SecureString), whose content is never printed:
/// it reads `SecureString(<redacted>)`.
#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PsValue {
    /// `<Nil/>` or a missing value.
    Null,
    /// `<B>true</B>` / `<B>false</B>`.
    Bool(bool),
    /// `<SB>…</SB>` — signed byte.
    I8(i8),
    /// `<By>…</By>` — unsigned byte.
    U8(u8),
    /// `<I16>…</I16>`.
    I16(i16),
    /// `<U16>…</U16>`.
    U16(u16),
    /// `<I32>…</I32>`.
    I32(i32),
    /// `<U32>…</U32>`.
    U32(u32),
    /// `<I64>…</I64>`.
    I64(i64),
    /// `<U64>…</U64>`.
    U64(u64),
    /// `<Sg>…</Sg>` — single-precision float.
    F32(f32),
    /// `<Db>…</Db>` — double-precision float.
    Double(f64),
    /// `<D>…</D>` — .NET `Decimal`. Stored as its decimal string so
    /// we don't drag in another crate for high-precision arithmetic.
    Decimal(String),
    /// `<C>…</C>` — a .NET `[char]`, one UTF-16 code unit.
    ///
    /// A Rust `char` is a whole scalar value, so this variant holds only
    /// the characters of the Basic Multilingual Plane. On the wire a
    /// surrogate half (the two `[char]`s of an emoji) decodes to U+FFFD,
    /// and a `char` outside the plane is written as U+FFFD, as PowerShell
    /// would refuse the message otherwise. Use a [`PsValue::String`] to
    /// carry text.
    Char(char),
    /// `<S>…</S>` — UTF-8 string.
    String(String),
    /// `<BA>…</BA>` — byte array, transported as base64 on the wire.
    Bytes(Vec<u8>),
    /// `<DT>…</DT>` — .NET `DateTime` serialised as ISO-8601.
    ///
    /// Stored as a string so no date crate is needed. Use
    /// `chrono::DateTime::parse_from_rfc3339` on the callers' side to
    /// convert.
    DateTime(String),
    /// `<TS>…</TS>` — .NET `TimeSpan` serialised as
    /// `[-][d.]hh:mm:ss[.fffffff]` or an ISO-8601 duration.
    Duration(String),
    /// `<G>…</G>` — .NET `Guid`.
    Guid(Uuid),
    /// `<Version>…</Version>` — .NET `System.Version`.
    Version(String),
    /// `<URI>…</URI>` — `System.Uri`.
    Uri(String),
    /// `<XD>…</XD>` — `System.Xml.XmlDocument` or fragment.
    Xml(String),
    /// `<SBK>…</SBK>` — PowerShell script block source.
    ///
    /// The body is escaped like `<S>`, `_xHHHH_` escapes included. Over
    /// remoting a script block arrives on the server as a plain
    /// **string**, not a `ScriptBlock`: PowerShell never sets
    /// `DeserializationOptions.DeserializeScriptBlocks` there, so a
    /// parameter typed `[scriptblock]` has to rebuild it with
    /// `[scriptblock]::Create($s)`. The decoder also accepts `<SCT>`,
    /// which is not a PowerShell tag but what psrp-rs itself used to
    /// write.
    ScriptBlock(String),
    /// `<SS>…</SS>` — a `SecureString`.
    ///
    /// The string is the element's body as it travels: the codec never
    /// encrypts or decrypts it. PowerShell puts there the base64 of the
    /// value encrypted with the session key (AES-256-CBC, see
    /// [`SessionKey::encrypt_secure_string`](crate::crypto::SessionKey::encrypt_secure_string)),
    /// so, once [`request_session_key`](crate::RunspacePool::request_session_key)
    /// has negotiated that key:
    ///
    /// * a decoded `SecureString` holds that base64; turn it into the
    ///   plaintext with
    ///   [`decrypt_secure_string`](crate::RunspacePool::decrypt_secure_string);
    /// * to send one, put in the variant the base64 that
    ///   [`encrypt_secure_string`](crate::RunspacePool::encrypt_secure_string)
    ///   returns. The encoder writes whatever the variant holds, so a
    ///   plaintext put here crosses the wire in clear and PowerShell
    ///   cannot decrypt it.
    ///
    /// The `SecureString`s that a [`PsHost`](crate::PsHost) returns for
    /// `Read-Host -AsSecureString` or `Get-Credential` are the exception:
    /// the host returns the **plaintext** and the pool encrypts it with the
    /// session key before it answers, starting the key exchange itself if
    /// it has no key yet.
    SecureString(String),
    /// `<LST>` / `<IE>` / `<QUE>` / `<STK>`.
    List(Vec<PsValue>),
    /// `<DCT>` with `<En>` / `<Key>` / `<Value>` entries.
    Dict(Vec<(PsValue, PsValue)>),
    /// A wrapped `<Obj>` carrying a member set `<MS>`.
    Object(PsObject),
}

impl std::fmt::Debug for PsValue {
    /// What `#[derive(Debug)]` would print, `{:#?}` included, with the
    /// content of a `SecureString` left out: it is a secret in clear when a
    /// [`PsHost`](crate::PsHost) returned it, and values get printed (an
    /// `assert_eq!`, a `tracing` field, an error message built from an
    /// unexpected value).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn tuple(
            f: &mut std::fmt::Formatter<'_>,
            name: &str,
            field: &dyn std::fmt::Debug,
        ) -> std::fmt::Result {
            f.debug_tuple(name).field(field).finish()
        }
        match self {
            Self::Null => f.write_str("Null"),
            Self::Bool(v) => tuple(f, "Bool", v),
            Self::I8(v) => tuple(f, "I8", v),
            Self::U8(v) => tuple(f, "U8", v),
            Self::I16(v) => tuple(f, "I16", v),
            Self::U16(v) => tuple(f, "U16", v),
            Self::I32(v) => tuple(f, "I32", v),
            Self::U32(v) => tuple(f, "U32", v),
            Self::I64(v) => tuple(f, "I64", v),
            Self::U64(v) => tuple(f, "U64", v),
            Self::F32(v) => tuple(f, "F32", v),
            Self::Double(v) => tuple(f, "Double", v),
            Self::Decimal(v) => tuple(f, "Decimal", v),
            Self::Char(v) => tuple(f, "Char", v),
            Self::String(v) => tuple(f, "String", v),
            Self::Bytes(v) => tuple(f, "Bytes", v),
            Self::DateTime(v) => tuple(f, "DateTime", v),
            Self::Duration(v) => tuple(f, "Duration", v),
            Self::Guid(v) => tuple(f, "Guid", v),
            Self::Version(v) => tuple(f, "Version", v),
            Self::Uri(v) => tuple(f, "Uri", v),
            Self::Xml(v) => tuple(f, "Xml", v),
            Self::ScriptBlock(v) => tuple(f, "ScriptBlock", v),
            Self::SecureString(_) => tuple(f, "SecureString", &format_args!("<redacted>")),
            Self::List(v) => tuple(f, "List", v),
            Self::Dict(v) => tuple(f, "Dict", v),
            Self::Object(v) => tuple(f, "Object", v),
        }
    }
}

impl PsValue {
    /// Get a string if this value is one of the string-like variants
    /// (`String`, `Version`, `Uri`, `Xml`, `ScriptBlock`, `Decimal`,
    /// `DateTime`, `Duration`, `SecureString`).
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s)
            | Self::Version(s)
            | Self::Uri(s)
            | Self::Xml(s)
            | Self::ScriptBlock(s)
            | Self::Decimal(s)
            | Self::DateTime(s)
            | Self::Duration(s)
            | Self::SecureString(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Get an `i32` if this value is one of the signed integer variants,
    /// lossily narrowing where necessary.
    #[must_use]
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::I8(v) => Some(i32::from(*v)),
            Self::I16(v) => Some(i32::from(*v)),
            Self::I32(v) => Some(*v),
            Self::I64(v) => i32::try_from(*v).ok(),
            Self::U8(v) => Some(i32::from(*v)),
            Self::U16(v) => Some(i32::from(*v)),
            Self::U32(v) => i32::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Get an `i64` if this value is any integer variant.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I8(v) => Some(i64::from(*v)),
            Self::I16(v) => Some(i64::from(*v)),
            Self::I32(v) => Some(i64::from(*v)),
            Self::I64(v) => Some(*v),
            Self::U8(v) => Some(i64::from(*v)),
            Self::U16(v) => Some(i64::from(*v)),
            Self::U32(v) => Some(i64::from(*v)),
            Self::U64(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Get a `bool` if this value is one, else `None`.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Access the extended member set if this value is an object.
    #[must_use]
    pub fn properties(&self) -> Option<&IndexMap<String, PsValue>> {
        if let Self::Object(o) = self {
            Some(&o.properties)
        } else {
            None
        }
    }

    /// Return the type-names hierarchy if this is an object with a `<TN>`.
    #[must_use]
    pub fn type_names(&self) -> Option<&[String]> {
        if let Self::Object(o) = self {
            Some(&o.type_names)
        } else {
            None
        }
    }
}

/// A PSObject with named properties.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PsObject {
    /// Extended member set (`<MS>`), ordered.
    pub properties: IndexMap<String, PsValue>,
    /// Type hierarchy from `<TN>` (most-derived first), if any.
    pub type_names: Vec<String>,
    /// Optional `<ToString>` display representation.
    pub to_string: Option<String>,
}

impl PsObject {
    /// Create an empty object.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a property, returning `self` for builder chains.
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: PsValue) -> Self {
        self.properties.insert(name.into(), value);
        self
    }

    /// Attach a type-name hierarchy (most-derived first).
    #[must_use]
    pub fn with_type_names<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.type_names = names.into_iter().map(Into::into).collect();
        self
    }

    /// Look up a property by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PsValue> {
        self.properties.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_accessors() {
        assert_eq!(PsValue::String("hi".into()).as_str(), Some("hi"));
        assert_eq!(PsValue::Version("5.1".into()).as_str(), Some("5.1"));
        assert_eq!(PsValue::Uri("http://x".into()).as_str(), Some("http://x"));
        assert_eq!(PsValue::Decimal("1.5".into()).as_str(), Some("1.5"));
        assert_eq!(PsValue::I32(5).as_str(), None);
    }

    #[test]
    fn integer_accessors() {
        assert_eq!(PsValue::I8(-1).as_i32(), Some(-1));
        assert_eq!(PsValue::U8(255).as_i32(), Some(255));
        assert_eq!(PsValue::I16(-100).as_i32(), Some(-100));
        assert_eq!(PsValue::U16(65_535).as_i32(), Some(65_535));
        assert_eq!(PsValue::I32(42).as_i32(), Some(42));
        assert_eq!(PsValue::I64(i64::MAX).as_i32(), None);
        assert_eq!(PsValue::I64(42).as_i64(), Some(42));
        assert_eq!(PsValue::U64(u64::MAX).as_i64(), None);
        assert_eq!(PsValue::String("x".into()).as_i32(), None);
    }

    #[test]
    fn bool_accessor() {
        assert_eq!(PsValue::Bool(true).as_bool(), Some(true));
        assert_eq!(PsValue::I32(1).as_bool(), None);
    }

    #[test]
    fn object_accessors() {
        let obj = PsObject::new()
            .with("Name", PsValue::String("Alice".into()))
            .with_type_names(["Foo", "Bar"]);
        let v = PsValue::Object(obj);
        assert!(v.properties().is_some());
        assert_eq!(
            v.type_names(),
            Some(&["Foo".to_string(), "Bar".to_string()][..])
        );
        assert_eq!(
            v.properties()
                .unwrap()
                .get("Name")
                .and_then(PsValue::as_str),
            Some("Alice")
        );
        assert!(PsValue::Null.properties().is_none());
        assert!(PsValue::Null.type_names().is_none());
    }

    #[test]
    fn as_str_returns_none_for_non_string_variants() {
        assert_eq!(PsValue::I32(5).as_str(), None);
        assert_eq!(PsValue::Bool(true).as_str(), None);
        assert_eq!(PsValue::Null.as_str(), None);
        assert_eq!(PsValue::List(vec![]).as_str(), None);
        assert_eq!(PsValue::Double(1.0).as_str(), None);
    }

    #[test]
    fn as_str_covers_all_string_like_variants() {
        assert_eq!(PsValue::Xml("<r/>".into()).as_str(), Some("<r/>"));
        assert_eq!(PsValue::ScriptBlock("Get-X".into()).as_str(), Some("Get-X"));
        assert_eq!(
            PsValue::DateTime("2024-01-01".into()).as_str(),
            Some("2024-01-01")
        );
        assert_eq!(PsValue::Duration("P1D".into()).as_str(), Some("P1D"));
        assert_eq!(PsValue::SecureString("ss".into()).as_str(), Some("ss"));
    }

    #[test]
    fn as_i32_overflow_returns_none() {
        assert_eq!(PsValue::U32(u32::MAX).as_i32(), None);
        assert_eq!(PsValue::I64(i64::MAX).as_i32(), None);
        assert_eq!(PsValue::U64(100).as_i32(), None); // U64 not in match
    }

    #[test]
    fn as_i64_overflow_returns_none() {
        assert_eq!(PsValue::U64(u64::MAX).as_i64(), None);
        assert_eq!(PsValue::Bool(true).as_i64(), None);
        assert_eq!(PsValue::Null.as_i64(), None);
    }

    #[test]
    fn as_i64_covers_all_integer_variants() {
        assert_eq!(PsValue::I8(-1).as_i64(), Some(-1));
        assert_eq!(PsValue::U8(200).as_i64(), Some(200));
        assert_eq!(PsValue::I16(-1000).as_i64(), Some(-1000));
        assert_eq!(PsValue::U16(60000).as_i64(), Some(60000));
        assert_eq!(PsValue::U32(4_000_000_000).as_i64(), Some(4_000_000_000));
    }

    #[test]
    fn properties_and_type_names_on_non_objects() {
        assert!(PsValue::I32(1).properties().is_none());
        assert!(PsValue::String("x".into()).properties().is_none());
        assert!(PsValue::List(vec![]).properties().is_none());
        assert!(PsValue::I32(1).type_names().is_none());
        assert!(PsValue::String("x".into()).type_names().is_none());
        assert!(PsValue::Bool(false).type_names().is_none());
    }

    /// `Debug` is hand-written to keep a `SecureString` out of it; for every
    /// other variant it must read as the derive did.
    #[test]
    fn debug_reads_like_a_derive() {
        let guid = Uuid::nil();
        let cases: Vec<(PsValue, &str)> = vec![
            (PsValue::Null, "Null"),
            (PsValue::Bool(true), "Bool(true)"),
            (PsValue::I8(-1), "I8(-1)"),
            (PsValue::U8(1), "U8(1)"),
            (PsValue::I16(-2), "I16(-2)"),
            (PsValue::U16(2), "U16(2)"),
            (PsValue::I32(-3), "I32(-3)"),
            (PsValue::U32(3), "U32(3)"),
            (PsValue::I64(-4), "I64(-4)"),
            (PsValue::U64(4), "U64(4)"),
            (PsValue::F32(1.5), "F32(1.5)"),
            (PsValue::Double(2.5), "Double(2.5)"),
            (PsValue::Decimal("1.0".into()), r#"Decimal("1.0")"#),
            (PsValue::Char('c'), "Char('c')"),
            (PsValue::String("a\"b".into()), r#"String("a\"b")"#),
            (PsValue::Bytes(vec![1, 2]), "Bytes([1, 2])"),
            (PsValue::DateTime("d".into()), r#"DateTime("d")"#),
            (PsValue::Duration("t".into()), r#"Duration("t")"#),
            (
                PsValue::Guid(guid),
                "Guid(00000000-0000-0000-0000-000000000000)",
            ),
            (PsValue::Version("1.2".into()), r#"Version("1.2")"#),
            (PsValue::Uri("u".into()), r#"Uri("u")"#),
            (PsValue::Xml("<x/>".into()), r#"Xml("<x/>")"#),
            (PsValue::ScriptBlock("gci".into()), r#"ScriptBlock("gci")"#),
            (
                PsValue::List(vec![PsValue::Null, PsValue::I32(1)]),
                "List([Null, I32(1)])",
            ),
            (
                PsValue::Dict(vec![(PsValue::String("k".into()), PsValue::Bool(false))]),
                r#"Dict([(String("k"), Bool(false))])"#,
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(format!("{value:?}"), expected);
        }
        let object = PsValue::Object(PsObject::new().with("a", PsValue::I32(1)));
        assert_eq!(
            format!("{object:?}"),
            r#"Object(PsObject { properties: {"a": I32(1)}, type_names: [], to_string: None })"#
        );
        // The alternate form nests as a derive's does.
        assert_eq!(
            format!("{:#?}", PsValue::List(vec![PsValue::I32(1)])),
            "List(\n    [\n        I32(\n            1,\n        ),\n    ],\n)"
        );
    }

    /// Regression: `Debug` printed a `SecureString` like any string, and a
    /// [`PsHost`](crate::PsHost) returns its secrets in clear in that
    /// variant.
    #[test]
    fn debug_never_prints_a_secure_string() {
        let secret = || PsValue::SecureString("hunter2".into());
        assert_eq!(format!("{:?}", secret()), "SecureString(<redacted>)");
        assert_eq!(
            format!("{:#?}", secret()),
            "SecureString(\n    <redacted>,\n)"
        );

        let nested = PsValue::List(vec![
            PsValue::Dict(vec![(secret(), secret())]),
            PsValue::Object(
                PsObject::new()
                    .with("UserName", PsValue::String("alice".into()))
                    .with("Password", secret()),
            ),
        ]);
        for printed in [format!("{nested:?}"), format!("{nested:#?}")] {
            assert!(!printed.contains("hunter2"), "{printed}");
            assert_eq!(printed.matches("<redacted>").count(), 3, "{printed}");
            assert!(printed.contains("alice"), "{printed}");
        }
    }
}
