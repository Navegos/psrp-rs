//! CLIXML decoder.
//!
//! Tolerant: unknown elements are skipped; a dangling `<Ref>` decodes to
//! [`PsValue::Null`]; leading whitespace / BOM / `<Objs>` wrappers are
//! accepted transparently.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, RandomState};

use quick_xml::Reader;
use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesStart, Event};

use super::{PsObject, PsValue};
use crate::error::{PsrpError, Result};

/// Parse a CLIXML fragment into a sequence of top-level values.
///
/// A single CLIXML body may contain several siblings (a PSRP `PipelineOutput`
/// message, for example, is one `<Obj>` at the top level — but a
/// `SessionCapability` message consists of an `<Obj>` with a `<MS>` of
/// primitive siblings, which this parser also handles).
///
/// # Limits
///
/// The document usually comes from a remote host, so what it may cost is
/// bounded, and passing a bound is a [`PsrpError::Clixml`]:
///
/// - nesting: [`MAX_NESTING_DEPTH`] levels;
/// - `<Ref>` and `<TNRef>` copies: in proportion to the length of the
///   document;
/// - memory: the values of one document may take
///   [`DEFAULT_MAX_DECODED_SIZE`] bytes. Decoding amplifies (a `<Nil/>` is
///   six bytes of XML and one [`PsValue`] in memory, some twenty times
///   more), so the length of the document bounds nothing: the decoder counts
///   what it builds, every value at its size in memory plus its text or
///   bytes, every property and type name, every copy a reference makes. The
///   count is an estimate (it ignores the spare capacity of collections),
///   charged as the document is read, so decoding stops at the limit, not
///   after the values have been built.
///
/// A [`RunspacePool`](crate::RunspacePool) applies the last one to each
/// pipeline as a whole, see [`ReceiveLimits`](crate::ReceiveLimits).
pub fn parse_clixml(xml: &str) -> Result<Vec<PsValue>> {
    parse_clixml_within(xml, &mut DecodeBudget::default())
}

/// Most memory the values decoded from one document, or by one pipeline, may
/// take by default: 1 GiB. [`parse_clixml`] says how it is counted.
pub const DEFAULT_MAX_DECODED_SIZE: usize = 1 << 30;

/// A cap on the memory taken by the values decoded against it, shared by the
/// documents of one pipeline. [`parse_clixml`] says what is counted.
#[derive(Debug, Clone)]
pub(crate) struct DecodeBudget {
    limit: u64,
    used: u64,
}

impl Default for DecodeBudget {
    /// [`DEFAULT_MAX_DECODED_SIZE`], none of it used.
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DECODED_SIZE)
    }
}

impl DecodeBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit: weight_of_len(limit),
            used: 0,
        }
    }

    /// A budget with the same limit and nothing used.
    fn unused(&self) -> Self {
        Self {
            limit: self.limit,
            used: 0,
        }
    }

    /// What the documents decoded so far were charged.
    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        usize::try_from(self.used).unwrap_or(usize::MAX)
    }
}

/// [`parse_clixml`] for a message that is read and dropped (a state, a host
/// call, a session key): it is bounded by the limit of `budget` on its own,
/// whatever is already used, and nothing is taken from it. Without this,
/// such a message would be decoded against the default gibibyte whatever
/// limit the caller had set; counted against what is left, the state that
/// ends a pipeline would be refused when its output had filled the budget.
pub(crate) fn parse_clixml_transient(xml: &str, budget: &DecodeBudget) -> Result<Vec<PsValue>> {
    parse_clixml_within(xml, &mut budget.unused())
}

/// [`parse_clixml`] against a budget shared with other documents: what this
/// one decodes to is taken from `budget`, and passing it is an error.
pub(crate) fn parse_clixml_within(xml: &str, budget: &mut DecodeBudget) -> Result<Vec<PsValue>> {
    let cleaned = xml.trim_start_matches('\u{FEFF}').trim_start();
    let mut reader = Reader::from_str(cleaned);
    reader.config_mut().trim_text(false);

    let mut state = DecoderState {
        budget: ref_budget(cleaned.len()),
        names_budget: type_names_budget(cleaned.len()),
        decoded: budget.used,
        decoded_limit: budget.limit,
        ..DecoderState::default()
    };
    state.note_referenced(cleaned)?;
    let mut out: Vec<PsValue> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                if let Some(value) = parse_element(&mut reader, &e, &mut state)? {
                    out.push(value);
                }
            }
            Event::Empty(e) => {
                if let Some(value) = parse_empty(&e, &mut state)? {
                    out.push(value);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    // The copies kept for a later `<Ref>` are released with `state`.
    budget.used = state.decoded.saturating_sub(state.kept);
    Ok(out)
}

/// Maximum `<Obj>` / `<LST>` / `<DCT>` nesting accepted from the wire.
///
/// The parser is recursive, and the document comes from the remote host:
/// without a cap, ~10 KiB of `<Obj><MS>` repeated is enough to overflow
/// the stack and **abort the process** — a stack overflow is not a
/// catchable panic, so `forbid(unsafe_code)` buys nothing here.
///
/// 64 was measured as the deepest level that still fits comfortably in
/// the 2 MiB stack of a Tokio worker thread in a debug build, and it is
/// an order of magnitude more than PowerShell's own serializer ever
/// emits (`Serialization.MaximumDepth` defaults to 1).
pub const MAX_NESTING_DEPTH: u32 = 64;

/// Floor, ceiling and per-byte allowance of the weight (see [`measure`]) that
/// the references of one document may materialize.
///
/// A reference is resolved by cloning the object it points to, so a server
/// can chain a few dozen objects that each hold two references to the
/// previous one: ~1 KiB of XML then expands to 2^n values and exhausts the
/// memory (the process aborts, it is not a catchable error). Legitimate
/// sharing grows with the document (a collection whose elements share one
/// object), hence an allowance per byte of XML on top of the floor, and the
/// ceiling keeps the worst case near a gigabyte (a value costs at most
/// ~112 bytes per unit of weight; text is cheaper).
const REF_BUDGET_FLOOR: u64 = 1 << 20;
const REF_BUDGET_CEILING: u64 = 8 << 20;
const REF_BUDGET_PER_BYTE: u64 = 8;

/// A length as a weight. `usize` fits `u64` on every supported target; the
/// saturation only makes the conversion total, and a saturated weight just
/// exhausts the budget sooner.
fn weight_of_len(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn ref_budget(xml_len: usize) -> u64 {
    type_names_budget(xml_len).min(REF_BUDGET_CEILING)
}

/// The weight (see [`type_names_weight`]) that the `<TNRef>`s of one document
/// may copy: the floor and the allowance per byte of the references, without
/// their ceiling.
///
/// PowerShell writes the type names of an object once and a `<TNRef>` in
/// every later object of that type, so a document of small typed objects
/// legitimately copies in proportion to its length, however long it is (a
/// `<TNRef>` to four names weighs about a hundred, in an object of at least
/// forty bytes). What is refused is the product: a long list stored once and
/// named by thousands of empty objects. The absolute bound on what a document
/// decodes to is [`DecodeBudget`], which these copies are charged to as well.
fn type_names_budget(xml_len: usize) -> u64 {
    REF_BUDGET_FLOOR.saturating_add(weight_of_len(xml_len).saturating_mul(REF_BUDGET_PER_BYTE))
}

/// The `RefId`s that some `<Ref>` of the document points to.
///
/// Only those objects are kept for a later reference, so that an object
/// nobody references is not cloned (once per enclosing object that has a
/// `RefId`, which is all of them in PowerShell's output).
///
/// A document may name millions of ids, each as long as the server likes,
/// so the set holds a hash of each, not its text. The hash is keyed per
/// document. Two ids with the same hash would only make the decoder keep
/// (and charge) an object nobody references.
#[derive(Default)]
struct Referenced {
    keys: RandomState,
    ids: HashSet<u64>,
}

impl Referenced {
    /// Note `id`; true when it was not there yet.
    fn insert(&mut self, id: &str) -> bool {
        self.ids.insert(self.keys.hash_one(id))
    }

    fn contains(&self, id: &str) -> bool {
        self.ids.contains(&self.keys.hash_one(id))
    }
}

/// What one id of [`Referenced`] is charged: its hash and its share of the
/// table.
const REFERENCED_ID_SIZE: u64 = 16;

#[derive(Default)]
struct DecoderState {
    /// Objects that a `<Ref>` points to, by `RefId` (see [`Referenced`]).
    refs: HashMap<String, PsValue>,
    referenced: Referenced,
    /// Weight materialized by references so far, bounded by `budget`.
    expanded: u64,
    budget: u64,
    /// Type-name lists stored by a `<TN RefId>`, for the `<TNRef>`s.
    type_names: HashMap<String, Vec<String>>,
    /// Weight copied by `<TNRef>`s so far, bounded by `names_budget`.
    names_expanded: u64,
    names_budget: u64,
    /// Current nesting level, maintained by [`parse_element`].
    depth: u32,
    /// Estimated memory of everything decoded so far, bounded by
    /// `decoded_limit` (see [`DecodeBudget`]).
    decoded: u64,
    decoded_limit: u64,
    /// The part of `decoded` that lives only as long as this state: the
    /// copies in `refs` and `type_names`.
    kept: u64,
}

impl DecoderState {
    /// Charge `weight` to the reference budget, or fail when it is spent.
    fn charge(&mut self, weight: u64) -> Result<()> {
        let expanded = self.expanded.saturating_add(weight);
        if expanded > self.budget {
            return Err(PsrpError::clixml(format!(
                "CLIXML <Ref> expansion exceeds {}",
                self.budget
            )));
        }
        self.expanded = expanded;
        Ok(())
    }

    /// Charge `weight` to the `<TNRef>` budget, or fail when it is spent.
    fn charge_names(&mut self, weight: u64) -> Result<()> {
        let expanded = self.names_expanded.saturating_add(weight);
        if expanded > self.names_budget {
            return Err(PsrpError::clixml(format!(
                "CLIXML <TNRef> expansion exceeds {}",
                self.names_budget
            )));
        }
        self.names_expanded = expanded;
        Ok(())
    }

    /// Count `bytes` more of decoded values, or fail when that passes the
    /// cap.
    fn charge_size(&mut self, bytes: u64) -> Result<()> {
        let decoded = self.decoded.saturating_add(bytes);
        if decoded > self.decoded_limit {
            return Err(PsrpError::clixml(format!(
                "CLIXML decodes to more than the {}-byte limit",
                self.decoded_limit
            )));
        }
        self.decoded = decoded;
        Ok(())
    }

    /// [`charge_size`](Self::charge_size) for a copy this state keeps for
    /// itself (in `refs`, `type_names` or `referenced`): counted while the
    /// document is decoded, given back to the caller's budget at the end.
    fn charge_kept(&mut self, bytes: u64) -> Result<()> {
        self.charge_size(bytes)?;
        self.kept = self.kept.saturating_add(bytes);
        Ok(())
    }

    /// Read the document once for the ids its `<Ref>`s point to (see
    /// [`Referenced`]), each charged as it is noted: the set is built before
    /// a single value is, from a document that may be nothing but `<Ref>`s.
    /// A malformed document ends the scan early; the real parse reports the
    /// error.
    fn note_referenced(&mut self, xml: &str) -> Result<()> {
        let mut reader = Reader::from_str(xml);
        let mut buf = Vec::new();
        while let Ok(event) = reader.read_event_into(&mut buf) {
            match event {
                Event::Start(e) | Event::Empty(e) if e.name().as_ref() == "Ref" => {
                    if let Ok(Some(id)) = ref_ref_id_attr(&e)
                        && self.referenced.insert(&id)
                    {
                        self.charge_kept(REFERENCED_ID_SIZE)?;
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }
        Ok(())
    }
}

/// What one [`PsValue`] takes inline, wherever it sits.
fn node_size() -> u64 {
    weight_of_len(std::mem::size_of::<PsValue>())
}

/// What a property costs besides its name and its value: the `String`
/// header, the hash and the index of its map entry.
const ENTRY_SIZE: u64 = 48;

/// What `v` takes by itself: its node, and its text or bytes. The children
/// of a container are not counted (they were when they were decoded).
fn own_size(v: &PsValue) -> u64 {
    let payload = match v {
        PsValue::String(s)
        | PsValue::Decimal(s)
        | PsValue::DateTime(s)
        | PsValue::Duration(s)
        | PsValue::Version(s)
        | PsValue::Uri(s)
        | PsValue::Xml(s)
        | PsValue::ScriptBlock(s)
        | PsValue::SecureString(s) => s.len(),
        PsValue::Bytes(b) => b.len(),
        PsValue::Object(o) => o.to_string.as_ref().map_or(0, String::len),
        _ => 0,
    };
    node_size().saturating_add(weight_of_len(payload))
}

/// What a property named `name` costs, its value aside.
fn entry_size(name: &str) -> u64 {
    ENTRY_SIZE.saturating_add(weight_of_len(name.len()))
}

/// What a list of type names costs: each one's text and `String` header.
fn type_names_size(names: &[String]) -> u64 {
    let header = weight_of_len(std::mem::size_of::<String>());
    names.iter().fold(0, |size: u64, name| {
        size.saturating_add(header)
            .saturating_add(weight_of_len(name.len()))
    })
}

/// What `v` takes with everything under it: the cost of a copy.
fn deep_size(v: &PsValue) -> u64 {
    let children = match v {
        PsValue::List(items) => items
            .iter()
            .fold(0, |size: u64, item| size.saturating_add(deep_size(item))),
        PsValue::Dict(entries) => entries.iter().fold(0, |size: u64, (key, value)| {
            size.saturating_add(deep_size(key))
                .saturating_add(deep_size(value))
        }),
        PsValue::Object(o) => {
            o.properties
                .iter()
                .fold(type_names_size(&o.type_names), |size, (name, value)| {
                    size.saturating_add(entry_size(name))
                        .saturating_add(deep_size(value))
                })
        }
        _ => 0,
    };
    own_size(v).saturating_add(children)
}

/// The weight of a list of type names, as [`measure`] counts it in an object:
/// one per name, plus its length.
fn type_names_weight(names: &[String]) -> u64 {
    names.iter().fold(0, |weight: u64, name| {
        weight
            .saturating_add(weight_of_len(name.len()))
            .saturating_add(1)
    })
}

/// The attributes of `e` that parse, in order, duplicates included.
///
/// quick-xml checks each attribute name against the earlier ones of its tag
/// unless told not to. Past 32 attributes it hashes the names, but a name it
/// has seen still costs a scan of all the earlier ones, and the iteration
/// goes on after the error: a tag of n different attributes followed by m
/// copies of the last cost n × m comparisons, hours of CPU for 20 MB of
/// attributes, inside one call that nothing can interrupt. Nothing here
/// needs the check: each reader takes the first attribute of the name it
/// wants, as it did when the copies were reported as errors and skipped.
fn attributes<'a>(e: &'a BytesStart<'_>) -> impl Iterator<Item = Attribute<'a>> {
    let mut attributes = e.attributes();
    attributes.with_checks(false);
    attributes.flatten()
}

/// Read the `N="…"` property-name attribute.
///
/// The value is XML-unescaped and then run through the PowerShell
/// `_xHHHH_` decoder, mirroring exactly what `encode::escape` did on the
/// way out. Skipping either step corrupts any property name containing
/// `&`, `<`, `>`, `"`, `'` or a control character — and because the
/// re-encoder escapes the result again, the damage compounds on every
/// hop (`&lt;` becomes `&amp;lt;` becomes `&amp;amp;lt;` …).
fn name_attr(e: &BytesStart) -> Result<Option<String>> {
    for attr in attributes(e) {
        if attr.key.as_ref() == "N" {
            let unescaped = attr
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(|err| PsrpError::clixml(err.to_string()))?;
            return Ok(Some(decode_pwsh_escapes(&unescaped)));
        }
    }
    Ok(None)
}

/// Read the `RefId="…"` attribute of an `<Obj>` / `<TN>`.
fn ref_id_attr(e: &BytesStart) -> Result<Option<String>> {
    for attr in attributes(e) {
        if attr.key.as_ref() == "RefId" {
            let unescaped = attr
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(|err| PsrpError::clixml(err.to_string()))?;
            return Ok(Some(unescaped.into_owned()));
        }
    }
    Ok(None)
}

/// Read the `RefId="…"` attribute of a `<Ref>` / `<TNRef>`.
fn ref_ref_id_attr(e: &BytesStart) -> Result<Option<String>> {
    ref_id_attr(e)
}

/// Resolve a `<Ref RefId="…"/>` against the objects decoded so far.
///
/// PowerShell writes a second occurrence of an object already serialized
/// in the same graph as exactly this self-closed element
/// (`WritePSObjectReference`), in a list item, a dictionary key or value,
/// a member or at the top level, so every one of those goes through here.
/// A reference with no `RefId`, or to an id not decoded yet (a dangling
/// one, or a cycle back to an object still being built), is `Null`.
///
/// The copy is bounded: by the reference budget over the whole document,
/// and so that, planted `level` containers below the current element, it
/// stays within [`MAX_NESTING_DEPTH`] (a chain of references would
/// otherwise build a value deep enough to overflow the stack of whatever
/// walks it next).
fn resolve_ref(e: &BytesStart, state: &mut DecoderState, level: u32) -> Result<PsValue> {
    let Some(id) = ref_ref_id_attr(e)? else {
        state.charge_size(node_size())?;
        return Ok(PsValue::Null);
    };
    let Some(((weight, height), size)) = state
        .refs
        .get(&id)
        .map(|target| (measure(target), deep_size(target)))
    else {
        state.charge_size(node_size())?;
        return Ok(PsValue::Null);
    };
    if state.depth.saturating_add(level).saturating_add(height) > MAX_NESTING_DEPTH {
        return Err(PsrpError::clixml(format!(
            "CLIXML <Ref> would nest deeper than {MAX_NESTING_DEPTH} levels"
        )));
    }
    // Charged before the copy is made: a copy that passes a budget is
    // refused without having been built.
    state.charge(weight)?;
    state.charge_size(size)?;
    Ok(state.refs.get(&id).cloned().unwrap_or(PsValue::Null))
}

/// Rough memory weight and container nesting of a decoded value.
///
/// Every node weighs 1, plus the length of its text or bytes and of the
/// names it carries; the height counts `Object` / `List` / `Dict` levels.
/// Both are over-estimates on purpose: they only bound a copy.
fn measure(v: &PsValue) -> (u64, u32) {
    match v {
        PsValue::String(s)
        | PsValue::Decimal(s)
        | PsValue::DateTime(s)
        | PsValue::Duration(s)
        | PsValue::Version(s)
        | PsValue::Uri(s)
        | PsValue::Xml(s)
        | PsValue::ScriptBlock(s)
        | PsValue::SecureString(s) => (weight_of_len(s.len()).saturating_add(1), 0),
        PsValue::Bytes(b) => (weight_of_len(b.len()).saturating_add(1), 0),
        PsValue::List(items) => items.iter().fold((1, 1), |(w, h), i| {
            let (iw, ih) = measure(i);
            (w.saturating_add(iw), h.max(ih.saturating_add(1)))
        }),
        PsValue::Dict(entries) => entries.iter().fold((1, 1), |(w, h), (k, val)| {
            let (kw, kh) = measure(k);
            let (vw, vh) = measure(val);
            (
                w.saturating_add(kw).saturating_add(vw),
                h.max(kh.max(vh).saturating_add(1)),
            )
        }),
        PsValue::Object(o) => {
            let mut weight = o
                .to_string
                .as_ref()
                .map_or(0, |s| weight_of_len(s.len()))
                .saturating_add(1);
            for t in &o.type_names {
                weight = weight
                    .saturating_add(weight_of_len(t.len()))
                    .saturating_add(1);
            }
            let mut height: u32 = 1;
            for (name, val) in &o.properties {
                let (vw, vh) = measure(val);
                weight = weight
                    .saturating_add(weight_of_len(name.len()))
                    .saturating_add(1)
                    .saturating_add(vw);
                height = height.max(vh.saturating_add(1));
            }
            (weight, height)
        }
        _ => (1, 0),
    }
}

fn parse_empty(e: &BytesStart, state: &mut DecoderState) -> Result<Option<PsValue>> {
    let value = match e.name().as_ref() {
        "Nil" => PsValue::Null,
        // Charged whole by `resolve_ref`.
        "Ref" => return resolve_ref(e, state, 1).map(Some),
        "S" => PsValue::String(String::new()),
        // PowerShell normally writes an empty value self-closed
        // (`<S N="x" />`, `<SBK N="x" />`: the .NET writer shortens an element
        // with no content), and `<S></S>` only when its output buffer happens
        // to flush before the end tag; both must decode.
        "SBK" | "SCT" => PsValue::ScriptBlock(String::new()),
        // `<ToString />` and anything unknown.
        _ => return Ok(None),
    };
    // Six bytes of XML are one value in memory: this is where a document of
    // `<Nil/>` is stopped.
    state.charge_size(node_size())?;
    Ok(Some(value))
}

/// The value of a dictionary slot, `Null` when the entry had none; that
/// `Null` is a value like the others and is charged as one.
fn or_null(slot: Option<PsValue>, state: &mut DecoderState) -> Result<PsValue> {
    if let Some(value) = slot {
        return Ok(value);
    }
    state.charge_size(node_size())?;
    Ok(PsValue::Null)
}

/// Add a property to `obj`, charging what its entry costs besides the value
/// (already charged when it was decoded).
fn insert_property(
    obj: &mut PsObject,
    name: String,
    value: PsValue,
    state: &mut DecoderState,
) -> Result<()> {
    state.charge_size(entry_size(&name))?;
    obj.properties.insert(name, value);
    Ok(())
}

/// Give `obj` the type names stored under `rid` by an earlier `<TN>`.
///
/// The list is copied into every object that names it, so the copy is
/// charged (see [`type_names_budget`]), and before it is made: a long list
/// stored once and named by thousands of empty objects used to cost the
/// product of the two, with nothing counted (45 KiB of XML for two million
/// strings).
fn apply_type_names_ref(
    obj: &mut PsObject,
    rid: Option<String>,
    state: &mut DecoderState,
) -> Result<()> {
    let Some(rid) = rid else {
        return Ok(());
    };
    let Some((weight, size)) = state
        .type_names
        .get(&rid)
        .map(|names| (type_names_weight(names), type_names_size(names)))
    else {
        return Ok(());
    };
    state.charge_names(weight)?;
    state.charge_size(size)?;
    if let Some(names) = state.type_names.get(&rid) {
        obj.type_names.clone_from(names);
    }
    Ok(())
}

fn parse_int<T>(reader: &mut Reader<&[u8]>, closing: &str) -> Result<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    let text = read_text(reader, closing)?;
    text.trim()
        .parse::<T>()
        .map_err(|err| PsrpError::clixml(format!("{closing}: {err}")))
}

fn parse_float(s: &str) -> std::result::Result<f64, String> {
    match s {
        "NaN" => Ok(f64::NAN),
        "Infinity" => Ok(f64::INFINITY),
        "-Infinity" => Ok(f64::NEG_INFINITY),
        other => other.parse::<f64>().map_err(|e| e.to_string()),
    }
}

/// Depth-guarded entry point for element parsing.
///
/// Every recursion cycle in this module passes through here
/// (`parse_element` → `parse_obj_body` → `parse_member_set` /
/// `parse_list` / `parse_dict` → `parse_element`), so one counter is
/// enough to bound them all.
fn parse_element(
    reader: &mut Reader<&[u8]>,
    e: &BytesStart,
    state: &mut DecoderState,
) -> Result<Option<PsValue>> {
    if state.depth >= MAX_NESTING_DEPTH {
        return Err(PsrpError::clixml(format!(
            "CLIXML nested deeper than {MAX_NESTING_DEPTH} levels"
        )));
    }
    // The guard above keeps `depth` below MAX_NESTING_DEPTH, so neither step
    // can saturate; saturating ops just keep the arithmetic total.
    state.depth = state.depth.saturating_add(1);
    let result = parse_element_inner(reader, e, state);
    state.depth = state.depth.saturating_sub(1);
    let value = result?;
    // Every value is charged here, by itself: what a container holds was
    // charged as it was decoded. A `<Ref>` is the exception, `resolve_ref`
    // charged its whole copy.
    if let Some(value) = &value
        && e.name().as_ref() != "Ref"
    {
        state.charge_size(own_size(value))?;
    }
    Ok(value)
}

fn parse_element_inner(
    reader: &mut Reader<&[u8]>,
    e: &BytesStart,
    state: &mut DecoderState,
) -> Result<Option<PsValue>> {
    let tag = e.name().as_ref().to_string();
    match tag.as_str() {
        "S" => {
            let text = read_text(reader, "S")?;
            Ok(Some(PsValue::String(text)))
        }
        "I32" => {
            let text = read_text(reader, "I32")?;
            let v = text
                .trim()
                .parse::<i32>()
                .map_err(|err| PsrpError::clixml(format!("I32: {err}")))?;
            Ok(Some(PsValue::I32(v)))
        }
        "I64" => {
            let text = read_text(reader, "I64")?;
            let v = text
                .trim()
                .parse::<i64>()
                .map_err(|err| PsrpError::clixml(format!("I64: {err}")))?;
            Ok(Some(PsValue::I64(v)))
        }
        "B" => {
            let text = read_text(reader, "B")?;
            let v = match text.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                other => return Err(PsrpError::clixml(format!("B: bad bool '{other}'"))),
            };
            Ok(Some(PsValue::Bool(v)))
        }
        "Db" => {
            let text = read_text(reader, "Db")?;
            let v =
                parse_float(text.trim()).map_err(|err| PsrpError::clixml(format!("Db: {err}")))?;
            Ok(Some(PsValue::Double(v)))
        }
        "Sg" => {
            let text = read_text(reader, "Sg")?;
            let v =
                parse_float(text.trim()).map_err(|err| PsrpError::clixml(format!("Sg: {err}")))?;
            // `f64` -> `f32` has no `From`/`TryFrom`; rounding to the nearest
            // `f32` (out-of-range magnitudes become infinity) is the intent.
            #[expect(
                clippy::as_conversions,
                reason = "intentional f64 to f32 narrowing: no lossless conversion exists and `as` is saturating/rounding, never UB"
            )]
            let narrowed = v as f32;
            Ok(Some(PsValue::F32(narrowed)))
        }
        "SB" => Ok(Some(PsValue::I8(parse_int(reader, "SB")?))),
        "By" => Ok(Some(PsValue::U8(parse_int(reader, "By")?))),
        "I16" => Ok(Some(PsValue::I16(parse_int(reader, "I16")?))),
        "U16" => Ok(Some(PsValue::U16(parse_int(reader, "U16")?))),
        "U32" => Ok(Some(PsValue::U32(parse_int(reader, "U32")?))),
        "U64" => Ok(Some(PsValue::U64(parse_int(reader, "U64")?))),
        "D" => {
            let text = read_text(reader, "D")?;
            Ok(Some(PsValue::Decimal(text.trim().to_string())))
        }
        "C" => {
            let text = read_text(reader, "C")?;
            // A `[char]` is one UTF-16 code unit on the wire
            // (`XmlConvert.ToString((UInt16)c)`), so half of an emoji comes
            // as `<C>55357</C>`: a surrogate is no `char`, and one of them
            // must not fail the whole document, so it reads as U+FFFD (as does
            // a number that is no scalar value at all). A scalar above the
            // plane is still read as that character: PowerShell would not
            // send it, but psrp-rs used to write `<C>128512</C>` for `'😀'`.
            let code: u32 = text
                .trim()
                .parse()
                .map_err(|err| PsrpError::clixml(format!("C: {err}")))?;
            Ok(Some(PsValue::Char(
                char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER),
            )))
        }
        "BA" => {
            let text = read_text(reader, "BA")?;
            let bytes = super::encode::base64_decode(text.trim())
                .ok_or_else(|| PsrpError::clixml("BA: invalid base64".to_string()))?;
            Ok(Some(PsValue::Bytes(bytes)))
        }
        "DT" => {
            let text = read_text(reader, "DT")?;
            Ok(Some(PsValue::DateTime(text)))
        }
        "TS" => {
            let text = read_text(reader, "TS")?;
            Ok(Some(PsValue::Duration(text)))
        }
        "G" => {
            let text = read_text(reader, "G")?;
            let uuid = uuid::Uuid::parse_str(text.trim())
                .map_err(|err| PsrpError::clixml(format!("G: {err}")))?;
            Ok(Some(PsValue::Guid(uuid)))
        }
        "Version" => {
            let text = read_text(reader, "Version")?;
            Ok(Some(PsValue::Version(text)))
        }
        "URI" => {
            let text = read_text(reader, "URI")?;
            Ok(Some(PsValue::Uri(text)))
        }
        "XD" => {
            let text = read_text(reader, "XD")?;
            Ok(Some(PsValue::Xml(text)))
        }
        // `SBK` is PowerShell's tag (MS-PSRP 2.2.5.1.23). `SCT` was never
        // one: it is what psrp-rs itself used to write, still accepted so
        // that such output decodes.
        "SBK" | "SCT" => {
            let text = read_text(reader, &tag)?;
            Ok(Some(PsValue::ScriptBlock(text)))
        }
        "SS" => {
            let text = read_text(reader, "SS")?;
            Ok(Some(PsValue::SecureString(text)))
        }
        "Obj" => {
            let ref_id = ref_id_attr(e)?;
            let obj = parse_obj_body(reader, state)?;
            let value = PsValue::Object(obj);
            if let Some(rid) = ref_id.filter(|r| state.referenced.contains(r)) {
                // A kept copy is memory too: it is charged like the others,
                // with the id it is kept under.
                state.charge(measure(&value).0)?;
                state.charge_kept(deep_size(&value).saturating_add(entry_size(&rid)))?;
                state.refs.insert(rid, value.clone());
            }
            // Flatten: if the object has no properties and no type names
            // but its inline LST/DCT was captured elsewhere we still report
            // the object as-is. Otherwise the caller uses `properties()`.
            Ok(Some(value))
        }
        "Ref" => {
            // The self-closed form is `parse_empty`'s; this is `<Ref ..>…</Ref>`.
            let value = resolve_ref(e, state, 0)?;
            skip_to_end(reader)?;
            Ok(Some(value))
        }
        _ => {
            // Unknown top-level element — skip.
            skip_to_end(reader)?;
            Ok(None)
        }
    }
}

fn parse_obj_body(reader: &mut Reader<&[u8]>, state: &mut DecoderState) -> Result<PsObject> {
    let mut obj = PsObject::new();
    let mut buf = Vec::new();
    let mut embedded: Option<PsValue> = None;
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => match e.name().as_ref() {
                "MS" | "Props" => {
                    parse_member_set(reader, state, &mut obj, e.name().as_ref().to_string())?;
                }
                "TN" => {
                    let rid = ref_id_attr(&e)?;
                    let names = parse_type_names(reader)?;
                    let size = type_names_size(&names);
                    state.charge_size(size)?;
                    if let Some(rid) = rid {
                        state.charge_kept(size.saturating_add(entry_size(&rid)))?;
                        state.type_names.insert(rid, names.clone());
                    }
                    obj.type_names = names;
                }
                "TNRef" => {
                    let rid = ref_ref_id_attr(&e)?;
                    skip_to_end(reader)?;
                    apply_type_names_ref(&mut obj, rid, state)?;
                }
                "LST" | "IE" | "QUE" | "STK" => {
                    let items = parse_list(reader, state, e.name().as_ref().to_string())?;
                    state.charge_size(node_size())?;
                    embedded = Some(PsValue::List(items));
                }
                "DCT" => {
                    let entries = parse_dict(reader, state)?;
                    state.charge_size(node_size())?;
                    embedded = Some(PsValue::Dict(entries));
                }
                // A nameless scalar child: the number of a .NET enum
                // (`<TN>…System.Enum…</TN><ToString>Monday</ToString>
                // <I32>1</I32>`). Anything else unknown is skipped.
                _ => {
                    if let Some(value) = parse_element(reader, &e, state)? {
                        embedded.get_or_insert(value);
                    }
                }
            },
            Event::Empty(e) => match e.name().as_ref() {
                "TNRef" => {
                    let rid = ref_ref_id_attr(&e)?;
                    apply_type_names_ref(&mut obj, rid, state)?;
                }
                "ToString" | "Nil" => {}
                _ => {}
            },
            Event::End(e) if e.name().as_ref() == "Obj" => break,
            Event::Eof => {
                return Err(PsrpError::clixml("unexpected EOF inside <Obj>"));
            }
            _ => {}
        }
        buf.clear();
    }

    // If the object had no <MS> but contained an embedded LST / DCT / scalar,
    // expose it under the synthetic property name "_value" so callers can
    // still retrieve it easily.
    if let Some(v) = embedded
        && obj.properties.is_empty()
    {
        insert_property(&mut obj, "_value".into(), v, state)?;
    }

    Ok(obj)
}

fn parse_member_set(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
    obj: &mut PsObject,
    closing_tag: String,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                let name = name_attr(&e)?.unwrap_or_default();
                if let Some(v) = parse_element(reader, &e, state)? {
                    insert_property(obj, name, v, state)?;
                }
            }
            Event::Empty(e) => match e.name().as_ref() {
                "Nil" => {
                    if let Some(name) = name_attr(&e)? {
                        state.charge_size(node_size())?;
                        insert_property(obj, name, PsValue::Null, state)?;
                    }
                }
                _ => {
                    if let Some(v) = parse_empty(&e, state)? {
                        let name = name_attr(&e)?.unwrap_or_default();
                        insert_property(obj, name, v, state)?;
                    }
                }
            },
            Event::End(e) if e.name().as_ref() == closing_tag.as_str() => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside member set")),
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_list(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
    closing_tag: String,
) -> Result<Vec<PsValue>> {
    let mut items = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                if let Some(v) = parse_element(reader, &e, state)? {
                    items.push(v);
                }
            }
            Event::Empty(e) => {
                if let Some(v) = parse_empty(&e, state)? {
                    items.push(v);
                }
            }
            Event::End(e) if e.name().as_ref() == closing_tag.as_str() => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside list")),
            _ => {}
        }
        buf.clear();
    }
    Ok(items)
}

fn parse_dict(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
) -> Result<Vec<(PsValue, PsValue)>> {
    let mut entries = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) if e.name().as_ref() == "En" => {
                let (k, v) = parse_dict_entry(reader, state)?;
                entries.push((k, v));
            }
            Event::End(e) if e.name().as_ref() == "DCT" => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside <DCT>")),
            _ => {}
        }
        buf.clear();
    }
    Ok(entries)
}

fn parse_dict_entry(
    reader: &mut Reader<&[u8]>,
    state: &mut DecoderState,
) -> Result<(PsValue, PsValue)> {
    let mut key = None;
    let mut val = None;
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) => {
                let name = name_attr(&e)?.unwrap_or_default();
                if let Some(v) = parse_element(reader, &e, state)? {
                    match name.as_str() {
                        "Key" => key = Some(v),
                        "Value" => val = Some(v),
                        _ => {}
                    }
                }
            }
            Event::Empty(e) => {
                if let Some(v) = parse_empty(&e, state)? {
                    match name_attr(&e)?.unwrap_or_default().as_str() {
                        "Key" => key = Some(v),
                        "Value" => val = Some(v),
                        _ => {}
                    }
                }
            }
            Event::End(e) if e.name().as_ref() == "En" => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside <En>")),
            _ => {}
        }
        buf.clear();
    }
    // An `<En></En>` is nine bytes of XML and two values in memory.
    Ok((or_null(key, state)?, or_null(val, state)?))
}

fn parse_type_names(reader: &mut Reader<&[u8]>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(e) if e.name().as_ref() == "T" => {
                let text = read_text(reader, "T")?;
                out.push(text);
            }
            Event::End(e) if e.name().as_ref() == "TN" => break,
            Event::Eof => return Err(PsrpError::clixml("EOF inside <TN>")),
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn read_text(reader: &mut Reader<&[u8]>, closing: &str) -> Result<String> {
    let mut out = String::new();
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Text(t) => {
                out.push_str(&t);
            }
            Event::GeneralRef(r) => {
                if let Some(c) = r
                    .resolve_char_ref()
                    .map_err(|e| PsrpError::clixml(e.to_string()))?
                {
                    out.push(c);
                } else {
                    let name: &str = r.as_ref();
                    match quick_xml::escape::resolve_predefined_entity(name) {
                        Some(s) => out.push_str(s),
                        None => {
                            return Err(PsrpError::clixml(format!(
                                "unknown entity reference &{name};"
                            )));
                        }
                    }
                }
            }
            Event::CData(c) => {
                out.push_str(c.as_ref());
            }
            Event::End(e) if e.name().as_ref() == closing => break,
            Event::Eof => {
                return Err(PsrpError::clixml(format!("EOF reading <{closing}>")));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(decode_pwsh_escapes(&out))
}

/// Drain everything up to the end tag that closes the current element.
///
/// Iterative on purpose — this is the escape hatch for *unknown*
/// elements, so it must stay bounded by the input size rather than by
/// the stack. The counter saturates instead of wrapping so that a
/// pathologically long run of start tags cannot overflow it.
fn skip_to_end(reader: &mut Reader<&[u8]>) -> Result<()> {
    let mut depth: usize = 1;
    let mut buf = Vec::new();
    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| PsrpError::clixml(e.to_string()))?
        {
            Event::Start(_) => depth = depth.saturating_add(1),
            Event::End(_) => {
                // `depth` starts at 1 and the loop exits at 0, so it is never
                // 0 here; saturating keeps the subtraction total.
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

/// Decode the `_xHHHH_` escapes PowerShell emits (`EncodeString`).
///
/// Each escape is one UTF-16 code unit, and a character outside the BMP is
/// written as the escapes of its surrogate pair (`_xD83D__xDE00_` is
/// U+1F600), so a run of consecutive escapes is decoded as UTF-16. A
/// surrogate without its other half becomes U+FFFD: .NET's
/// `XmlConvert.DecodeName` yields the lone code unit, which a Rust
/// `String` cannot hold.
///
/// An escape is exactly `_x`, four hex digits of either case, and `_`.
/// A leading `+` in place of the first digit is tolerated (`_x+041_` is
/// `A`, an accident of `from_str_radix` kept for compatibility). `_X` and
/// the eight-digit form `_xHHHHHHHH_`, which `DecodeName` also accepts
/// but PowerShell never emits, are left as text.
fn decode_pwsh_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut units: Vec<u16> = Vec::new();
    let mut rest = s;
    loop {
        if let Some((unit, tail)) = split_pwsh_escape(rest) {
            units.push(unit);
            rest = tail;
            continue;
        }
        // Not an escape: the run so far ends here. Decode it, then copy
        // the text up to the next `_`, the only character that can open
        // an escape (the first one goes whatever it is: it opens none).
        if !units.is_empty() {
            out.extend(
                char::decode_utf16(units.drain(..))
                    .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)),
            );
        }
        let mut chars = rest.chars();
        let Some(first) = chars.next() else {
            break;
        };
        let after = chars.as_str();
        let (text, tail) = after
            .split_at_checked(after.find('_').unwrap_or(after.len()))
            .unwrap_or((after, ""));
        out.push(first);
        out.push_str(text);
        rest = tail;
    }
    out
}

/// The code unit of the `_xHHHH_` escape that starts `s`, and the text
/// after it.
fn split_pwsh_escape(s: &str) -> Option<(u16, &str)> {
    let hex = s.get(..7)?.strip_prefix("_x")?.strip_suffix('_')?;
    let unit = u16::from_str_radix(hex, 16).ok()?;
    Some((unit, s.get(7..)?))
}

#[cfg(test)]
mod tests {
    /// Regression (found while fuzzing `clixml_decoder`): the parser is
    /// recursive and the document is attacker-controlled, so ~10 KiB of
    /// `<Obj><MS>` used to overflow the stack and abort the process.
    #[test]
    fn deep_nesting_is_rejected_not_fatal() {
        use super::super::parse_clixml;
        use super::MAX_NESTING_DEPTH;

        let deep = |n: usize| "<Obj><MS>".repeat(n) + "<Nil/>" + &"</MS></Obj>".repeat(n);

        // Comfortably inside the limit: still parses.
        parse_clixml(&deep(MAX_NESTING_DEPTH as usize / 2)).expect("shallow document");

        // Past it: a structured error, never a crash.
        let err = parse_clixml(&deep(MAX_NESTING_DEPTH as usize + 5))
            .expect_err("over-deep document must be rejected");
        assert!(
            err.to_string().contains("nested deeper"),
            "unexpected error: {err}"
        );

        // And the pathological case that used to abort the process.
        assert!(parse_clixml(&deep(20_000)).is_err());
    }

    // Regression (found by the `clixml_encode_decode` fuzz target):
    // attribute values used to be taken raw, so a property name holding
    // an XML metacharacter came back still escaped — and the encoder
    // then escaped it again on the next hop.
    #[test]
    fn property_names_are_xml_unescaped() {
        use super::super::{PsObject, PsValue, parse_clixml, to_clixml};

        let value = PsValue::Object(
            PsObject::new()
                .with("a<b", PsValue::I32(1))
                .with("x&y", PsValue::I32(2))
                .with("q\"r", PsValue::I32(3)),
        );

        let xml = to_clixml(&value);
        let decoded = parse_clixml(&xml).expect("decodes");
        assert_eq!(decoded[0], value, "property names were mangled");

        // And the damage must not compound across hops.
        let again = parse_clixml(&to_clixml(&decoded[0])).expect("decodes");
        assert_eq!(again[0], value);
    }

    #[test]
    fn property_names_decode_pwsh_escapes() {
        use super::super::{PsObject, PsValue, parse_clixml, to_clixml};

        // `escape` turns control characters in a name into `_xHHHH_`;
        // the decoder has to turn them back.
        let value = PsValue::Object(PsObject::new().with("a\u{1}b", PsValue::Null));
        let xml = to_clixml(&value);
        assert!(xml.contains("_x0001_"), "encoder did not escape: {xml}");
        let decoded = parse_clixml(&xml).expect("decodes");
        assert_eq!(decoded[0], value);
    }

    use super::super::encode::to_clixml;
    use super::*;

    #[test]
    fn primitives() {
        let cases = vec![
            ("<S>hi</S>", PsValue::String("hi".into())),
            ("<I32>-5</I32>", PsValue::I32(-5)),
            ("<I64>99</I64>", PsValue::I64(99)),
            ("<B>true</B>", PsValue::Bool(true)),
            ("<B>false</B>", PsValue::Bool(false)),
            ("<Db>1.5</Db>", PsValue::Double(1.5)),
            ("<Nil/>", PsValue::Null),
        ];
        for (xml, expected) in cases {
            let got = parse_clixml(xml).unwrap();
            assert_eq!(got.len(), 1, "{xml}");
            assert_eq!(got[0], expected, "{xml}");
        }
    }

    #[test]
    fn double_special_values() {
        assert!(
            matches!(parse_clixml("<Db>NaN</Db>").unwrap()[0], PsValue::Double(v) if v.is_nan())
        );
        assert!(matches!(
            parse_clixml("<Db>Infinity</Db>").unwrap()[0],
            PsValue::Double(v) if v.is_infinite() && v.is_sign_positive()
        ));
        assert!(matches!(
            parse_clixml("<Db>-Infinity</Db>").unwrap()[0],
            PsValue::Double(v) if v.is_infinite() && v.is_sign_negative()
        ));
    }

    #[test]
    fn bool_accepts_1_and_0() {
        assert_eq!(parse_clixml("<B>1</B>").unwrap()[0], PsValue::Bool(true));
        assert_eq!(parse_clixml("<B>0</B>").unwrap()[0], PsValue::Bool(false));
    }

    #[test]
    fn bad_bool_errors() {
        assert!(parse_clixml("<B>maybe</B>").is_err());
    }

    #[test]
    fn bad_int_errors() {
        assert!(parse_clixml("<I32>not-a-number</I32>").is_err());
        assert!(parse_clixml("<I64>xx</I64>").is_err());
        assert!(parse_clixml("<Db>oops</Db>").is_err());
    }

    #[test]
    fn escapes_and_bom() {
        let xml = "\u{FEFF}  <S>&lt;hi&amp;&gt;</S>";
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got[0], PsValue::String("<hi&>".into()));
    }

    #[test]
    fn pwsh_escape_decode() {
        let got = parse_clixml("<S>ab_x0001_cd</S>").unwrap();
        assert_eq!(got[0], PsValue::String("ab\u{0001}cd".into()));
    }

    /// Issue #18: PowerShell writes a character outside the BMP as the
    /// escapes of its two UTF-16 surrogates (`EncodeString`,
    /// serialization.cs), so 😀 arrives as `_xD83D__xDE00_`.
    #[test]
    fn surrogate_pair_escapes_decode_to_one_char() {
        let mut failures = Vec::new();
        for (escaped, expected) in [
            ("_xD83D__xDE00_", "\u{1F600}"),
            ("a_xD83D__xDE00_b", "a\u{1F600}b"),
            ("_xd83d__xde00_", "\u{1F600}"),
            ("_xD83D__xde00_", "\u{1F600}"),
            ("_xD83D__xDE00__xD83D__xDE01_", "\u{1F600}\u{1F601}"),
            ("_xD800__xDC00_", "\u{10000}"),
            ("_xDBFF__xDFFF_", "\u{10FFFF}"),
            // A lone surrogate: .NET would yield the bare code unit, which
            // a Rust `String` cannot hold, so it becomes U+FFFD.
            ("_xD83D_", "\u{FFFD}"),
            ("a_xD83D_b", "a\u{FFFD}b"),
            ("_xDE00_", "\u{FFFD}"),
            ("_xDE00__xD83D_", "\u{FFFD}\u{FFFD}"),
            ("_xD83D_x_xDE00_", "\u{FFFD}x\u{FFFD}"),
            ("_xD83D__x0041_", "\u{FFFD}A"),
            ("_xD83D__xD83D__xDE00_", "\u{FFFD}\u{1F600}"),
            ("_xD83D_xDE00_", "\u{FFFD}xDE00_"),
            // Unchanged around them.
            ("_x0041__x0042_", "AB"),
            // Deliberately preserves an existing quirk (`from_str_radix`
            // accepts a leading `+`; see the "Related" note of #18), so
            // that a future fix has to change this test on purpose.
            ("_x+041_", "A"),
            ("_X0041_", "_X0041_"),
        ] {
            let got = decode_pwsh_escapes(escaped);
            if got != expected {
                failures.push(format!("{escaped:?} -> {got:?}, expected {expected:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn surrogate_pair_escapes_decode_in_text_and_property_names() {
        let xml = r#"<Obj RefId="0"><MS><S N="k_xD83D__xDE00_">x_xD83D__xDE00_y</S><S N="_xDE00_">_xD83D_</S></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        let expected = PsValue::Object(
            PsObject::new()
                .with("k\u{1F600}", PsValue::String("x\u{1F600}y".into()))
                .with("\u{FFFD}", PsValue::String("\u{FFFD}".into())),
        );
        assert_eq!(got, vec![expected]);
    }

    /// The encoder writes non-BMP characters as literal UTF-8, and escapes
    /// a literal `_x`, so they still come back exactly.
    #[test]
    fn non_bmp_characters_round_trip() {
        for text in [
            "\u{1F600}",
            "a\u{1F600}b\u{10000}\u{10FFFF}",
            "\u{1F600}_xD83D_",
            "_xD83D__xDE00_",
            "\u{FFFD}",
        ] {
            let value = PsValue::Object(PsObject::new().with(text, PsValue::String(text.into())));
            let xml = to_clixml(&value);
            assert_eq!(
                parse_clixml(&xml).unwrap(),
                vec![value],
                "{text:?} via {xml}"
            );
        }
    }

    #[test]
    fn object_with_member_set() {
        let xml = r#"<Obj RefId="0"><TN RefId="0"><T>System.Diagnostics.Process</T></TN><MS><S N="Name">svchost</S><I32 N="Id">42</I32><Nil N="Maybe"/></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 1);
        let obj = match &got[0] {
            PsValue::Object(o) => o,
            _ => panic!("expected object"),
        };
        assert_eq!(
            obj.type_names,
            vec!["System.Diagnostics.Process".to_string()]
        );
        assert_eq!(obj.get("Name"), Some(&PsValue::String("svchost".into())));
        assert_eq!(obj.get("Id"), Some(&PsValue::I32(42)));
        assert_eq!(obj.get("Maybe"), Some(&PsValue::Null));
    }

    #[test]
    fn object_with_list_and_dict() {
        let xml = r#"<Obj RefId="0"><LST><I32>1</I32><I32>2</I32></LST></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        let obj = match &got[0] {
            PsValue::Object(o) => o,
            _ => panic!("expected object"),
        };
        assert_eq!(
            obj.get("_value"),
            Some(&PsValue::List(vec![PsValue::I32(1), PsValue::I32(2)]))
        );
    }

    #[test]
    fn tnref_resolution() {
        // Outer object defines TN with RefId=0. Inner object references it via TNRef.
        let xml = r#"
          <Obj RefId="0"><TN RefId="0"><T>Foo</T></TN><MS><S N="k">v</S></MS></Obj>
          <Obj RefId="1"><TNRef RefId="0"/><MS><I32 N="n">7</I32></MS></Obj>
        "#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 2);
        if let PsValue::Object(o) = &got[1] {
            assert_eq!(o.type_names, vec!["Foo".to_string()]);
            assert_eq!(o.get("n"), Some(&PsValue::I32(7)));
        } else {
            panic!();
        }
    }

    #[test]
    fn ref_resolution() {
        let xml = r#"<Obj RefId="abc"><MS><S N="k">v</S></MS></Obj><Ref RefId="abc"/>"#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], got[1]);
    }

    #[test]
    fn dangling_ref_becomes_null() {
        let got = parse_clixml(r#"<Ref RefId="missing"/>"#).unwrap();
        assert_eq!(got[0], PsValue::Null);
    }

    #[test]
    fn unknown_elements_are_skipped() {
        let xml =
            r#"<Obj RefId="0"><UnknownThing><nested/></UnknownThing><MS><S N="k">v</S></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert_eq!(o.get("k"), Some(&PsValue::String("v".into())));
        } else {
            panic!();
        }
    }

    #[test]
    fn roundtrip_complex_object() {
        let obj = PsObject {
            type_names: vec!["Foo".into(), "Bar".into()],
            to_string: None,
            properties: {
                let mut p = indexmap::IndexMap::new();
                p.insert("name".into(), PsValue::String("n".into()));
                p.insert("count".into(), PsValue::I32(3));
                p.insert("flag".into(), PsValue::Bool(true));
                p.insert("empty".into(), PsValue::Null);
                p.insert(
                    "tags".into(),
                    PsValue::List(vec![
                        PsValue::String("a".into()),
                        PsValue::String("b".into()),
                    ]),
                );
                p
            },
        };
        let xml = to_clixml(&PsValue::Object(obj.clone()));
        let got = parse_clixml(&xml).unwrap();
        let got_obj = match &got[0] {
            PsValue::Object(o) => o,
            _ => panic!(),
        };
        assert_eq!(got_obj.type_names, obj.type_names);
        assert_eq!(got_obj.get("name"), obj.properties.get("name"));
        assert_eq!(got_obj.get("count"), obj.properties.get("count"));
        assert_eq!(got_obj.get("flag"), obj.properties.get("flag"));
        assert_eq!(got_obj.get("empty"), Some(&PsValue::Null));
        // Embedded list comes back as an object whose _value is the list.
        if let Some(PsValue::Object(tags_obj)) = got_obj.get("tags") {
            assert_eq!(
                tags_obj.get("_value"),
                Some(&PsValue::List(vec![
                    PsValue::String("a".into()),
                    PsValue::String("b".into())
                ]))
            );
        } else {
            panic!("expected tags to be an object wrapping a list");
        }
    }

    #[test]
    fn cdata_section_decoded() {
        let got = parse_clixml("<S><![CDATA[hello & <world>]]></S>").unwrap();
        assert_eq!(got[0], PsValue::String("hello & <world>".into()));
    }

    #[test]
    fn top_level_ref_with_content_resolves() {
        // Non-self-closing `<Ref RefId="..">…</Ref>` at top level.
        let xml = r#"<Obj RefId="a"><MS><S N="k">v</S></MS></Obj><Ref RefId="a">ignored</Ref>"#;
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], got[1]);
    }

    #[test]
    fn empty_obj_body_produces_empty_object() {
        let got = parse_clixml("<Obj RefId=\"0\"></Obj>").unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert!(o.properties.is_empty());
            assert!(o.type_names.is_empty(), "{:?}", o.type_names);
        } else {
            panic!();
        }
    }

    #[test]
    fn props_element_is_treated_like_ms() {
        let xml = r#"<Obj RefId="0"><Props><S N="k">v</S></Props></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert_eq!(o.get("k"), Some(&PsValue::String("v".into())));
        } else {
            panic!();
        }
    }

    #[test]
    fn pwsh_escape_roundtrip() {
        assert_eq!(decode_pwsh_escapes("_x0041_BC"), "ABC");
        assert_eq!(decode_pwsh_escapes("no escapes here"), "no escapes here");
        assert_eq!(
            decode_pwsh_escapes("_xZZZZ_"),
            "_xZZZZ_",
            "invalid hex passes through"
        );
        assert_eq!(
            decode_pwsh_escapes("café"),
            "café",
            "multi-byte chars preserved"
        );
    }

    #[test]
    fn extended_primitives() {
        // SB (i8), By (u8), I16, U16, U32, U64
        let cases: Vec<(&str, PsValue)> = vec![
            ("<SB>-128</SB>", PsValue::I8(-128)),
            ("<By>255</By>", PsValue::U8(255)),
            ("<I16>-32000</I16>", PsValue::I16(-32000)),
            ("<U16>65535</U16>", PsValue::U16(65535)),
            ("<U32>4000000000</U32>", PsValue::U32(4_000_000_000)),
            ("<U64>18446744073709551615</U64>", PsValue::U64(u64::MAX)),
        ];
        for (xml, expected) in cases {
            let got = parse_clixml(xml).unwrap();
            assert_eq!(got.len(), 1, "{xml}");
            assert_eq!(got[0], expected, "{xml}");
        }
    }

    #[test]
    fn extended_primitive_errors() {
        assert!(parse_clixml("<SB>not_int</SB>").is_err());
        assert!(parse_clixml("<By>-1</By>").is_err());
        assert!(parse_clixml("<I16>99999</I16>").is_err());
        assert!(parse_clixml("<U16>-1</U16>").is_err());
        assert!(parse_clixml("<U32>-1</U32>").is_err());
        assert!(parse_clixml("<U64>not_a_number</U64>").is_err());
    }

    #[test]
    fn char_primitive() {
        let got = parse_clixml("<C>65</C>").unwrap();
        assert_eq!(got[0], PsValue::Char('A'));
    }

    #[test]
    fn char_invalid_code_point() {
        // Not a number
        assert!(parse_clixml("<C>abc</C>").is_err());
        assert!(parse_clixml("<C>-1</C>").is_err());
        assert!(parse_clixml("<C>4294967296</C>").is_err());
    }

    /// Older psrp-rs wrote `'😀'` as `<C>128512</C>`; it is still read back as
    /// that character, and a number that is no scalar value is U+FFFD.
    #[test]
    fn char_above_the_bmp_is_still_read_leniently() {
        assert_eq!(
            parse_clixml("<C>65536</C><C>128512</C><C>1114111</C><C>1114112</C><C>4294967295</C>")
                .unwrap(),
            vec![
                PsValue::Char('\u{10000}'),
                PsValue::Char('\u{1F600}'),
                PsValue::Char('\u{10FFFF}'),
                PsValue::Char('\u{FFFD}'),
                PsValue::Char('\u{FFFD}'),
            ]
        );
    }

    /// `"😀".ToCharArray()` is `<C>55357</C><C>56832</C>`: a lone surrogate
    /// is U+FFFD, wherever it sits, and does not cost the rest of the
    /// document (the whole `run` used to fail on it).
    #[test]
    fn char_surrogate_is_replacement_not_an_error() {
        for unit in [0xD800u32, 0xD83D, 0xDE00, 0xDFFF] {
            assert_eq!(
                parse_clixml(&format!("<C>{unit}</C>")).unwrap(),
                vec![PsValue::Char('\u{FFFD}')],
                "{unit:#x}"
            );
        }
        // The edges of the range are still real characters.
        assert_eq!(
            parse_clixml("<C>55295</C><C>57344</C><C>65535</C>").unwrap(),
            vec![
                PsValue::Char('\u{D7FF}'),
                PsValue::Char('\u{E000}'),
                PsValue::Char('\u{FFFF}'),
            ]
        );
        let got =
            parse_clixml(r#"<Obj RefId="0"><LST><C>55357</C><I32>2</I32><C>56832</C></LST></Obj>"#)
                .unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("expected one object, got {got:?}");
        };
        assert_eq!(
            o.get("_value"),
            Some(&PsValue::List(vec![
                PsValue::Char('\u{FFFD}'),
                PsValue::I32(2),
                PsValue::Char('\u{FFFD}'),
            ]))
        );
    }

    #[test]
    fn base64_primitive() {
        // "aGVsbG8=" = "hello"
        let got = parse_clixml("<BA>aGVsbG8=</BA>").unwrap();
        assert_eq!(got[0], PsValue::Bytes(b"hello".to_vec()));
    }

    #[test]
    fn base64_invalid() {
        assert!(parse_clixml("<BA>!!!not-base64!!!</BA>").is_err());
    }

    #[test]
    fn guid_primitive() {
        let got = parse_clixml("<G>12345678-1234-1234-1234-123456789abc</G>").unwrap();
        if let PsValue::Guid(g) = &got[0] {
            assert_eq!(g.to_string(), "12345678-1234-1234-1234-123456789abc");
        } else {
            panic!("expected Guid");
        }
    }

    #[test]
    fn guid_invalid() {
        assert!(parse_clixml("<G>not-a-guid</G>").is_err());
    }

    #[test]
    fn datetime_and_duration() {
        let got = parse_clixml("<DT>2024-01-01T00:00:00Z</DT>").unwrap();
        assert_eq!(
            got[0],
            PsValue::DateTime("2024-01-01T00:00:00Z".to_string())
        );
        let got = parse_clixml("<TS>P1DT2H</TS>").unwrap();
        assert_eq!(got[0], PsValue::Duration("P1DT2H".to_string()));
    }

    #[test]
    fn version_uri_xml_scriptblock_securestring() {
        let cases = vec![
            ("<Version>5.1</Version>", PsValue::Version("5.1".into())),
            (
                "<URI>http://example.com</URI>",
                PsValue::Uri("http://example.com".into()),
            ),
            (
                "<XD>some xml data</XD>",
                PsValue::Xml("some xml data".into()),
            ),
            (
                "<SBK>Get-Process</SBK>",
                PsValue::ScriptBlock("Get-Process".into()),
            ),
            // `SCT` is not a PowerShell tag; it is only what psrp-rs
            // itself used to write, kept so that output still decodes.
            (
                "<SCT>Get-Process</SCT>",
                PsValue::ScriptBlock("Get-Process".into()),
            ),
            (
                "<SS>encrypted</SS>",
                PsValue::SecureString("encrypted".into()),
            ),
        ];
        for (xml, expected) in cases {
            let got = parse_clixml(xml).unwrap();
            assert_eq!(got.len(), 1, "{xml}");
            assert_eq!(got[0], expected, "{xml}");
        }
    }

    /// Regression (#19): PowerShell's script-block tag is `SBK`
    /// (`SerializationStrings.ScriptBlockTag`, MS-PSRP 2.2.5.1.23), and
    /// the decoder only knew `SCT`, so every `<SBK>` was skipped as an
    /// unknown element: a top-level output vanished, a property went
    /// missing, a list item disappeared and shifted the ones after it.
    ///
    /// The documents are verbatim `PSSerializer.Serialize` output
    /// (pwsh 7.3.12), indentation removed.
    #[test]
    fn script_block_sbk_from_powershell_is_not_dropped() {
        // Top level: `{}` and a body with XML metacharacters and a
        // literal `_x000D_`, which PowerShell escapes as in `<S>`.
        let got =
            parse_clixml(r#"<SBK></SBK><SBK> Get-Date "a&amp;b&lt;c&gt;" _x005F_x000D_ </SBK>"#)
                .unwrap();
        assert_eq!(
            got,
            vec![
                PsValue::ScriptBlock(String::new()),
                PsValue::ScriptBlock(r#" Get-Date "a&b<c>" _x000D_ "#.into()),
            ]
        );

        // `[pscustomobject]@{ Action = { 1 }; L = @({ 2 }, 3) }`: a
        // property value and a list item.
        let xml = concat!(
            r#"<Obj RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T>"#,
            r#"<T>System.Object</T></TN><MS><SBK N="Action"> 1 </SBK>"#,
            r#"<Obj N="L" RefId="1"><TN RefId="1"><T>System.Object[]</T><T>System.Array</T>"#,
            r#"<T>System.Object</T></TN><LST><SBK> 2 </SBK><I32>3</I32></LST></Obj></MS></Obj>"#,
        );
        let got = parse_clixml(xml).unwrap();
        let PsValue::Object(obj) = &got[0] else {
            panic!("expected an object, got {got:?}");
        };
        assert_eq!(obj.get("Action"), Some(&PsValue::ScriptBlock(" 1 ".into())));
        let Some(PsValue::Object(list)) = obj.get("L") else {
            panic!("expected `L` to be an object, got {obj:?}");
        };
        assert_eq!(
            list.get("_value"),
            Some(&PsValue::List(vec![
                PsValue::ScriptBlock(" 2 ".into()),
                PsValue::I32(3),
            ]))
        );
    }

    /// A script block survives the encoder and decoder at every position,
    /// with content that needs each kind of escape: XML metacharacters, a
    /// CR (which XML end-of-line handling would turn into LF) and a
    /// literal `_x` that would otherwise read as a `_xHHHH_` escape.
    #[test]
    fn script_block_round_trips_with_escapes() {
        let body = "if ($a -lt 1) {\r\n  'a&b' <c> \"_x000D_\" _x\r}\n";
        let sb = PsValue::ScriptBlock(body.into());

        let xml = to_clixml(&sb);
        assert!(xml.starts_with("<SBK>") && xml.ends_with("</SBK>"), "{xml}");
        assert!(!xml.contains('\r'), "literal CR in {xml:?}");
        assert_eq!(parse_clixml(&xml).unwrap(), vec![sb.clone()], "{xml}");

        let obj = PsValue::Object(PsObject::new().with("Action", sb.clone()));
        let xml = to_clixml(&obj);
        assert!(xml.contains(r#"<SBK N="Action">"#), "{xml}");
        assert_eq!(parse_clixml(&xml).unwrap(), vec![obj], "{xml}");

        let list = PsValue::List(vec![sb.clone(), PsValue::I32(3)]);
        let got = parse_clixml(&to_clixml(&list)).unwrap();
        let PsValue::Object(o) = &got[0] else {
            panic!("expected the list wrapped in an object, got {got:?}");
        };
        assert_eq!(o.get("_value"), Some(&list));

        // As a dict value and as a dict key.
        let dict = PsValue::Dict(vec![
            (PsValue::String("k".into()), sb.clone()),
            (sb.clone(), PsValue::I32(4)),
        ]);
        let xml = to_clixml(&dict);
        assert!(
            xml.contains(r#"<SBK N="Value">"#) && xml.contains(r#"<SBK N="Key">"#),
            "{xml}"
        );
        let got = parse_clixml(&xml).unwrap();
        let PsValue::Object(o) = &got[0] else {
            panic!("expected the dict wrapped in an object, got {got:?}");
        };
        assert_eq!(o.get("_value"), Some(&dict), "{xml}");
    }

    /// PowerShell normally writes an empty script block (or string) self-closed,
    /// `<SBK N="x" />`, and `<SBK></SBK>` only when its output buffer flushes
    /// before the end tag: neither may be dropped, wherever it appears (a
    /// self-closed `<S N="x"/>` in a member set or dict entry used to be lost).
    #[test]
    fn self_closed_script_block_is_an_empty_script_block() {
        let empty = PsValue::ScriptBlock(String::new());
        let wrapped = |xml: &str| -> PsValue {
            let got = parse_clixml(xml).unwrap();
            let [PsValue::Object(o)] = got.as_slice() else {
                panic!("expected one object, got {got:?}");
            };
            o.get("_value").cloned().unwrap_or(PsValue::Null)
        };

        // Top level, the legacy tag included.
        assert_eq!(
            parse_clixml("<SBK/><SCT/><I32>1</I32>").unwrap(),
            vec![empty.clone(), empty.clone(), PsValue::I32(1)]
        );
        // A list item: the items after it keep their position.
        assert_eq!(
            wrapped(r#"<Obj RefId="0"><LST><SBK/><I32>2</I32></LST></Obj>"#),
            PsValue::List(vec![empty.clone(), PsValue::I32(2)])
        );
        // A dict value and a dict key.
        assert_eq!(
            wrapped(concat!(
                r#"<Obj RefId="0"><DCT><En><S N="Key">k</S><SBK N="Value"/></En>"#,
                r#"<En><SBK N="Key"/><I32 N="Value">3</I32></En></DCT></Obj>"#,
            )),
            PsValue::Dict(vec![
                (PsValue::String("k".into()), empty.clone()),
                (empty.clone(), PsValue::I32(3)),
            ])
        );
        // A property. Member sets and dict entries now read every
        // self-closed value the way lists and the top level do, so a
        // self-closed `<S N="…"/>` is an empty string there too.
        let got = parse_clixml(
            r#"<Obj RefId="0"><MS><SBK N="Action"/><S N="Empty"/><I32 N="After">4</I32></MS></Obj>"#,
        )
        .unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("expected one object, got {got:?}");
        };
        assert_eq!(o.get("Action"), Some(&empty));
        assert_eq!(o.get("Empty"), Some(&PsValue::String(String::new())));
        assert_eq!(o.get("After"), Some(&PsValue::I32(4)));
    }

    #[test]
    fn decimal_primitive() {
        let got = parse_clixml("<D>123.456</D>").unwrap();
        assert_eq!(got[0], PsValue::Decimal("123.456".to_string()));
    }

    #[test]
    fn single_float() {
        let got = parse_clixml("<Sg>1.5</Sg>").unwrap();
        if let PsValue::F32(v) = got[0] {
            assert!((v - 1.5).abs() < f32::EPSILON);
        } else {
            panic!("expected F32");
        }
    }

    #[test]
    fn single_float_special() {
        let got = parse_clixml("<Sg>NaN</Sg>").unwrap();
        assert!(matches!(got[0], PsValue::F32(v) if v.is_nan()));
        let got = parse_clixml("<Sg>Infinity</Sg>").unwrap();
        assert!(matches!(got[0], PsValue::F32(v) if v.is_infinite()));
    }

    #[test]
    fn single_float_out_of_range_becomes_infinity() {
        // f64 magnitudes beyond f32 narrow to infinity, never panic.
        let got = parse_clixml("<Sg>1e300</Sg>").unwrap();
        assert!(matches!(got[0], PsValue::F32(v) if v.is_infinite() && v > 0.0));
        let got = parse_clixml("<Sg>-1e300</Sg>").unwrap();
        assert!(matches!(got[0], PsValue::F32(v) if v.is_infinite() && v < 0.0));
    }

    #[test]
    fn measure_is_total_on_large_values() {
        let v = PsValue::List(vec![
            PsValue::String("abc".into()),
            PsValue::Bytes(vec![0; 5]),
        ]);
        assert_eq!(measure(&v), (1 + 4 + 6, 1));
    }

    #[test]
    fn single_float_error() {
        assert!(parse_clixml("<Sg>not-float</Sg>").is_err());
    }

    #[test]
    fn unknown_top_level_element_skipped() {
        let xml = "<FutureTag><nested>data</nested></FutureTag><I32>42</I32>";
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], PsValue::I32(42));
    }

    #[test]
    fn unknown_element_is_skipped_with_its_known_children() {
        // A known element inside an unknown one belongs to it: it must not
        // surface as a value of its own.
        let xml = "<FutureTag><I32>1</I32><S>leak</S></FutureTag><I32>42</I32>";
        assert_eq!(parse_clixml(xml).unwrap(), vec![PsValue::I32(42)]);
    }

    #[test]
    fn unknown_element_cut_short_ends_the_parse() {
        // The input ends inside the unknown element: the skip must stop at
        // the end of the input instead of reading it again forever.
        assert_eq!(parse_clixml("<FutureTag><I32>1</I32>").unwrap(), vec![]);
        assert_eq!(
            parse_clixml("<I32>2</I32><FutureTag><S>x").unwrap(),
            vec![PsValue::I32(2)]
        );
    }

    #[test]
    fn tnref_with_an_end_tag_keeps_the_rest_of_the_object() {
        let xml = r#"
          <Obj RefId="0"><TN RefId="0"><T>Foo</T></TN><MS/></Obj>
          <Obj RefId="1"><TNRef RefId="0"></TNRef><MS><I32 N="n">7</I32></MS></Obj>
        "#;
        let got = parse_clixml(xml).unwrap();
        let PsValue::Object(o) = &got[1] else {
            panic!("{got:?}");
        };
        assert_eq!(o.type_names, vec!["Foo".to_string()]);
        assert_eq!(o.get("n"), Some(&PsValue::I32(7)));
    }

    #[test]
    fn unknown_self_closing_element_skipped() {
        let xml = "<UnknownThing/><I32>7</I32>";
        let got = parse_clixml(xml).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], PsValue::I32(7));
    }

    #[test]
    fn empty_s_tag_self_closing() {
        let got = parse_clixml("<S/>").unwrap();
        assert_eq!(got[0], PsValue::String(String::new()));
    }

    #[test]
    fn eof_inside_obj_is_error() {
        assert!(parse_clixml("<Obj RefId=\"0\"><MS>").is_err());
    }

    #[test]
    fn eof_inside_list_is_error() {
        assert!(parse_clixml("<Obj RefId=\"0\"><LST><I32>1</I32>").is_err());
    }

    #[test]
    fn eof_inside_dict_is_error() {
        assert!(parse_clixml("<Obj RefId=\"0\"><DCT><En>").is_err());
    }

    #[test]
    fn eof_inside_text_is_error() {
        assert!(parse_clixml("<S>unclosed").is_err());
    }

    #[test]
    fn dict_entry_with_nil_key_and_value() {
        let xml = r#"<Obj RefId="0"><DCT><En><Nil N="Key"/><Nil N="Value"/></En></DCT></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            if let Some(PsValue::Dict(entries)) = o.get("_value") {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0], (PsValue::Null, PsValue::Null));
            } else {
                panic!("expected dict");
            }
        } else {
            panic!("expected object");
        }
    }

    #[test]
    fn ref_inside_member_set() {
        let xml = r#"<Obj RefId="a"><MS><S N="k">v</S></MS></Obj><Obj RefId="b"><MS><Ref N="copy" RefId="a"/></MS></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[1] {
            assert_eq!(o.get("copy"), Some(&got[0]));
        } else {
            panic!();
        }
    }

    #[test]
    fn ie_que_stk_treated_as_list() {
        for tag in ["IE", "QUE", "STK"] {
            let xml = format!(r#"<Obj RefId="0"><{tag}><I32>1</I32><I32>2</I32></{tag}></Obj>"#);
            let got = parse_clixml(&xml).unwrap();
            if let PsValue::Object(o) = &got[0] {
                assert_eq!(
                    o.get("_value"),
                    Some(&PsValue::List(vec![PsValue::I32(1), PsValue::I32(2)])),
                    "{tag} should be treated as list"
                );
            } else {
                panic!("{tag} should produce object");
            }
        }
    }

    #[test]
    fn tnref_self_closing_in_obj() {
        let xml = r#"
          <Obj RefId="0"><TN RefId="0"><T>Foo</T></TN><MS><S N="k">v</S></MS></Obj>
          <Obj RefId="1"><TNRef RefId="0"/><MS><I32 N="n">7</I32></MS></Obj>
        "#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[1] {
            assert_eq!(o.type_names, vec!["Foo".to_string()]);
        } else {
            panic!();
        }
    }

    #[test]
    fn nil_inside_list() {
        let xml = r#"<Obj RefId="0"><LST><I32>1</I32><Nil/><I32>3</I32></LST></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            assert_eq!(
                o.get("_value"),
                Some(&PsValue::List(vec![
                    PsValue::I32(1),
                    PsValue::Null,
                    PsValue::I32(3)
                ]))
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn dict_roundtrip() {
        let v = PsValue::Dict(vec![
            (PsValue::String("k1".into()), PsValue::I32(1)),
            (PsValue::String("k2".into()), PsValue::String("v".into())),
        ]);
        let xml = to_clixml(&v);
        let got = parse_clixml(&xml).unwrap();
        if let PsValue::Object(o) = &got[0] {
            if let Some(PsValue::Dict(entries)) = o.get("_value") {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].0, PsValue::String("k1".into()));
                assert_eq!(entries[0].1, PsValue::I32(1));
            } else {
                panic!("dict lost");
            }
        } else {
            panic!();
        }
    }

    /// PowerShell writes the second occurrence of an object in one graph as a
    /// self-closed `<Ref RefId="…" />` (`WritePSObjectReference`): in a list
    /// item, a dict key or value, a property, or at the top level. It used to
    /// be dropped from a list (the items after it shifted) and read as `Null`
    /// in a dict entry.
    #[test]
    fn self_closed_ref_resolves_wherever_it_appears() {
        let o = |n: &str| {
            let mut obj = PsObject::default();
            obj.properties.insert("a".into(), PsValue::String(n.into()));
            PsValue::Object(obj)
        };
        let first = r#"<Obj RefId="1"><MS><S N="a">x</S></MS></Obj>"#;
        let decode = |xml: &str| {
            let got = parse_clixml(xml).unwrap();
            let [PsValue::Object(o)] = got.as_slice() else {
                panic!("expected one object, got {got:?}");
            };
            o.get("_value").cloned().unwrap_or(PsValue::Null)
        };

        // `@($o, $o, 3)`: the reference keeps its position.
        assert_eq!(
            decode(&format!(
                r#"<Obj RefId="0"><LST>{first}<Ref RefId="1" /><I32>3</I32></LST></Obj>"#
            )),
            PsValue::List(vec![o("x"), o("x"), PsValue::I32(3)])
        );
        // `@{a=$o; b=$o}`, and a reference used as a key.
        assert_eq!(
            decode(concat!(
                r#"<Obj RefId="0"><DCT>"#,
                r#"<En><S N="Key">a</S><Obj N="Value" RefId="1"><MS><S N="a">x</S></MS></Obj></En>"#,
                r#"<En><S N="Key">b</S><Ref N="Value" RefId="1" /></En>"#,
                r#"<En><Ref N="Key" RefId="1" /><I32 N="Value">9</I32></En>"#,
                r#"</DCT></Obj>"#,
            )),
            PsValue::Dict(vec![
                (PsValue::String("a".into()), o("x")),
                (PsValue::String("b".into()), o("x")),
                (o("x"), PsValue::I32(9)),
            ])
        );
        // A property, and the top level.
        let got = parse_clixml(&format!(
            r#"{first}<Obj RefId="2"><MS><Ref N="p" RefId="1" /></MS></Obj><Ref RefId="1" />"#
        ))
        .unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[2], o("x"));
        let PsValue::Object(holder) = &got[1] else {
            panic!("{got:?}");
        };
        assert_eq!(holder.get("p"), Some(&o("x")));
    }

    /// A reference to an id that is not decoded (dangling, or a cycle back to
    /// an object still being built) is `Null`, in a list as at the top level,
    /// and does not shift its neighbours.
    #[test]
    fn dangling_or_cyclic_ref_is_null_in_place() {
        assert_eq!(
            decode_value(
                r#"<Obj RefId="0"><LST><Ref RefId="nope" /><I32>2</I32><Ref RefId="0" /></LST></Obj>"#
            ),
            PsValue::List(vec![PsValue::Null, PsValue::I32(2), PsValue::Null])
        );
        // No RefId at all.
        assert_eq!(
            decode_value(r#"<Obj RefId="0"><LST><Ref /><I32>2</I32></LST></Obj>"#),
            PsValue::List(vec![PsValue::Null, PsValue::I32(2)])
        );
    }

    fn decode_value(xml: &str) -> PsValue {
        let got = parse_clixml(xml).unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("expected one object, got {got:?}");
        };
        o.get("_value").cloned().unwrap_or(PsValue::Null)
    }

    /// A server can chain objects that each hold two references to the
    /// previous one: a few KiB of XML then expands to 2^n values. That used to
    /// exhaust the memory and abort the process; now it is a parse error.
    #[test]
    fn doubling_refs_are_a_bounded_error_not_an_oom() {
        let mut xml = String::from(r#"<Obj RefId="0"><LST><S>x</S></LST></Obj>"#);
        for k in 1..=40 {
            xml.push_str(&format!(
                r#"<Obj RefId="{k}"><LST><Ref RefId="{p}" /><Ref RefId="{p}" /></LST></Obj>"#,
                p = k - 1
            ));
        }
        let err = parse_clixml(&xml).expect_err("2^40 values must not decode");
        assert!(err.to_string().contains("expansion"), "{err}");
    }

    /// Chaining one reference per level also builds a value deeper than the
    /// parser itself would accept; it is refused the same way.
    #[test]
    fn chained_refs_cannot_outgrow_the_nesting_limit() {
        let mut xml = String::from(r#"<Obj RefId="0"><LST><S>x</S></LST></Obj>"#);
        for k in 1..=200 {
            xml.push_str(&format!(
                r#"<Obj RefId="{k}"><LST><Ref RefId="{p}" /></LST></Obj>"#,
                p = k - 1
            ));
        }
        let err = parse_clixml(&xml).expect_err("a 400-level value must not decode");
        assert!(err.to_string().contains("deeper"), "{err}");
    }

    /// Ordinary sharing stays far below both limits.
    #[test]
    fn ordinary_sharing_is_not_limited() {
        let mut xml = String::from(
            r#"<Obj RefId="0"><MS><S N="Name">svchost</S><I32 N="Id">42</I32></MS></Obj><Obj RefId="1"><LST>"#,
        );
        for _ in 0..1000 {
            xml.push_str(r#"<Ref RefId="0" />"#);
        }
        xml.push_str("</LST></Obj>");
        let got = parse_clixml(&xml).unwrap();
        let PsValue::Object(list) = &got[1] else {
            panic!("{got:?}");
        };
        let Some(PsValue::List(items)) = list.get("_value") else {
            panic!("{list:?}");
        };
        assert_eq!(items.len(), 1000);
        assert!(items.iter().all(|i| *i == got[0]));
    }

    /// Legitimate sharing grows with the document: 15 000 elements that point
    /// at one 100-character object materialize ~1.6 M units of weight, past
    /// the floor of the budget but within what the document's size allows.
    #[test]
    fn sharing_scales_with_the_document() {
        let mut xml = format!(
            r#"<Obj RefId="s"><MS><S N="Name">{}</S></MS></Obj><Obj RefId="l"><LST>"#,
            "x".repeat(100)
        );
        for _ in 0..15_000 {
            xml.push_str(r#"<Ref RefId="s" />"#);
        }
        xml.push_str("</LST></Obj>");
        let got = parse_clixml(&xml).unwrap();
        let PsValue::Object(list) = &got[1] else {
            panic!("expected the list object");
        };
        let Some(PsValue::List(items)) = list.get("_value") else {
            panic!("{list:?}");
        };
        assert_eq!(items.len(), 15_000);
    }

    /// A .NET enum as `PSSerializer` writes it (captured from pwsh over
    /// WinRM): the number is a nameless child, which used to be dropped, so
    /// every enum came back as an empty object.
    #[test]
    fn enum_value_is_kept_under_value() {
        let xml = concat!(
            r#"<Obj RefId="0"><TN RefId="0"><T>System.IO.FileAttributes</T><T>System.Enum</T>"#,
            r#"<T>System.ValueType</T><T>System.Object</T></TN>"#,
            r#"<ToString>ReadOnly, Hidden</ToString><I32>3</I32></Obj>"#,
        );
        let got = parse_clixml(xml).unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("expected one object, got {got:?}");
        };
        assert_eq!(o.get("_value"), Some(&PsValue::I32(3)));
        assert_eq!(o.type_names[0], "System.IO.FileAttributes");
        assert_eq!(o.type_names[1], "System.Enum");
    }

    /// Other underlying types, and an enum inside a property, a list and a
    /// dictionary value (`CommandOrigin` of an `InvocationInfo`).
    #[test]
    fn enum_value_survives_inside_containers() {
        let en = |n: &str, v: &str| {
            format!(
                r#"<Obj RefId="9"><TN RefId="9"><T>E</T><T>System.Enum</T></TN><ToString>x</ToString><{n}>{v}</{n}></Obj>"#
            )
        };
        let xml = format!(
            r#"<Obj RefId="0"><MS>{}</MS></Obj>"#,
            en("I32", "1").replace("<Obj ", r#"<Obj N="Origin" "#)
        );
        let got = parse_clixml(&xml).unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("{got:?}");
        };
        let Some(PsValue::Object(origin)) = o.get("Origin") else {
            panic!("{o:?}");
        };
        assert_eq!(origin.get("_value"), Some(&PsValue::I32(1)));

        let xml = format!(
            r#"<Obj RefId="0"><LST>{}{}</LST></Obj>"#,
            en("By", "7"),
            en("I64", "9000000000")
        );
        let got = parse_clixml(&xml).unwrap();
        let [PsValue::Object(list)] = got.as_slice() else {
            panic!("{got:?}");
        };
        let Some(PsValue::List(items)) = list.get("_value") else {
            panic!("{list:?}");
        };
        let values: Vec<_> = items
            .iter()
            .map(|i| match i {
                PsValue::Object(o) => o.get("_value").cloned(),
                _ => None,
            })
            .collect();
        assert_eq!(
            values,
            vec![Some(PsValue::U8(7)), Some(PsValue::I64(9_000_000_000))]
        );
    }

    /// An object that has properties keeps them: the nameless child only
    /// fills `_value` when there is no member set (as for `<LST>`).
    #[test]
    fn a_member_set_wins_over_a_nameless_scalar() {
        let xml = r#"<Obj RefId="0"><MS><S N="a">x</S></MS><I32>5</I32></Obj>"#;
        let got = parse_clixml(xml).unwrap();
        let [PsValue::Object(o)] = got.as_slice() else {
            panic!("{got:?}");
        };
        assert_eq!(o.get("a"), Some(&PsValue::String("x".into())));
        assert!(o.get("_value").is_none());
    }

    // ---------- <TNRef> copies and the decoded-size budget ----------

    /// Decode against a budget of `limit` bytes; what was used comes back too.
    fn within(xml: &str, limit: u64) -> (Result<Vec<PsValue>>, u64) {
        let mut budget = DecodeBudget::new(usize::try_from(limit).unwrap());
        let got = parse_clixml_within(xml, &mut budget);
        (got, budget.used)
    }

    /// What one value takes inline.
    fn node() -> u64 {
        u64::try_from(std::mem::size_of::<PsValue>()).unwrap()
    }

    /// Regression: a `<TNRef>` copied the stored list into the object with
    /// nothing counted, so 1 000 names stored once and named by 2 000 empty
    /// objects were two million strings for 45 KiB of XML (+107 MiB, and
    /// four times that for twice the document). Both spellings of the
    /// element are charged.
    #[test]
    fn type_name_refs_cannot_multiply_a_long_list() {
        for reference in [r#"<TNRef RefId="0" />"#, r#"<TNRef RefId="0"></TNRef>"#] {
            let mut xml = String::from(r#"<Obj RefId="0"><TN RefId="0">"#);
            for _ in 0..1000 {
                xml.push_str("<T>a</T>");
            }
            xml.push_str("</TN></Obj>");
            for _ in 0..2000 {
                xml.push_str("<Obj>");
                xml.push_str(reference);
                xml.push_str("</Obj>");
            }
            let err = parse_clixml(&xml).expect_err("two million strings must not decode");
            assert!(err.to_string().contains("<TNRef> expansion"), "{err}");
        }
    }

    /// What PowerShell does write is not limited, however long the document:
    /// one `<TNRef>` per object of a type. 100 000 of them weigh more than
    /// the ceiling of the `<Ref>` budget, which does not apply to them.
    #[test]
    fn a_type_name_ref_per_object_is_not_limited() {
        let names = [
            "System.IO.FileInfo",
            "System.IO.FileSystemInfo",
            "System.MarshalByRefObject",
            "System.Object",
        ];
        let mut xml = String::from(r#"<Obj RefId="0"><TN RefId="0">"#);
        for name in names {
            xml.push_str(&format!("<T>{name}</T>"));
        }
        xml.push_str("</TN><LST>");
        for _ in 0..100_000 {
            xml.push_str(r#"<Obj><TNRef RefId="0" /></Obj>"#);
        }
        xml.push_str("</LST></Obj>");
        let weight = type_names_weight(&names.map(String::from));
        assert!(weight * 100_000 > REF_BUDGET_CEILING);

        let got = parse_clixml(&xml).unwrap();
        let Some(PsValue::List(items)) = got[0].properties().and_then(|o| o.get("_value")) else {
            panic!("expected the list");
        };
        assert_eq!(items.len(), 100_000);
        assert_eq!(items[99_999].type_names().unwrap(), names);
    }

    /// The budgets of the two kinds of reference: same floor and allowance,
    /// a ceiling for `<Ref>` only.
    #[test]
    fn reference_budgets() {
        assert_eq!(ref_budget(0), 1 << 20);
        assert_eq!(type_names_budget(0), 1 << 20);
        assert_eq!(ref_budget(1000), (1 << 20) + 8000);
        assert_eq!(type_names_budget(1000), (1 << 20) + 8000);
        assert_eq!(ref_budget(100 << 20), 8 << 20);
        assert_eq!(type_names_budget(100 << 20), (1 << 20) + (800 << 20));
        assert_eq!(type_names_budget(usize::MAX), u64::MAX);
    }

    /// The copy of a `<TNRef>` is charged at its weight: one per name plus
    /// its length.
    #[test]
    fn a_type_name_ref_is_charged_at_its_weight() {
        let names = vec!["ab".to_string(), String::new(), "c".to_string()];
        assert_eq!(type_names_weight(&names), 3 + 3);
        assert_eq!(type_names_weight(&[]), 0);

        let mut state = DecoderState {
            names_budget: 12,
            decoded_limit: u64::MAX,
            ..DecoderState::default()
        };
        state.type_names.insert("7".into(), names.clone());
        let mut obj = PsObject::new();
        apply_type_names_ref(&mut obj, Some("7".into()), &mut state).unwrap();
        assert_eq!(obj.type_names, names);
        assert_eq!(state.names_expanded, 6);
        assert_eq!(state.decoded, type_names_size(&names));
        // A second copy fits exactly, a third does not, and is not made.
        apply_type_names_ref(&mut obj, Some("7".into()), &mut state).unwrap();
        assert_eq!(state.names_expanded, 12);
        let mut other = PsObject::new();
        let err = apply_type_names_ref(&mut other, Some("7".into()), &mut state).unwrap_err();
        assert!(err.to_string().contains("exceeds 12"), "{err}");
        assert_eq!(other.type_names, Vec::<String>::new());
        assert_eq!(state.names_expanded, 12);
        // No id, or an unknown one: nothing copied, nothing charged.
        apply_type_names_ref(&mut other, None, &mut state).unwrap();
        apply_type_names_ref(&mut other, Some("8".into()), &mut state).unwrap();
        assert_eq!(other.type_names, Vec::<String>::new());
        assert_eq!(state.names_expanded, 12);
    }

    /// A list of type names costs each name's text and `String` header.
    #[test]
    fn type_names_size_counts_text_and_headers() {
        let header = u64::try_from(std::mem::size_of::<String>()).unwrap();
        let names = vec!["ab".to_string(), "c".to_string()];
        assert_eq!(type_names_size(&names), 2 * header + 3);
        assert_eq!(type_names_size(&[]), 0);
    }

    /// Regression: six bytes of `<Nil/>` are one value in memory, some twenty
    /// times more, and nothing bounded what a document decodes to. Every
    /// value is now counted as it is built, to the byte of this estimate.
    #[test]
    fn a_document_is_charged_for_every_value_it_builds() {
        let mut xml = String::from(r#"<Obj RefId="0"><LST>"#);
        for _ in 0..1000 {
            xml.push_str("<Nil/>");
        }
        xml.push_str("</LST></Obj>");
        // 1 000 items, the list, the object, and the `_value` entry.
        let exact = 1002 * node() + ENTRY_SIZE + 6;

        let (got, used) = within(&xml, exact);
        assert_eq!(got.unwrap().len(), 1);
        assert_eq!(used, exact);

        let (got, used) = within(&xml, exact - 1);
        let err = got.expect_err("one byte short");
        assert!(matches!(err, PsrpError::Clixml(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains(&format!("more than the {}-byte limit", exact - 1)),
            "{err}"
        );
        assert_eq!(used, 0, "a refused document is not charged to the caller");
    }

    /// One budget for several documents: the second one starts where the
    /// first one stopped.
    #[test]
    fn a_budget_is_shared_between_documents() {
        let xml = "<S>hello</S><Nil/>";
        let cost = 2 * node() + 5;
        let mut budget = DecodeBudget::new(usize::try_from(2 * cost + 1).unwrap());
        parse_clixml_within(xml, &mut budget).unwrap();
        assert_eq!(budget.used, cost);
        parse_clixml_within(xml, &mut budget).unwrap();
        assert_eq!(budget.used, 2 * cost);
        let err = parse_clixml_within(xml, &mut budget).unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
        assert_eq!(budget.used, 2 * cost);
    }

    /// Text and bytes count for their length, names for theirs.
    #[test]
    fn payloads_and_names_are_counted() {
        let scalar = |xml: &str| within(xml, u64::MAX).1 - node();
        assert_eq!(scalar("<S>hello</S>"), 5);
        assert_eq!(scalar("<S/>"), 0);
        assert_eq!(scalar("<BA>AAAA</BA>"), 3);
        assert_eq!(scalar("<I32>12345</I32>"), 0);
        assert_eq!(scalar("<DT>2026-01-01</DT>"), 10);
        assert_eq!(scalar("<SBK/>"), 0);

        // An object, a three-letter property holding a two-letter string.
        let (_, used) = within(r#"<Obj><MS><S N="abc">xy</S></MS></Obj>"#, u64::MAX);
        assert_eq!(used, 2 * node() + 2 + ENTRY_SIZE + 3);
        // The same with a null and with an empty string, self-closed.
        for member in [r#"<Nil N="abc"/>"#, r#"<S N="abc"/>"#] {
            let (_, used) = within(&format!("<Obj><MS>{member}</MS></Obj>"), u64::MAX);
            assert_eq!(used, 2 * node() + ENTRY_SIZE + 3, "{member}");
        }
        // Type names: charged once for the object, and nothing stays charged
        // for the copy kept under their `RefId`.
        let names = type_names_size(&["ab".to_string()]);
        for tn in ["<TN>", r#"<TN RefId="0">"#] {
            let (_, used) = within(&format!("<Obj>{tn}<T>ab</T></TN></Obj>"), u64::MAX);
            assert_eq!(used, node() + names, "{tn}");
        }
    }

    /// An entry with no key or no value still holds two values.
    #[test]
    fn empty_dictionary_entries_are_charged() {
        let dict = |entries: &str| {
            let xml = format!("<Obj><DCT>{entries}</DCT></Obj>");
            // The object, the dictionary and the `_value` entry aside.
            within(&xml, u64::MAX).1 - 2 * node() - ENTRY_SIZE - 6
        };
        assert_eq!(dict(""), 0);
        assert_eq!(dict("<En></En>"), 2 * node());
        assert_eq!(dict(r#"<En><S N="Key">k</S></En>"#), 2 * node() + 1);
        assert_eq!(dict(r#"<En><Nil N="Value"/></En>"#), 2 * node());
        assert_eq!(
            dict(r#"<En><S N="Key">k</S><I32 N="Value">1</I32></En>"#),
            2 * node() + 1
        );

        let xml = format!("<Obj><DCT>{}</DCT></Obj>", "<En></En>".repeat(500));
        let (got, _) = within(&xml, 999 * node());
        assert!(got.unwrap_err().to_string().contains("limit"));
    }

    /// A `<Ref>` is charged for its whole copy, before the copy is made, and
    /// the copy kept for it counts while the document is decoded only.
    #[test]
    fn references_are_charged_for_the_whole_copy() {
        let xml = r#"<Obj RefId="s"><MS><S N="a">x</S></MS></Obj><Ref RefId="s"/>"#;
        let object = 2 * node() + 1 + ENTRY_SIZE + 1;

        let (got, used) = within(xml, u64::MAX);
        assert_eq!(got.unwrap().len(), 2);
        assert_eq!(used, 2 * object, "the object and its copy");

        // While decoding, the kept copy is a third one, with the id it is
        // kept under and the note that a `<Ref>` points to that id.
        let decoding = 3 * object + (ENTRY_SIZE + 1) + REFERENCED_ID_SIZE;
        assert!(within(xml, decoding).0.is_ok());
        let (got, _) = within(xml, decoding - 1);
        assert!(got.unwrap_err().to_string().contains("limit"));

        // Dangling references are one `Null` each.
        let (got, used) = within(r#"<Ref RefId="none"/><Ref/>"#, u64::MAX);
        assert_eq!(got.unwrap(), vec![PsValue::Null, PsValue::Null]);
        assert_eq!(used, 2 * node());
        // Same for the spelling with an end tag.
        let (_, used) = within(r#"<Ref RefId="none"></Ref>"#, u64::MAX);
        assert_eq!(used, node());
    }

    /// `deep_size` is what a clone allocates: every node, text, name and
    /// type name under the value.
    #[test]
    fn deep_size_walks_the_whole_value() {
        let mut inner = PsObject::new().with("ab", PsValue::String("xyz".into()));
        inner.type_names = vec!["T".into()];
        inner.to_string = Some("shown".into());
        let inner_size = 2 * node() + 3 + (ENTRY_SIZE + 2) + type_names_size(&inner.type_names) + 5;
        assert_eq!(deep_size(&PsValue::Object(inner.clone())), inner_size);

        let list = PsValue::List(vec![PsValue::Object(inner.clone()), PsValue::I32(1)]);
        assert_eq!(deep_size(&list), 2 * node() + inner_size);

        let dict = PsValue::Dict(vec![(PsValue::String("k".into()), PsValue::Object(inner))]);
        assert_eq!(deep_size(&dict), 2 * node() + 1 + inner_size);
        assert_eq!(deep_size(&PsValue::Bytes(vec![0; 9])), node() + 9);
        assert_eq!(deep_size(&PsValue::Null), node());
    }

    /// The public entry point allows a gigabyte per document.
    /// Regression: quick-xml checked every attribute name against the
    /// earlier ones of its tag, and a name it had seen cost a scan of all of
    /// them: 20 000 names followed by 20 000 copies of the last took
    /// 4 × 10^8 comparisons (seconds here, hours for 20 MB of attributes),
    /// inside a call nothing can interrupt.
    #[test]
    fn repeated_attributes_cost_no_more_than_the_others() {
        use std::fmt::Write as _;
        let mut doc = String::from("<Obj");
        for i in 0..20_000 {
            write!(doc, r#" a{i}="""#).unwrap();
        }
        for _ in 0..20_000 {
            doc.push_str(r#" a19999="""#);
        }
        doc.push_str("><MS/></Obj>");
        let started = std::time::Instant::now();
        assert_eq!(parse_clixml(&doc).unwrap().len(), 1);
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_secs(2), "{took:?}");
    }

    /// With copies of an attribute, the first one is read, as it was when
    /// quick-xml reported the others as errors.
    #[test]
    fn the_first_attribute_of_a_name_is_the_one_read() {
        let values = parse_clixml(concat!(
            r#"<Obj RefId="0" RefId="9"><MS><S N="a" N="b">x</S></MS></Obj>"#,
            r#"<Ref RefId="0"/><Ref RefId="9"/>"#,
        ))
        .unwrap();
        assert_eq!(values.len(), 3);
        let PsValue::Object(obj) = &values[0] else {
            panic!("an object");
        };
        assert_eq!(obj.get("a"), Some(&PsValue::String("x".into())));
        assert_eq!(obj.get("b"), None);
        assert_eq!(values[1], values[0], "kept under its first id");
        assert_eq!(values[2], PsValue::Null, "the second id names nothing");
    }

    /// Regression: the ids that `<Ref>`s point to were collected as text
    /// before anything was charged, from a document that may be nothing but
    /// `<Ref>`s: a 200 MiB message cost several times that, whatever
    /// `max_pipeline_size` said. Each id is now a hash, charged as it is
    /// noted and given back at the end.
    #[test]
    fn the_ids_references_point_to_are_charged() {
        // A thousand references to objects that do not exist, in an element
        // the decoder skips: no value is built.
        use std::fmt::Write as _;
        let mut doc = String::from("<X>");
        for i in 0..1000 {
            write!(doc, r#"<Ref RefId="{i}"/>"#).unwrap();
        }
        doc.push_str("</X>");
        let (decoded, used) = within(&doc, 1000 * REFERENCED_ID_SIZE);
        assert_eq!(decoded.unwrap().len(), 0);
        assert_eq!(used, 0, "given back once the document is decoded");
        let (decoded, _) = within(&doc, 1000 * REFERENCED_ID_SIZE - 1);
        let err = decoded.unwrap_err();
        assert!(err.to_string().contains("byte limit"), "{err}");

        // The same id a thousand times is one id.
        let same = format!("<X>{}</X>", r#"<Ref RefId="7"/>"#.repeat(1000));
        assert!(within(&same, REFERENCED_ID_SIZE).0.is_ok());
        assert!(within(&same, REFERENCED_ID_SIZE - 1).0.is_err());
    }

    /// The id a copy is kept under is as long as the server likes: it is
    /// charged with the copy.
    #[test]
    fn the_id_a_copy_is_kept_under_is_charged() {
        let id = "i".repeat(10_000);
        let object = format!(r#"<Obj RefId="{id}"><MS/></Obj><Ref RefId="{id}"/>"#);
        assert!(within(&object, 9_000).0.is_err());
        let (decoded, used) = within(&object, 12_000);
        assert_eq!(decoded.unwrap().len(), 2);
        assert!(used < 1_000, "given back with the copy: {used}");

        let names = format!(r#"<Obj RefId="0"><TN RefId="{id}"><T>A</T></TN><MS/></Obj>"#);
        assert!(within(&names, 9_000).0.is_err());
        let (decoded, used) = within(&names, 12_000);
        assert_eq!(decoded.unwrap().len(), 1);
        assert!(used < 1_000, "{used}");
    }

    /// A message that is read and dropped gets the whole limit, whatever
    /// the budget has used, and leaves the budget as it was.
    #[test]
    fn a_transient_document_gets_the_whole_limit_and_takes_nothing() {
        let doc = "<S>one</S><S>two</S><Nil/>";
        let mut measure = DecodeBudget::new(usize::MAX);
        parse_clixml_within(doc, &mut measure).unwrap();
        let size = measure.used();
        assert_eq!(size, 3 * std::mem::size_of::<PsValue>() + 6);
        let mut budget = DecodeBudget::new(size);
        parse_clixml_within(doc, &mut budget).unwrap();
        assert_eq!(budget.used(), size, "full");
        assert!(parse_clixml_within("<Nil/>", &mut budget.clone()).is_err());

        assert_eq!(parse_clixml_transient(doc, &budget).unwrap().len(), 3);
        assert_eq!(budget.used(), size, "nothing taken");
        let tighter = DecodeBudget::new(size - 1);
        let err = parse_clixml_transient(doc, &tighter).unwrap_err();
        assert!(err.to_string().contains("byte limit"), "{err}");
        assert_eq!(DecodeBudget::default().used(), 0);
    }

    #[test]
    fn default_decoded_size_is_a_gibibyte() {
        assert_eq!(DEFAULT_MAX_DECODED_SIZE, 1 << 30);
        let budget = DecodeBudget::new(DEFAULT_MAX_DECODED_SIZE);
        assert_eq!((budget.limit, budget.used), (1 << 30, 0));
    }
}
