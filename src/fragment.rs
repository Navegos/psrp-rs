//! PSRP fragment layer (MS-PSRP §2.2.4).
//!
//! A PSRP message is sliced into one or more fragments. Each fragment has a
//! 21-byte big-endian header followed by a blob:
//!
//! ```text
//!  0                               8                              16
//! +-------------------------------+-------------------------------+---+-----+
//! |          ObjectId  (u64 BE)   |        FragmentId (u64 BE)    | F | Len |
//! +-------------------------------+-------------------------------+---+-----+
//!                                                                  ^17 ^21 + payload
//! ```
//!
//! `F` flags: `0x01` = Start of object, `0x02` = End of object.
//!
//! The fragmenter splits a message payload at [`MAX_FRAGMENT_PAYLOAD`]; the
//! reassembler is stateful and tolerates fragments being split at arbitrary
//! byte boundaries across successive `feed` calls.

use std::collections::HashMap;

use crate::error::{PsrpError, Result};

/// Maximum payload bytes per fragment. Matches `pypsrp`'s default and is well
/// under `winrm-rs`' default `max_envelope_size` of 153 600 bytes (base64
/// overhead included).
pub const MAX_FRAGMENT_PAYLOAD: usize = 32 * 1024;

/// Size of the fragment header in bytes.
pub const FRAGMENT_HEADER_LEN: usize = 21;

const FLAG_START: u8 = 0x01;
const FLAG_END: u8 = 0x02;

/// A single PSRP fragment (header + blob).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Object identifier shared by all fragments of the same message.
    pub object_id: u64,
    /// 0-based index of this fragment within the message.
    pub fragment_id: u64,
    /// True for the first fragment of an object.
    pub start: bool,
    /// True for the last fragment of an object.
    pub end: bool,
    /// Payload bytes for this fragment.
    pub blob: Vec<u8>,
}

impl Fragment {
    fn flags(&self) -> u8 {
        let mut f = 0;
        if self.start {
            f |= FLAG_START;
        }
        if self.end {
            f |= FLAG_END;
        }
        f
    }

    /// Serialize this fragment to its wire representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        // Capacity hint only: a saturated value is never reached (a `Vec`
        // length is bounded by `isize::MAX`).
        let mut out = Vec::with_capacity(FRAGMENT_HEADER_LEN.saturating_add(self.blob.len()));
        out.extend_from_slice(&self.object_id.to_be_bytes());
        out.extend_from_slice(&self.fragment_id.to_be_bytes());
        out.push(self.flags());
        out.extend_from_slice(
            &u32::try_from(self.blob.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.blob);
        out
    }
}

/// Split a complete PSRP message payload into fragments for the given
/// `object_id`. At least one fragment is always returned (an empty message
/// yields a single `start+end` fragment with an empty blob).
#[must_use]
pub fn split_message(object_id: u64, payload: &[u8]) -> Vec<Fragment> {
    if payload.is_empty() {
        return vec![Fragment {
            object_id,
            fragment_id: 0,
            start: true,
            end: true,
            blob: Vec::new(),
        }];
    }

    let mut out = Vec::new();
    let mut chunks = payload.chunks(MAX_FRAGMENT_PAYLOAD).peekable();
    // `fragment_id` is a `u64` counter, so no `usize` -> `u64` cast is needed
    // and `end` is "no chunk left" rather than an index compared to a length.
    for fragment_id in 0u64.. {
        let Some(chunk) = chunks.next() else {
            break;
        };
        out.push(Fragment {
            object_id,
            fragment_id,
            start: fragment_id == 0,
            end: chunks.peek().is_none(),
            blob: chunk.to_vec(),
        });
    }
    out
}

/// Encode every fragment produced by [`split_message`] into a single
/// concatenated byte buffer ready to be sent via `Shell::send_input`.
#[must_use]
pub fn encode_message(object_id: u64, payload: &[u8]) -> Vec<u8> {
    let frags = split_message(object_id, payload);
    // Capacity hint only: the sum of in-memory `Vec` lengths cannot overflow.
    let total: usize = frags
        .iter()
        .map(|f| FRAGMENT_HEADER_LEN.saturating_add(f.blob.len()))
        .fold(0, usize::saturating_add);
    let mut out = Vec::with_capacity(total);
    for f in frags {
        out.extend_from_slice(&f.encode());
    }
    out
}

/// Default cap on what a [`Reassembler`] holds for messages still incomplete,
/// and so on the size of one reassembled message: 200 MiB (209 715 200
/// bytes), the default of PowerShell's own client
/// (`MaximumReceivedObjectSize`).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 200 * 1024 * 1024;

/// What an incomplete message costs against the cap besides its bytes, so
/// that a server opening objects it never fills is bounded too.
const IN_FLIGHT_OVERHEAD: usize = 64;

/// Capacity above which the receive buffer is given back once most of it is
/// unused: a single large chunk must not pin its high-water mark for the
/// life of the pool.
const BUFFER_KEEP: usize = 1024 * 1024;

/// Track partial messages so they can be emitted whole once the final
/// fragment arrives. One exists from the start fragment to the end one.
#[derive(Debug, Default)]
struct InFlight {
    buf: Vec<u8>,
    next_fragment_id: u64,
}

/// What [`decode_one`] found at the start of the buffer.
#[derive(Debug)]
enum Decoded {
    /// The header or the blob is not all there yet: a normal condition, the
    /// caller waits for more bytes.
    Incomplete,
    /// A whole fragment, and the number of bytes it occupies (header
    /// included).
    Whole(Fragment, usize),
    /// A header that announces a blob longer than the cap leaves. Known as
    /// soon as the header is read, before a byte of the blob is waited for.
    TooLong { object_id: u64, blob_len: usize },
}

/// Decode the first fragment of `buf`, if it is complete and its blob is at
/// most `max_blob` bytes (what the cap leaves).
fn decode_one(buf: &[u8], max_blob: usize) -> Result<Decoded> {
    let Some((object_id, rest)) = buf.split_first_chunk::<8>() else {
        return Ok(Decoded::Incomplete);
    };
    let Some((fragment_id, rest)) = rest.split_first_chunk::<8>() else {
        return Ok(Decoded::Incomplete);
    };
    let Some((&[flags], rest)) = rest.split_first_chunk::<1>() else {
        return Ok(Decoded::Incomplete);
    };
    let Some((blob_len, rest)) = rest.split_first_chunk::<4>() else {
        return Ok(Decoded::Incomplete);
    };
    let object_id = u64::from_be_bytes(*object_id);
    let blob_len = usize::try_from(u32::from_be_bytes(*blob_len))
        .map_err(|_| PsrpError::fragment("fragment length exceeds the address space"))?;
    if blob_len > max_blob {
        return Ok(Decoded::TooLong {
            object_id,
            blob_len,
        });
    }
    let Some(blob) = rest.get(..blob_len) else {
        return Ok(Decoded::Incomplete);
    };
    // Cannot saturate: `blob_len <= rest.len()`, so the sum is at most
    // `buf.len()`.
    let consumed = FRAGMENT_HEADER_LEN.saturating_add(blob_len);
    Ok(Decoded::Whole(
        Fragment {
            object_id,
            fragment_id: u64::from_be_bytes(*fragment_id),
            start: flags & FLAG_START != 0,
            end: flags & FLAG_END != 0,
            blob: blob.to_vec(),
        },
        consumed,
    ))
}

/// Stateful reassembler for incoming PSRP fragments.
///
/// Bytes from `Shell::receive_next` can be fed in arbitrary chunks. Whenever
/// a complete message is reconstructed (from the `start` fragment through the
/// `end` fragment), its payload is returned in order from [`Reassembler::feed`].
///
/// What it holds for messages still incomplete is capped (see
/// [`Reassembler::with_max_message_size`]): the bytes come from the remote
/// host, and a message that never ends, or a fragment announcing 4 GiB,
/// would otherwise be buffered until the process runs out of memory. The
/// cap counts payload bytes; the memory in use stays within a small
/// multiple of it (the fragment being received is buffered until it is
/// whole, and a growing message is moved as it grows).
///
/// [`feed`](Reassembler::feed) returns an error for a fragment it refuses
/// (over the cap, out of order, without a start) and drops that fragment:
/// the reassembler stays in step with the stream, and the next call goes on
/// with what follows. The messages completed earlier in the same call are
/// lost with the error.
#[derive(Debug)]
pub struct Reassembler {
    buffer: Vec<u8>,
    in_flight: HashMap<u64, InFlight>,
    /// Bytes charged for the messages in flight: their payload so far plus
    /// [`IN_FLIGHT_OVERHEAD`] each. Never above `max_message_size`.
    held: usize,
    max_message_size: usize,
    /// Bytes still to come of a fragment refused on its header: dropped as
    /// they arrive, never buffered. The buffer is empty while this is not 0.
    skip: usize,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::with_max_message_size(DEFAULT_MAX_MESSAGE_SIZE)
    }
}

impl Reassembler {
    /// Create a fresh reassembler with the default cap,
    /// [`DEFAULT_MAX_MESSAGE_SIZE`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a reassembler that holds at most `max` bytes of payload for
    /// the messages still incomplete, all of them together. A message cannot
    /// be larger than that either, and a fragment announcing more than what
    /// is left is refused when its header is read.
    #[must_use]
    pub fn with_max_message_size(max: usize) -> Self {
        Self {
            buffer: Vec::new(),
            in_flight: HashMap::new(),
            held: 0,
            max_message_size: max,
            skip: 0,
        }
    }

    /// The cap set by [`with_max_message_size`](Self::with_max_message_size).
    #[must_use]
    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Forget everything held: the bytes buffered, the messages in flight
    /// and what is left to skip of a refused fragment. The cap is kept.
    ///
    /// For a caller whose bytes start coming from another stream, one that
    /// continues nothing of the stream before: a
    /// [`RunspacePool`](crate::RunspacePool) does it when its transport
    /// starts a pipeline on a stream of its own (see
    /// [`PsrpTransport::pipeline_has_its_own_stream`](crate::transport::PsrpTransport::pipeline_has_its_own_stream)).
    pub fn clear(&mut self) {
        self.buffer = Vec::new();
        self.in_flight = HashMap::new();
        self.held = 0;
        self.skip = 0;
    }

    /// Change the cap. Messages already in flight are kept: the new cap
    /// applies to the next fragment.
    pub fn set_max_message_size(&mut self, max: usize) {
        self.max_message_size = max;
    }

    /// Feed raw bytes received from the transport and return every message
    /// payload that becomes complete as a result.
    ///
    /// # Errors
    ///
    /// [`PsrpError::Fragment`] for a fragment that is refused. It ends the
    /// call: the messages completed before it in the same call are not
    /// returned, and the fragments after it stay buffered until the next
    /// call (an empty `feed` is enough to get them).
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        // What is left of a fragment refused on its header is not buffered.
        let skipped = self.skip.min(bytes.len());
        self.skip = self.skip.saturating_sub(skipped);
        self.buffer
            .extend_from_slice(bytes.get(skipped..).unwrap_or_default());
        let mut consumed = 0;
        let completed = self.take_fragments(&mut consumed);
        // One shift for the whole chunk, error or not. Draining after each
        // fragment moved the rest of the buffer every time: quadratic in the
        // number of fragments of a chunk, which the server chooses.
        self.buffer.drain(..consumed.min(self.buffer.len()));
        // Whole when it is empty, down to twice what is left otherwise: a
        // server that ends every chunk on a partial header never leaves it
        // empty.
        if self.buffer.capacity() > BUFFER_KEEP {
            if self.buffer.is_empty() {
                self.buffer = Vec::new();
            } else if self.buffer.len() <= self.buffer.capacity() / 4 {
                let keep = self.buffer.len().saturating_mul(2).max(BUFFER_KEEP);
                self.buffer.shrink_to(keep);
            }
        }
        completed
    }

    /// Take every complete fragment out of the buffer, from `*consumed` on,
    /// advancing it past each one (a refused fragment included, so that it is
    /// dropped with the rest).
    fn take_fragments(&mut self, consumed: &mut usize) -> Result<Vec<Vec<u8>>> {
        let mut completed = Vec::new();

        loop {
            let pending = self.buffer.get(*consumed..).unwrap_or_default();
            // A fragment larger than what the cap leaves can never be
            // accepted: it is refused on its header, not once received.
            let left = self.max_message_size.saturating_sub(self.held);
            let (fragment, len) = match decode_one(pending, left)? {
                Decoded::Incomplete => break,
                Decoded::Whole(fragment, len) => (fragment, len),
                Decoded::TooLong {
                    object_id,
                    blob_len,
                } => {
                    // Dropped with what has arrived of its blob; the rest is
                    // skipped as it comes (`feed`), so the stream stays in
                    // step and a caller that reads on after this error does
                    // not pile the refused bytes up behind the header.
                    let arrived = pending
                        .len()
                        .saturating_sub(FRAGMENT_HEADER_LEN)
                        .min(blob_len);
                    *consumed = consumed
                        .saturating_add(FRAGMENT_HEADER_LEN)
                        .saturating_add(arrived);
                    self.skip = blob_len.saturating_sub(arrived);
                    self.refuse(object_id);
                    return Err(PsrpError::fragment(format!(
                        "a {blob_len}-byte fragment of object {object_id} exceeds the \
                         {}-byte message limit ({left} bytes left)",
                        self.max_message_size
                    )));
                }
            };
            *consumed = consumed.saturating_add(len);
            let Fragment {
                object_id,
                fragment_id,
                start,
                end,
                blob,
            } = fragment;

            // An entry exists only for a started message, so a refused
            // fragment leaves nothing behind.
            if start {
                if self.in_flight.contains_key(&object_id) {
                    return Err(PsrpError::fragment(format!(
                        "duplicate start fragment for object {object_id}"
                    )));
                }
                if fragment_id != 0 {
                    return Err(PsrpError::fragment(format!(
                        "start fragment for object {object_id} has non-zero fragment id {fragment_id}"
                    )));
                }
                self.charge(IN_FLIGHT_OVERHEAD, object_id)?;
                self.in_flight.insert(object_id, InFlight::default());
            }
            let Some(expected) = self
                .in_flight
                .get(&object_id)
                .map(|entry| entry.next_fragment_id)
            else {
                return Err(PsrpError::fragment(format!(
                    "continuation fragment before start for object {object_id}"
                )));
            };
            if fragment_id != expected {
                return Err(PsrpError::fragment(format!(
                    "out-of-order fragment for object {object_id}: expected {expected}, got {fragment_id}"
                )));
            }
            let next_fragment_id = fragment_id.checked_add(1).ok_or_else(|| {
                PsrpError::fragment(format!("fragment id overflow for object {object_id}"))
            })?;
            if let Err(over) = self.charge(blob.len(), object_id) {
                self.refuse(object_id);
                return Err(over);
            }

            if end {
                let mut done = self
                    .in_flight
                    .remove(&object_id)
                    .map_or_default(|entry| entry.buf);
                done.extend_from_slice(&blob);
                self.held = self
                    .held
                    .saturating_sub(done.len().saturating_add(IN_FLIGHT_OVERHEAD));
                completed.push(done);
            } else if let Some(entry) = self.in_flight.get_mut(&object_id) {
                entry.next_fragment_id = next_fragment_id;
                entry.buf.extend_from_slice(&blob);
            }
        }

        Ok(completed)
    }

    /// Refuse the message of `object_id` whole: what it held is released.
    fn refuse(&mut self, object_id: u64) {
        if let Some(entry) = self.in_flight.remove(&object_id) {
            self.held = self
                .held
                .saturating_sub(entry.buf.len().saturating_add(IN_FLIGHT_OVERHEAD));
        }
    }

    /// Count `bytes` more for the messages in flight, or refuse them when
    /// that would pass the cap.
    fn charge(&mut self, bytes: usize, object_id: u64) -> Result<()> {
        let held = self.held.saturating_add(bytes);
        if held > self.max_message_size {
            return Err(PsrpError::fragment(format!(
                "object {object_id} would bring the incomplete messages over the {}-byte limit",
                self.max_message_size
            )));
        }
        self.held = held;
        Ok(())
    }

    /// True if there are no partially-accumulated messages, no leftover
    /// buffered bytes and no refused fragment still arriving.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.buffer.is_empty() && self.in_flight.is_empty() && self.skip == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrip_single_fragment() {
        let payload = b"hello world".to_vec();
        let bytes = encode_message(42, &payload);
        let mut r = Reassembler::new();
        let out = r.feed(&bytes).unwrap();
        assert_eq!(out, vec![payload]);
        assert!(r.is_idle());
    }

    #[test]
    fn empty_message_roundtrip() {
        let bytes = encode_message(7, b"");
        let mut r = Reassembler::new();
        let out = r.feed(&bytes).unwrap();
        assert_eq!(out, vec![Vec::<u8>::new()]);
    }

    #[test]
    fn splits_at_max_fragment_payload() {
        let payload = vec![0xABu8; MAX_FRAGMENT_PAYLOAD * 2 + 10];
        let frags = split_message(1, &payload);
        assert_eq!(frags.len(), 3);
        assert!(frags[0].start && !frags[0].end);
        assert!(!frags[1].start && !frags[1].end);
        assert!(!frags[2].start && frags[2].end);
        assert_eq!(frags[0].blob.len(), MAX_FRAGMENT_PAYLOAD);
        assert_eq!(frags[1].blob.len(), MAX_FRAGMENT_PAYLOAD);
        assert_eq!(frags[2].blob.len(), 10);

        let bytes = encode_message(1, &payload);
        let mut r = Reassembler::new();
        let out = r.feed(&bytes).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], payload);
    }

    #[test]
    fn feed_byte_by_byte() {
        let payload = b"PSRP fragments love being cruelly sliced".to_vec();
        let bytes = encode_message(9, &payload);
        let mut r = Reassembler::new();
        let mut got = Vec::new();
        for b in &bytes {
            got.extend(r.feed(&[*b]).unwrap());
        }
        assert_eq!(got, vec![payload]);
    }

    #[test]
    fn feed_header_split() {
        // split exactly in the middle of the header
        let payload = b"halfway header".to_vec();
        let bytes = encode_message(2, &payload);
        let (a, b) = bytes.split_at(10);
        let mut r = Reassembler::new();
        let fed = r.feed(a).unwrap();
        assert!(fed.is_empty(), "{fed:?}");
        let out = r.feed(b).unwrap();
        assert_eq!(out, vec![payload]);
    }

    #[test]
    fn interleaved_object_ids() {
        // Message A: 2 fragments; Message B: 1 fragment. We send them
        // interleaved: A0 B0 A1. Wire order MUST preserve per-object fragment
        // ordering, which it does here.
        let a_payload = vec![0xAA; MAX_FRAGMENT_PAYLOAD + 5];
        let b_payload = b"beta".to_vec();

        let a_frags = split_message(100, &a_payload);
        let b_frags = split_message(200, &b_payload);

        let mut wire = Vec::new();
        wire.extend_from_slice(&a_frags[0].encode());
        wire.extend_from_slice(&b_frags[0].encode());
        wire.extend_from_slice(&a_frags[1].encode());

        let mut r = Reassembler::new();
        let out = r.feed(&wire).unwrap();
        // B completes first, then A.
        assert_eq!(out, vec![b_payload, a_payload]);
        assert!(r.is_idle());
    }

    #[test]
    fn rejects_continuation_before_start() {
        // Fabricate a fragment with flags=0 and fragment_id=0 without a
        // preceding start fragment.
        let f = Fragment {
            object_id: 5,
            fragment_id: 0,
            start: false,
            end: true,
            blob: b"oops".to_vec(),
        };
        let mut r = Reassembler::new();
        let err = r.feed(&f.encode()).unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)));
    }

    #[test]
    fn rejects_duplicate_start() {
        let f1 = Fragment {
            object_id: 5,
            fragment_id: 0,
            start: true,
            end: false,
            blob: b"a".to_vec(),
        };
        let f2 = Fragment {
            object_id: 5,
            fragment_id: 0,
            start: true,
            end: false,
            blob: b"b".to_vec(),
        };
        let mut r = Reassembler::new();
        r.feed(&f1.encode()).unwrap();
        let err = r.feed(&f2.encode()).unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)));
    }

    #[test]
    fn rejects_out_of_order_fragment_id() {
        let f0 = Fragment {
            object_id: 5,
            fragment_id: 0,
            start: true,
            end: false,
            blob: b"a".to_vec(),
        };
        let f2 = Fragment {
            object_id: 5,
            fragment_id: 2,
            start: false,
            end: true,
            blob: b"c".to_vec(),
        };
        let mut r = Reassembler::new();
        r.feed(&f0.encode()).unwrap();
        let err = r.feed(&f2.encode()).unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)));
    }

    #[test]
    fn rejects_start_with_nonzero_fragment_id() {
        let f = Fragment {
            object_id: 5,
            fragment_id: 3,
            start: true,
            end: true,
            blob: b"a".to_vec(),
        };
        let mut r = Reassembler::new();
        let err = r.feed(&f.encode()).unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)));
    }

    #[test]
    fn fragment_encode_flags_start_only() {
        let f = Fragment {
            object_id: 1,
            fragment_id: 0,
            start: true,
            end: false,
            blob: b"x".to_vec(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[16], 0x01);
    }

    #[test]
    fn fragment_encode_flags_end_only() {
        let f = Fragment {
            object_id: 1,
            fragment_id: 1,
            start: false,
            end: true,
            blob: b"x".to_vec(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[16], 0x02);
    }

    #[test]
    fn fragment_encode_flags_both() {
        let f = Fragment {
            object_id: 1,
            fragment_id: 0,
            start: true,
            end: true,
            blob: b"x".to_vec(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[16], 0x03);
    }

    #[test]
    fn max_fragment_payload_value() {
        assert_eq!(MAX_FRAGMENT_PAYLOAD, 32_768);
    }

    #[test]
    fn fragment_encode_flags_none() {
        let f = Fragment {
            object_id: 1,
            fragment_id: 1,
            start: false,
            end: false,
            blob: b"x".to_vec(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[16], 0x00);
    }

    #[test]
    fn end_flag_on_last_chunk_when_payload_is_exact_multiple() {
        let payload = vec![1u8; MAX_FRAGMENT_PAYLOAD * 2];
        let frags = split_message(3, &payload);
        assert_eq!(frags.len(), 2);
        assert!(frags[0].start && !frags[0].end);
        assert!(!frags[1].start && frags[1].end);
        assert_eq!(frags[1].fragment_id, 1);
    }

    /// A header and `tail`: one fragment announcing `len` bytes of blob.
    fn header_announcing(len: u32, flags: u8, tail: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&1u64.to_be_bytes());
        wire.extend_from_slice(&0u64.to_be_bytes());
        wire.push(flags);
        wire.extend_from_slice(&len.to_be_bytes());
        wire.extend_from_slice(tail);
        wire
    }

    #[test]
    fn long_blob_under_the_cap_waits_for_more_bytes() {
        // Header announcing 1 MiB with only 3 bytes behind it: no panic,
        // nothing emitted, bytes stay buffered.
        let wire = header_announcing(1 << 20, FLAG_START | FLAG_END, b"abc");
        let mut r = Reassembler::new();
        let out = r.feed(&wire).unwrap();
        assert_eq!(out.len(), 0);
        assert!(!r.is_idle());
    }

    #[test]
    fn hostile_huge_length_is_refused_at_the_header() {
        // 4 GiB - 1 announced: refused on the header alone, in one chunk or
        // byte by byte, instead of buffering until the blob is complete.
        let wire = header_announcing(u32::MAX, FLAG_START | FLAG_END, b"abc");
        let err = Reassembler::new().feed(&wire).unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)), "{err:?}");
        assert!(err.to_string().contains("message limit"), "{err}");

        let mut r = Reassembler::new();
        let (header, rest) = wire.split_at(FRAGMENT_HEADER_LEN - 1);
        for byte in header {
            assert_eq!(r.feed(&[*byte]).unwrap().len(), 0);
        }
        assert!(r.feed(&rest[..1]).is_err(), "the 21st byte completes it");
    }

    #[test]
    fn default_cap_is_powershell_s_200_mib() {
        assert_eq!(DEFAULT_MAX_MESSAGE_SIZE, 200 << 20);
        assert_eq!(Reassembler::new().max_message_size(), 200 << 20);
        assert_eq!(Reassembler::default().max_message_size(), 200 << 20);
        let mut r = Reassembler::with_max_message_size(10);
        assert_eq!(r.max_message_size(), 10);
        r.set_max_message_size(11);
        assert_eq!(r.max_message_size(), 11);
    }

    /// The cap counts the payload plus [`IN_FLIGHT_OVERHEAD`] per message.
    #[test]
    fn a_message_at_the_cap_passes_and_one_byte_more_is_refused() {
        let cap = IN_FLIGHT_OVERHEAD + 100;
        let fits = vec![7u8; 100];
        let mut r = Reassembler::with_max_message_size(cap);
        assert_eq!(r.feed(&encode_message(1, &fits)).unwrap(), vec![fits]);
        assert!(r.is_idle());
        assert_eq!(r.held, 0, "a completed message is no longer counted");

        // One byte more, in one fragment: refused when the blob is charged,
        // and nothing of the refused message stays counted or buffered.
        let err = r.feed(&encode_message(2, &[7u8; 101])).unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
        assert_eq!(r.held, 0);
        assert!(r.is_idle());
    }

    /// A message that never ends is refused once it has grown to the cap,
    /// whatever the size of its fragments.
    #[test]
    fn an_endless_message_stops_at_the_cap() {
        let cap = IN_FLIGHT_OVERHEAD + 1000;
        let mut r = Reassembler::with_max_message_size(cap);
        let mut accepted = 0usize;
        let err = loop {
            let f = Fragment {
                object_id: 9,
                fragment_id: u64::try_from(accepted / 100).unwrap(),
                start: accepted == 0,
                end: false,
                blob: vec![1u8; 100],
            };
            match r.feed(&f.encode()) {
                Ok(done) => {
                    assert_eq!(done.len(), 0);
                    accepted += 100;
                }
                Err(e) => break e,
            }
            assert!(accepted <= 1000, "nothing stopped the message");
        };
        assert_eq!(accepted, 1000, "exactly the cap was accepted");
        assert!(err.to_string().contains("object 9"), "{err}");
    }

    /// Objects opened and never filled cost [`IN_FLIGHT_OVERHEAD`] each.
    #[test]
    fn empty_objects_in_flight_are_bounded_too() {
        let mut r = Reassembler::with_max_message_size(IN_FLIGHT_OVERHEAD * 3);
        let start = |id: u64| {
            Fragment {
                object_id: id,
                fragment_id: 0,
                start: true,
                end: false,
                blob: Vec::new(),
            }
            .encode()
        };
        for id in 1..=3 {
            r.feed(&start(id)).unwrap();
        }
        assert!(r.feed(&start(4)).is_err(), "a fourth one passes the cap");
        assert_eq!(r.in_flight.len(), 3, "the refused object left no entry");
    }

    /// What is held for incomplete messages counts against the next
    /// fragment as soon as its header is read.
    #[test]
    fn a_fragment_over_what_is_left_is_refused_at_the_header() {
        let cap = IN_FLIGHT_OVERHEAD + 100;
        let mut r = Reassembler::with_max_message_size(cap);
        let first = Fragment {
            object_id: 1,
            fragment_id: 0,
            start: true,
            end: false,
            blob: vec![0u8; 60],
        };
        assert_eq!(r.feed(&first.encode()).unwrap().len(), 0);
        assert_eq!(r.held, IN_FLIGHT_OVERHEAD + 60);

        // 40 bytes are left: a header announcing 41 is refused with no blob
        // behind it, one announcing 40 waits for them.
        let header = |len: u32| {
            let mut wire = Vec::new();
            wire.extend_from_slice(&1u64.to_be_bytes());
            wire.extend_from_slice(&1u64.to_be_bytes());
            wire.push(FLAG_END);
            wire.extend_from_slice(&len.to_be_bytes());
            wire
        };
        let mut waiting = Reassembler::with_max_message_size(cap);
        waiting.feed(&first.encode()).unwrap();
        assert_eq!(waiting.feed(&header(40)).unwrap().len(), 0);
        assert_eq!(
            waiting.feed(&[7u8; 40]).unwrap(),
            vec![[vec![0u8; 60], vec![7u8; 40]].concat()]
        );

        let err = r.feed(&header(41)).unwrap_err();
        assert!(err.to_string().contains("(40 bytes left)"), "{err}");
        assert!(err.to_string().contains("object 1"), "{err}");
        // The message is refused whole, and its 41 bytes are still expected.
        assert_eq!((r.held, r.in_flight.len(), r.skip), (0, 0, 41));
        assert!(!r.is_idle());
    }

    /// Regression: a header refused for the cap stayed at the front of the
    /// buffer, so every later `feed` failed on it again and kept the bytes it
    /// was given: a caller reading on after the error grew the buffer without
    /// limit. The refused fragment is now dropped, the part of its blob still
    /// to come is skipped unbuffered, and the stream goes on in step.
    #[test]
    fn a_fragment_refused_on_its_header_is_skipped_as_it_arrives() {
        let too_long = Fragment {
            object_id: 5,
            fragment_id: 0,
            start: true,
            end: true,
            blob: vec![9u8; 5000],
        }
        .encode();
        let next = encode_message(6, b"next");

        // Cut inside the blob, then byte by byte, then with what follows in
        // the same chunk as the last skipped byte.
        for cut in [FRAGMENT_HEADER_LEN, FRAGMENT_HEADER_LEN + 1, 3000] {
            let mut r = Reassembler::with_max_message_size(1000);
            assert_eq!(r.feed(&encode_message(1, b"ok")).unwrap().len(), 1);
            let (head, tail) = too_long.split_at(cut);
            let err = r.feed(head).unwrap_err();
            assert!(err.to_string().contains("a 5000-byte fragment"), "{err}");
            assert_eq!(r.skip, too_long.len() - cut, "cut at {cut}");
            assert_eq!((r.buffer.len(), r.held), (0, 0));

            let (alone, last) = tail.split_at(tail.len() - 1);
            for piece in alone.chunks(700) {
                assert_eq!(r.feed(piece).unwrap().len(), 0);
                assert_eq!(r.buffer.len(), 0, "skipped bytes are not kept");
            }
            let wire = [last, &next].concat();
            assert_eq!(r.feed(&wire).unwrap(), vec![b"next".to_vec()]);
            assert!(r.is_idle());
        }

        // All in one chunk: the error first, then what followed it.
        let mut r = Reassembler::with_max_message_size(1000);
        let wire = [too_long.as_slice(), &next].concat();
        assert!(r.feed(&wire).is_err());
        assert_eq!(r.skip, 0);
        assert_eq!(r.feed(&[]).unwrap(), vec![b"next".to_vec()]);
        assert!(r.is_idle());

        // Reading on after the error never grows the buffer.
        let mut r = Reassembler::with_max_message_size(1000);
        let huge = header_announcing(u32::MAX, FLAG_START | FLAG_END, b"");
        assert!(r.feed(&huge).is_err());
        for _ in 0..100 {
            assert_eq!(r.feed(&[0u8; 4096]).unwrap().len(), 0);
        }
        assert!(
            r.buffer.capacity() < 4096,
            "only the header was ever buffered"
        );
        assert_eq!(r.skip, usize::try_from(u32::MAX).unwrap() - 100 * 4096);
    }

    /// A refused fragment leaves no entry behind, and is dropped from the
    /// buffer with what came before it.
    #[test]
    fn a_refused_fragment_leaves_the_reassembler_idle() {
        let stray = Fragment {
            object_id: 3,
            fragment_id: 1,
            start: false,
            end: false,
            blob: b"x".to_vec(),
        };
        let mut wire = encode_message(1, b"ok");
        wire.extend_from_slice(&stray.encode());
        let mut r = Reassembler::new();
        assert!(r.feed(&wire).is_err());
        assert!(r.is_idle(), "nothing buffered, no entry for object 3");
        // The stream is usable again for well-formed fragments.
        assert_eq!(
            r.feed(&encode_message(4, b"next")).unwrap(),
            vec![b"next".to_vec()]
        );
    }

    /// What an error costs: the messages completed before the refused
    /// fragment in the same call, and nothing after it.
    #[test]
    fn an_error_loses_what_came_before_it_in_the_call_and_keeps_what_follows() {
        let stray = Fragment {
            object_id: 3,
            fragment_id: 1,
            start: false,
            end: false,
            blob: b"x".to_vec(),
        };
        let mut wire = encode_message(1, b"before");
        wire.extend_from_slice(&stray.encode());
        wire.extend_from_slice(&encode_message(4, b"after"));
        wire.extend_from_slice(&encode_message(5, b"last"));

        let mut r = Reassembler::new();
        assert!(r.feed(&wire).is_err());
        assert!(!r.is_idle(), "what follows the stray fragment is kept");
        assert_eq!(
            r.feed(&[]).unwrap(),
            vec![b"after".to_vec(), b"last".to_vec()]
        );
        assert!(r.is_idle());
    }

    /// Regression: `feed` shifted the buffer once per fragment, so a chunk
    /// of n fragments cost n^2/2 fragment moves. 37 000 empty fragments in
    /// one 777 KiB chunk took over half a second; it must now take about as
    /// long as feeding them one by one.
    #[test]
    fn many_small_fragments_in_one_chunk_are_linear() {
        let n: u64 = 37_000;
        let mut wire = Vec::new();
        for i in 0..n {
            wire.extend_from_slice(
                &Fragment {
                    object_id: 1,
                    fragment_id: i,
                    start: i == 0,
                    end: i == n - 1,
                    blob: Vec::new(),
                }
                .encode(),
            );
        }
        let mut one_by_one = Reassembler::new();
        let started = std::time::Instant::now();
        for fragment in wire.chunks(FRAGMENT_HEADER_LEN) {
            one_by_one.feed(fragment).unwrap();
        }
        let baseline = started.elapsed();

        let mut whole = Reassembler::new();
        let started = std::time::Instant::now();
        let done = whole.feed(&wire).unwrap();
        let single = started.elapsed();
        assert_eq!(done, vec![Vec::<u8>::new()]);
        assert!(whole.is_idle());
        // Quadratic was 9 times the baseline on this size; linear is under it.
        assert!(
            single <= baseline * 3 + std::time::Duration::from_millis(50),
            "one feed took {single:?}, fragment by fragment {baseline:?}"
        );
    }

    /// The buffer of a large chunk is released once it has been consumed.
    #[test]
    fn a_large_chunk_does_not_pin_the_buffer() {
        let payload = vec![0u8; BUFFER_KEEP * 2];
        let mut r = Reassembler::new();
        assert_eq!(r.feed(&encode_message(1, &payload)).unwrap().len(), 1);
        assert_eq!(r.buffer.capacity(), 0);

        // Nor when the chunk ends on the first bytes of another fragment,
        // which leave the buffer not empty.
        let mut wire = encode_message(2, &payload);
        wire.extend_from_slice(&[0u8; 5]);
        assert_eq!(r.feed(&wire).unwrap().len(), 1);
        assert_eq!(r.buffer.len(), 5);
        assert!(
            r.buffer.capacity() <= BUFFER_KEEP,
            "{}",
            r.buffer.capacity()
        );
        // A small buffer is left alone.
        let mut small = Reassembler::new();
        small.feed(&[0u8; 5]).unwrap();
        let capacity = small.buffer.capacity();
        small.feed(&[]).unwrap();
        assert_eq!(small.buffer.capacity(), capacity);
    }

    /// `clear` leaves nothing of the stream before, and keeps the cap.
    #[test]
    fn clear_forgets_everything_but_the_cap() {
        let mut r = Reassembler::with_max_message_size(1000);
        let open = Fragment {
            object_id: 1,
            fragment_id: 0,
            start: true,
            end: false,
            blob: vec![1u8; 10],
        };
        assert_eq!(r.feed(&open.encode()).unwrap().len(), 0);
        // A fragment refused on its header, its blob still to come, then the
        // first bytes of a header.
        assert!(r.feed(&header_announcing(5000, FLAG_END, b"")).is_err());
        assert_eq!(r.skip, 5000);
        let mut r2 = Reassembler::with_max_message_size(1000);
        r2.feed(&open.encode()).unwrap();
        r2.feed(&[0u8; 7]).unwrap();
        assert!(!r2.is_idle());

        for r in [&mut r, &mut r2] {
            r.clear();
            assert!(r.is_idle());
            assert_eq!((r.held, r.skip, r.buffer.capacity()), (0, 0, 0));
            assert_eq!(r.max_message_size(), 1000);
            // The next stream is read from its first byte, and may use the
            // object id the stream before left open.
            assert_eq!(
                r.feed(&encode_message(1, b"fresh")).unwrap(),
                vec![b"fresh".to_vec()]
            );
        }
    }

    #[test]
    fn rejects_fragment_id_overflow() {
        let mut r = Reassembler::new();
        r.in_flight.insert(
            5,
            InFlight {
                buf: Vec::new(),
                next_fragment_id: u64::MAX,
            },
        );
        let f = Fragment {
            object_id: 5,
            fragment_id: u64::MAX,
            start: false,
            end: false,
            blob: b"x".to_vec(),
        };
        let err = r.feed(&f.encode()).unwrap_err();
        assert!(matches!(err, PsrpError::Fragment(_)), "{err:?}");
    }

    #[test]
    fn is_idle_tracks_partial_state() {
        let payload = b"xxxxxxxxxx".to_vec();
        let bytes = encode_message(1, &payload);
        let mut r = Reassembler::new();
        assert!(r.is_idle());
        r.feed(&bytes[..15]).unwrap();
        assert!(!r.is_idle());
        r.feed(&bytes[15..]).unwrap();
        assert!(r.is_idle());
    }
}
