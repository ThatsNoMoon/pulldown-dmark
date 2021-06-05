//! The first pass resolves all block structure, generating an AST. Within a block, items
//! are in a linear chain with potential inline markup identified.

use std::cmp::max;

use crate::parse::{scan_containers, Allocations, Item, ItemBody};
use crate::scanners::*;

use crate::tree::Tree;

/// Runs the first pass, which resolves the block structure of the document,
/// and returns the resulting tree.
pub(crate) fn run_first_pass<'a>(text: &'a str) -> (Tree<Item>, Allocations<'a>) {
    // This is a very naive heuristic for the number of nodes
    // we'll need.
    let start_capacity = max(128, text.len() / 32);
    let lookup_table = &create_lut();
    let first_pass = FirstPass {
        text,
        tree: Tree::with_capacity(start_capacity),
        begin_list_item: false,
        last_line_blank: false,
        allocs: Allocations::new(),
        list_nesting: 0,
        lookup_table,
    };
    first_pass.run()
}

/// State for the first parsing pass.
struct FirstPass<'a, 'b> {
    text: &'a str,
    tree: Tree<Item>,
    begin_list_item: bool,
    last_line_blank: bool,
    allocs: Allocations<'a>,
    list_nesting: usize,
    lookup_table: &'b LookupTable,
}

impl<'a, 'b> FirstPass<'a, 'b> {
    fn run(mut self) -> (Tree<Item>, Allocations<'a>) {
        let mut ix = 0;
        while ix < self.text.len() {
            ix = self.parse_block(ix);
        }
        for _ in 0..self.tree.spine_len() {
            self.pop(ix);
        }
        (self.tree, self.allocs)
    }

    /// Returns offset after block.
    fn parse_block(&mut self, start_ix: usize) -> usize {
        let bytes = self.text.as_bytes();
        let mut line_start = LineStart::new(&bytes[start_ix..]);

        let i = scan_containers(&self.tree, &mut line_start);
        for _ in i..self.tree.spine_len() {
            self.pop(start_ix);
        }

        // Process new containers
        loop {
            let container_start = start_ix + line_start.bytes_scanned();
            if line_start.scan_blockquote_marker() {
                self.tree.append(Item {
                    start: container_start,
                    end: 0, // will get set later
                    body: ItemBody::BlockQuote,
                });
                self.tree.push();
            } else {
                break;
            }
        }

        let ix = start_ix + line_start.bytes_scanned();

        if let Some(n) = scan_blank_line(&bytes[ix..]) {
            if let Some(node_ix) = self.tree.peek_up() {
                match self.tree[node_ix].item.body {
                    ItemBody::BlockQuote => (),
                    _ => {
                        if self.begin_list_item {
                            // A list item can begin with at most one blank line.
                            self.pop(start_ix);
                        }
                        self.last_line_blank = true;
                    }
                }
            }
            return ix + n;
        }

        let indent = line_start.scan_space_upto(4);

        let ix = start_ix + line_start.bytes_scanned();

        if let Some((n, fence_ch)) = scan_code_fence(&bytes[ix..]) {
            return self.parse_fenced_code_block(ix, indent, fence_ch, n);
        }
        self.parse_paragraph(ix)
    }

    /// Returns offset of line start after paragraph.
    fn parse_paragraph(&mut self, start_ix: usize) -> usize {
        self.tree.append(Item {
            start: start_ix,
            end: 0, // will get set later
            body: ItemBody::Paragraph,
        });
        self.tree.push();
        let bytes = self.text.as_bytes();

        let mut ix = start_ix;
        loop {
            let (next_ix, brk) = self.parse_line(ix);

            ix = next_ix;
            let mut line_start = LineStart::new(&bytes[ix..]);
            scan_containers(&self.tree, &mut line_start);
            if !line_start.scan_space(4) {
                let ix_new = ix + line_start.bytes_scanned();
                // first check for non-empty lists, then for other interrupts
                let suffix = &bytes[ix_new..];
                if self.interrupt_paragraph_by_list(suffix) || scan_paragraph_interrupt(suffix) {
                    break;
                }
            }
            line_start.scan_all_space();
            if line_start.is_at_eol() {
                break;
            }
            ix = next_ix + line_start.bytes_scanned();
            if let Some(item) = brk {
                self.tree.append(item);
            }
        }

        self.pop(ix);
        ix
    }

    /// Parse a line of input, appending text and items to tree.
    ///
    /// Returns: index after line and an item representing the break.
    fn parse_line(&mut self, start: usize) -> (usize, Option<Item>) {
        let bytes = &self.text.as_bytes();
        let mut begin_text = start;

        let (final_ix, brk) =
            iterate_special_bytes(&self.lookup_table, bytes, start, |ix, byte| match byte {
                b'\n' | b'\r' => {
                    let mut i = ix;
                    let eol_bytes = scan_eol(&bytes[ix..]).unwrap();

                    let end_ix = ix + eol_bytes;
                    let trailing_backslashes = scan_rev_while(&bytes[..ix], |b| b == b'\\');
                    if trailing_backslashes % 2 == 1 && end_ix < self.text.len() {
                        i -= 1;
                        self.tree.append_text(begin_text, i);
                        return LoopInstruction::BreakAtWith(
                            end_ix,
                            Some(Item {
                                start: i,
                                end: end_ix,
                                body: ItemBody::HardBreak,
                            }),
                        );
                    }
                    let trailing_whitespace =
                        scan_rev_while(&bytes[..ix], is_ascii_whitespace_no_nl);
                    if trailing_whitespace >= 2 {
                        i -= trailing_whitespace;
                        self.tree.append_text(begin_text, i);
                        return LoopInstruction::BreakAtWith(
                            end_ix,
                            Some(Item {
                                start: i,
                                end: end_ix,
                                body: ItemBody::HardBreak,
                            }),
                        );
                    }

                    self.tree.append_text(begin_text, ix);
                    LoopInstruction::BreakAtWith(
                        end_ix,
                        Some(Item {
                            start: i,
                            end: end_ix,
                            body: ItemBody::SoftBreak,
                        }),
                    )
                }
                b'\\' => {
                    if ix + 1 < self.text.len() && is_ascii_punctuation(bytes[ix + 1]) {
                        self.tree.append_text(begin_text, ix);
                        if bytes[ix + 1] == b'`' {
                            let count = 1 + scan_ch_repeat(&bytes[(ix + 2)..], b'`');
                            self.tree.append(Item {
                                start: ix + 1,
                                end: ix + count + 1,
                                body: ItemBody::MaybeCode(count, true),
                            });
                            begin_text = ix + 1 + count;
                            LoopInstruction::ContinueAndSkip(count)
                        } else {
                            begin_text = ix + 1;
                            LoopInstruction::ContinueAndSkip(1)
                        }
                    } else {
                        LoopInstruction::ContinueAndSkip(0)
                    }
                }
                c @ b'*' | c @ b'_' | c @ b'~' => {
                    let string_suffix = &self.text[ix..];
                    let count = 1 + scan_ch_repeat(&string_suffix.as_bytes()[1..], c);
                    let can_open = delim_run_can_open(self.text, string_suffix, count, ix);
                    let can_close = delim_run_can_close(self.text, string_suffix, count, ix);
                    let is_valid_seq = c != b'~' || count == 2;

                    if (can_open || can_close) && is_valid_seq {
                        self.tree.append_text(begin_text, ix);
                        for i in 0..count {
                            self.tree.append(Item {
                                start: ix + i,
                                end: ix + i + 1,
                                body: ItemBody::MaybeEmphasis(count - i, can_open, can_close),
                            });
                        }
                        begin_text = ix + count;
                    }
                    LoopInstruction::ContinueAndSkip(count - 1)
                }
                b'`' => {
                    self.tree.append_text(begin_text, ix);
                    let count = 1 + scan_ch_repeat(&bytes[(ix + 1)..], b'`');
                    self.tree.append(Item {
                        start: ix,
                        end: ix + count,
                        body: ItemBody::MaybeCode(count, false),
                    });
                    begin_text = ix + count;
                    LoopInstruction::ContinueAndSkip(count - 1)
                }
                b'[' => {
                    self.tree.append_text(begin_text, ix);
                    self.tree.append(Item {
                        start: ix,
                        end: ix + 1,
                        body: ItemBody::MaybeLinkOpen,
                    });
                    begin_text = ix + 1;
                    LoopInstruction::ContinueAndSkip(0)
                }
                b']' => {
                    self.tree.append_text(begin_text, ix);
                    self.tree.append(Item {
                        start: ix,
                        end: ix + 1,
                        body: ItemBody::MaybeLinkClose(true),
                    });
                    begin_text = ix + 1;
                    LoopInstruction::ContinueAndSkip(0)
                }
                _ => LoopInstruction::ContinueAndSkip(0),
            });

        if brk.is_none() {
            // need to close text at eof
            self.tree.append_text(begin_text, final_ix);
        }
        (final_ix, brk)
    }

    /// Check whether we should allow a paragraph interrupt by lists. Only non-empty
    /// lists are allowed.
    fn interrupt_paragraph_by_list(&self, suffix: &[u8]) -> bool {
        scan_listitem(suffix).map_or(false, |(ix, delim, index, _)| {
            self.list_nesting > 0 ||
            // we don't allow interruption by either empty lists or
            // numbered lists starting at an index other than 1
            !scan_empty_list(&suffix[ix..]) && (delim == b'*' || delim == b'-' || index == 1)
        })
    }

    fn parse_fenced_code_block(
        &mut self,
        start_ix: usize,
        indent: usize,
        fence_ch: u8,
        n_fence_char: usize,
    ) -> usize {
        let bytes = self.text.as_bytes();
        let mut info_start = start_ix + n_fence_char;
        info_start += scan_whitespace_no_nl(&bytes[info_start..]);
        // TODO: info strings are typically very short. wouldnt it be faster
        // to just do a forward scan here?
        let mut ix = info_start + scan_nextline(&bytes[info_start..]);
        let info_end = ix - scan_rev_while(&bytes[info_start..ix], is_ascii_whitespace);
        let info_string = unescape(&self.text[info_start..info_end]);
        self.tree.append(Item {
            start: start_ix,
            end: 0, // will get set later
            body: ItemBody::FencedCodeBlock(self.allocs.allocate_cow(info_string)),
        });
        self.tree.push();
        loop {
            let mut line_start = LineStart::new(&bytes[ix..]);
            let n_containers = scan_containers(&self.tree, &mut line_start);
            if n_containers < self.tree.spine_len() {
                break;
            }
            line_start.scan_space(indent);
            let mut close_line_start = line_start.clone();
            if !close_line_start.scan_space(4) {
                let close_ix = ix + close_line_start.bytes_scanned();
                if let Some(n) = scan_closing_code_fence(&bytes[close_ix..], fence_ch, n_fence_char)
                {
                    ix = close_ix + n;
                    break;
                }
            }
            let remaining_space = line_start.remaining_space();
            ix += line_start.bytes_scanned();
            let next_ix = ix + scan_nextline(&bytes[ix..]);
            self.append_code_text(remaining_space, ix, next_ix);
            ix = next_ix;
        }

        self.pop(ix);

        // try to read trailing whitespace or it will register as a completely blank line
        ix + scan_blank_line(&bytes[ix..]).unwrap_or(0)
    }

    fn append_code_text(&mut self, remaining_space: usize, start: usize, end: usize) {
        if remaining_space > 0 {
            let cow_ix = self.allocs.allocate_cow("   "[..remaining_space].into());
            self.tree.append(Item {
                start,
                end: start,
                body: ItemBody::SynthesizeText(cow_ix),
            });
        }
        if self.text.as_bytes()[end - 2] == b'\r' {
            // Normalize CRLF to LF
            self.tree.append_text(start, end - 2);
            self.tree.append_text(end - 1, end);
        } else {
            self.tree.append_text(start, end);
        }
    }

    /// Pop a container, setting its end.
    fn pop(&mut self, ix: usize) {
        let cur_ix = self.tree.pop().unwrap();
        self.tree[cur_ix].item.end = ix;
    }
}

/// Checks whether we should break a paragraph on the given input.
/// Note: lists are dealt with in `interrupt_paragraph_by_list`, because determing
/// whether to break on a list requires additional context.
fn scan_paragraph_interrupt(bytes: &[u8]) -> bool {
    scan_eol(bytes).is_some()
        || scan_code_fence(bytes).is_some()
        || scan_blockquote_start(bytes).is_some()
}

/// Determines whether the delimiter run starting at given index is
/// left-flanking, as defined by the commonmark spec (and isn't intraword
/// for _ delims).
/// suffix is &s[ix..], which is passed in as an optimization, since taking
/// a string subslice is O(n).
fn delim_run_can_open(s: &str, suffix: &str, run_len: usize, ix: usize) -> bool {
    let next_char = if let Some(c) = suffix.chars().nth(run_len) {
        c
    } else {
        return false;
    };
    if next_char.is_whitespace() {
        return false;
    }
    if ix == 0 {
        return true;
    }
    let delim = suffix.chars().next().unwrap();
    if delim == '*' && !is_punctuation(next_char) {
        return true;
    }

    let prev_char = s[..ix].chars().last().unwrap();

    prev_char.is_whitespace()
        || is_punctuation(prev_char) && (delim != '\'' || ![']', ')'].contains(&prev_char))
}

/// Determines whether the delimiter run starting at given index is
/// left-flanking, as defined by the commonmark spec (and isn't intraword
/// for _ delims)
fn delim_run_can_close(s: &str, suffix: &str, run_len: usize, ix: usize) -> bool {
    if ix == 0 {
        return false;
    }
    let prev_char = s[..ix].chars().last().unwrap();
    if prev_char.is_whitespace() {
        return false;
    }
    let next_char = if let Some(c) = suffix.chars().nth(run_len) {
        c
    } else {
        return true;
    };
    let delim = suffix.chars().next().unwrap();
    if delim == '*' && !is_punctuation(prev_char) {
        return true;
    }

    next_char.is_whitespace() || is_punctuation(next_char)
}

fn create_lut() -> LookupTable {
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    {
        LookupTable {
            simd: simd::compute_lookup(),
            scalar: special_bytes(),
        }
    }
    #[cfg(not(all(target_arch = "x86_64", feature = "simd")))]
    {
        special_bytes()
    }
}

fn special_bytes() -> [bool; 256] {
    let mut bytes = [false; 256];
    let standard_bytes = [
        b'\n', b'\r', b'*', b'_', b'&', b'\\', b'[', b']', b'<', b'!', b'`', b'~',
    ];

    for &byte in &standard_bytes {
        bytes[byte as usize] = true;
    }

    bytes
}

enum LoopInstruction<T> {
    /// Continue looking for more special bytes, but skip next few bytes.
    ContinueAndSkip(usize),
    /// Break looping immediately, returning with the given index and value.
    BreakAtWith(usize, T),
}

#[cfg(all(target_arch = "x86_64", feature = "simd"))]
struct LookupTable {
    simd: [u8; 16],
    scalar: [bool; 256],
}

#[cfg(not(all(target_arch = "x86_64", feature = "simd")))]
type LookupTable = [bool; 256];

/// This function walks the byte slices from the given index and
/// calls the callback function on all bytes (and their indices) that are in the following set:
/// `` ` ``, `\`, `&`, `*`, `_`, `~`, `!`, `<`, `[`, `]`, `|`, `\r`, `\n`
/// It is guaranteed not call the callback on other bytes.
/// Whenever `callback(ix, byte)` returns a `ContinueAndSkip(n)` value, the callback
/// will not be called with an index that is less than `ix + n + 1`.
/// When the callback returns a `BreakAtWith(end_ix, opt+val)`, no more callbacks will be
/// called and the function returns immediately with the return value `(end_ix, opt_val)`.
/// If `BreakAtWith(..)` is never returned, this function will return the first
/// index that is outside the byteslice bound and a `None` value.
fn iterate_special_bytes<F, T>(
    lut: &LookupTable,
    bytes: &[u8],
    ix: usize,
    callback: F,
) -> (usize, Option<T>)
where
    F: FnMut(usize, u8) -> LoopInstruction<Option<T>>,
{
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    {
        simd::iterate_special_bytes(lut, bytes, ix, callback)
    }
    #[cfg(not(all(target_arch = "x86_64", feature = "simd")))]
    {
        scalar_iterate_special_bytes(lut, bytes, ix, callback)
    }
}

fn scalar_iterate_special_bytes<F, T>(
    lut: &[bool; 256],
    bytes: &[u8],
    mut ix: usize,
    mut callback: F,
) -> (usize, Option<T>)
where
    F: FnMut(usize, u8) -> LoopInstruction<Option<T>>,
{
    while ix < bytes.len() {
        let b = bytes[ix];
        if lut[b as usize] {
            match callback(ix, b) {
                LoopInstruction::ContinueAndSkip(skip) => {
                    ix += skip;
                }
                LoopInstruction::BreakAtWith(ix, val) => {
                    return (ix, val);
                }
            }
        }
        ix += 1;
    }

    (ix, None)
}

#[cfg(all(target_arch = "x86_64", feature = "simd"))]
mod simd {
    //! SIMD byte scanning logic.
    //!
    //! This module provides functions that allow walking through byteslices, calling
    //! provided callback functions on special bytes and their indices using SIMD.
    //! The byteset is defined in `compute_lookup`.
    //!
    //! The idea is to load in a chunk of 16 bytes and perform a lookup into a set of
    //! bytes on all the bytes in this chunk simultaneously. We produce a 16 bit bitmask
    //! from this and call the callback on every index corresponding to a 1 in this mask
    //! before moving on to the next chunk. This allows us to move quickly when there
    //! are no or few matches.
    //!
    //! The table lookup is inspired by this [great overview]. However, since all of the
    //! bytes we're interested in are ASCII, we don't quite need the full generality of
    //! the universal algorithm and are hence able to skip a few instructions.
    //!
    //! [great overview]: http://0x80.pl/articles/simd-byte-lookup.html

    use super::{LookupTable, LoopInstruction};
    use core::arch::x86_64::*;

    const VECTOR_SIZE: usize = std::mem::size_of::<__m128i>();

    /// Generates a lookup table containing the bitmaps for our
    /// special marker bytes. This is effectively a 128 element 2d bitvector,
    /// that can be indexed by a four bit row index (the lower nibble)
    /// and a three bit column index (upper nibble).
    pub(super) fn compute_lookup() -> [u8; 16] {
        let mut lookup = [0u8; 16];
        let standard_bytes = [
            b'\n', b'\r', b'*', b'_', b'\\', b'[', b']', b'!', b'`', b'~',
        ];

        for &byte in &standard_bytes {
            add_lookup_byte(&mut lookup, byte);
        }

        lookup
    }

    fn add_lookup_byte(lookup: &mut [u8; 16], byte: u8) {
        lookup[(byte & 0x0f) as usize] |= 1 << (byte >> 4);
    }

    /// Computes a bit mask for the given byteslice starting from the given index,
    /// where the 16 least significant bits indicate (by value of 1) whether or not
    /// there is a special character at that byte position. The least significant bit
    /// corresponds to `bytes[ix]` and the most significant bit corresponds to
    /// `bytes[ix + 15]`.
    /// It is only safe to call this function when `bytes.len() >= ix + VECTOR_SIZE`.
    #[target_feature(enable = "ssse3")]
    #[inline]
    unsafe fn compute_mask(lut: &[u8; 16], bytes: &[u8], ix: usize) -> i32 {
        debug_assert!(bytes.len() >= ix + VECTOR_SIZE);

        let bitmap = _mm_loadu_si128(lut.as_ptr() as *const __m128i);
        // Small lookup table to compute single bit bitshifts
        // for 16 bytes at once.
        let bitmask_lookup =
            _mm_setr_epi8(1, 2, 4, 8, 16, 32, 64, -128, -1, -1, -1, -1, -1, -1, -1, -1);

        // Load input from memory.
        let raw_ptr = bytes.as_ptr().add(ix) as *const __m128i;
        let input = _mm_loadu_si128(raw_ptr);
        // Compute the bitmap using the bottom nibble as an index
        // into the lookup table. Note that non-ascii bytes will have
        // their most significant bit set and will map to lookup[0].
        let bitset = _mm_shuffle_epi8(bitmap, input);
        // Compute the high nibbles of the input using a 16-bit rightshift of four
        // and a mask to prevent most-significant bit issues.
        let higher_nibbles = _mm_and_si128(_mm_srli_epi16(input, 4), _mm_set1_epi8(0x0f));
        // Create a bitmask for the bitmap by perform a left shift of the value
        // of the higher nibble. Bytes with their most significant set are mapped
        // to -1 (all ones).
        let bitmask = _mm_shuffle_epi8(bitmask_lookup, higher_nibbles);
        // Test the bit of the bitmap by AND'ing the bitmap and the mask together.
        let tmp = _mm_and_si128(bitset, bitmask);
        // Check whether the result was not null. NEQ is not a SIMD intrinsic,
        // but comparing to the bitmask is logically equivalent. This also prevents us
        // from matching any non-ASCII bytes since none of the bitmaps were all ones
        // (-1).
        let result = _mm_cmpeq_epi8(tmp, bitmask);

        // Return the resulting bitmask.
        _mm_movemask_epi8(result)
    }

    /// Calls callback on byte indices and their value.
    /// Breaks when callback returns LoopInstruction::BreakAtWith(ix, val). And skips the
    /// number of bytes in callback return value otherwise.
    /// Returns the final index and a possible break value.
    pub(super) fn iterate_special_bytes<F, T>(
        lut: &LookupTable,
        bytes: &[u8],
        ix: usize,
        callback: F,
    ) -> (usize, Option<T>)
    where
        F: FnMut(usize, u8) -> LoopInstruction<Option<T>>,
    {
        if is_x86_feature_detected!("ssse3") && bytes.len() >= VECTOR_SIZE {
            unsafe { simd_iterate_special_bytes(&lut.simd, bytes, ix, callback) }
        } else {
            super::scalar_iterate_special_bytes(&lut.scalar, bytes, ix, callback)
        }
    }

    /// Calls the callback function for every 1 in the given bitmask with
    /// the index `offset + ix`, where `ix` is the position of the 1 in the mask.
    /// Returns `Ok(ix)` to continue from index `ix`, `Err((end_ix, opt_val)` to break with
    /// final index `end_ix` and optional value `opt_val`.
    unsafe fn process_mask<F, T>(
        mut mask: i32,
        bytes: &[u8],
        mut offset: usize,
        callback: &mut F,
    ) -> Result<usize, (usize, Option<T>)>
    where
        F: FnMut(usize, u8) -> LoopInstruction<Option<T>>,
    {
        while mask != 0 {
            let mask_ix = mask.trailing_zeros() as usize;
            offset += mask_ix;
            match callback(offset, *bytes.get_unchecked(offset)) {
                LoopInstruction::ContinueAndSkip(skip) => {
                    offset += skip + 1;
                    mask >>= skip + 1 + mask_ix;
                }
                LoopInstruction::BreakAtWith(ix, val) => return Err((ix, val)),
            }
        }
        Ok(offset)
    }

    #[target_feature(enable = "ssse3")]
    /// Important: only call this function when `bytes.len() >= 16`. Doing
    /// so otherwise may exhibit undefined behaviour.
    unsafe fn simd_iterate_special_bytes<F, T>(
        lut: &[u8; 16],
        bytes: &[u8],
        mut ix: usize,
        mut callback: F,
    ) -> (usize, Option<T>)
    where
        F: FnMut(usize, u8) -> LoopInstruction<Option<T>>,
    {
        debug_assert!(bytes.len() >= VECTOR_SIZE);
        let upperbound = bytes.len() - VECTOR_SIZE;

        while ix < upperbound {
            let mask = compute_mask(lut, bytes, ix);
            let block_start = ix;
            ix = match process_mask(mask, bytes, ix, &mut callback) {
                Ok(ix) => std::cmp::max(ix, VECTOR_SIZE + block_start),
                Err((end_ix, val)) => return (end_ix, val),
            };
        }

        if bytes.len() > ix {
            // shift off the bytes at start we have already scanned
            let mask = compute_mask(lut, bytes, upperbound) >> ix - upperbound;
            if let Err((end_ix, val)) = process_mask(mask, bytes, ix, &mut callback) {
                return (end_ix, val);
            }
        }

        (bytes.len(), None)
    }

    #[cfg(test)]
    mod simd_test {
        use super::super::create_lut;
        use super::{iterate_special_bytes, LoopInstruction};

        fn check_expected_indices(bytes: &[u8], expected: &[usize], skip: usize) {
            let lut = create_lut();
            let mut indices = vec![];

            iterate_special_bytes::<_, i32>(&lut, bytes, 0, |ix, _byte_ty| {
                indices.push(ix);
                LoopInstruction::ContinueAndSkip(skip)
            });

            assert_eq!(&indices[..], expected);
        }

        #[test]
        fn simple_no_match() {
            check_expected_indices("abcdef0123456789".as_bytes(), &[], 0);
        }

        #[test]
        fn simple_match() {
            check_expected_indices("*bcd_f0123456789".as_bytes(), &[0, 4], 0);
        }

        #[test]
        fn single_open_fish() {
            check_expected_indices("<".as_bytes(), &[0], 0);
        }

        #[test]
        fn long_match() {
            check_expected_indices("0123456789abcde~*bcd_f0".as_bytes(), &[15, 16, 20], 0);
        }

        #[test]
        fn border_skip() {
            check_expected_indices("0123456789abcde~~~~d_f0".as_bytes(), &[15, 20], 3);
        }

        #[test]
        fn exhaustive_search() {
            let chars = [
                b'\n', b'\r', b'*', b'_', b'\\', b'[', b']', b'!', b'`', b'~',
            ];

            for &c in &chars {
                for i in 0u8..=255 {
                    if !chars.contains(&i) {
                        // full match
                        let mut buf = [i; 18];
                        buf[3] = c;
                        buf[6] = c;

                        check_expected_indices(&buf[..], &[3, 6], 0);
                    }
                }
            }
        }
    }
}
