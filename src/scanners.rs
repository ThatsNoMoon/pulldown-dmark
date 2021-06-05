// Copyright 2015 Google Inc. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! Scanners for fragments of CommonMark syntax

use std::char;
use std::convert::TryInto;

use crate::entities;
pub(crate) use crate::puncttable::{is_ascii_punctuation, is_punctuation};
use crate::strings::CowStr;

use memchr::memchr;

/// Analysis of the beginning of a line, including indentation and container
/// markers.
#[derive(Clone)]
pub(crate) struct LineStart<'a> {
    bytes: &'a [u8],
    tab_start: usize,
    ix: usize,
    spaces_remaining: usize,
    // no thematic breaks can occur before this offset.
    // this prevents scanning over and over up to a certain point
    min_hrule_offset: usize,
}

impl<'a> LineStart<'a> {
    pub(crate) fn new(bytes: &[u8]) -> LineStart {
        LineStart {
            bytes,
            tab_start: 0,
            ix: 0,
            spaces_remaining: 0,
            min_hrule_offset: 0,
        }
    }

    /// Try to scan a number of spaces.
    ///
    /// Returns true if all spaces were consumed.
    ///
    /// Note: consumes some spaces even if not successful.
    pub(crate) fn scan_space(&mut self, n_space: usize) -> bool {
        self.scan_space_inner(n_space) == 0
    }

    /// Scan a number of spaces up to a maximum.
    ///
    /// Returns number of spaces scanned.
    pub(crate) fn scan_space_upto(&mut self, n_space: usize) -> usize {
        n_space - self.scan_space_inner(n_space)
    }

    /// Returns unused remainder of spaces.
    fn scan_space_inner(&mut self, mut n_space: usize) -> usize {
        let n_from_remaining = self.spaces_remaining.min(n_space);
        self.spaces_remaining -= n_from_remaining;
        n_space -= n_from_remaining;
        while n_space > 0 && self.ix < self.bytes.len() {
            match self.bytes[self.ix] {
                b' ' => {
                    self.ix += 1;
                    n_space -= 1;
                }
                b'\t' => {
                    let spaces = 4 - (self.ix - self.tab_start) % 4;
                    self.ix += 1;
                    self.tab_start = self.ix;
                    let n = spaces.min(n_space);
                    n_space -= n;
                    self.spaces_remaining = spaces - n;
                }
                _ => break,
            }
        }
        n_space
    }

    /// Scan all available ASCII whitespace (not including eol).
    pub(crate) fn scan_all_space(&mut self) {
        self.spaces_remaining = 0;
        self.ix += self.bytes[self.ix..]
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
    }

    /// Determine whether we're at end of line (includes end of file).
    pub(crate) fn is_at_eol(&self) -> bool {
        self.bytes
            .get(self.ix)
            .map(|&c| c == b'\r' || c == b'\n')
            .unwrap_or(true)
    }

    fn scan_ch(&mut self, c: u8) -> bool {
        if self.ix < self.bytes.len() && self.bytes[self.ix] == c {
            self.ix += 1;
            true
        } else {
            false
        }
    }

    pub(crate) fn scan_blockquote_marker(&mut self) -> bool {
        let save = self.clone();
        let _ = self.scan_space(3);
        if self.scan_ch(b'>') {
            let _ = self.scan_space(1);
            true
        } else {
            *self = save;
            false
        }
    }

    pub(crate) fn bytes_scanned(&self) -> usize {
        self.ix
    }

    pub(crate) fn remaining_space(&self) -> usize {
        self.spaces_remaining
    }
}

pub(crate) fn is_ascii_whitespace(c: u8) -> bool {
    (c >= 0x09 && c <= 0x0d) || c == b' '
}

pub(crate) fn is_ascii_whitespace_no_nl(c: u8) -> bool {
    c == b'\t' || c == 0x0b || c == 0x0c || c == b' '
}

fn is_ascii_alphanumeric(c: u8) -> bool {
    matches!(c, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

fn is_digit(c: u8) -> bool {
    b'0' <= c && c <= b'9'
}

// scan a single character
pub(crate) fn scan_ch(data: &[u8], c: u8) -> usize {
    if !data.is_empty() && data[0] == c {
        1
    } else {
        0
    }
}

pub(crate) fn scan_while<F>(data: &[u8], mut f: F) -> usize
where
    F: FnMut(u8) -> bool,
{
    data.iter().take_while(|&&c| f(c)).count()
}

pub(crate) fn scan_rev_while<F>(data: &[u8], mut f: F) -> usize
where
    F: FnMut(u8) -> bool,
{
    data.iter().rev().take_while(|&&c| f(c)).count()
}

pub(crate) fn scan_ch_repeat(data: &[u8], c: u8) -> usize {
    scan_while(data, |x| x == c)
}

// Note: this scans ASCII whitespace only, for Unicode whitespace use
// a different function.
pub(crate) fn scan_whitespace_no_nl(data: &[u8]) -> usize {
    scan_while(data, is_ascii_whitespace_no_nl)
}

pub(crate) fn scan_eol(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return Some(0);
    }
    match bytes[0] {
        b'\n' => Some(1),
        b'\r' => Some(if bytes.get(1) == Some(&b'\n') { 2 } else { 1 }),
        _ => None,
    }
}

pub(crate) fn scan_blank_line(bytes: &[u8]) -> Option<usize> {
    let i = scan_whitespace_no_nl(bytes);
    scan_eol(&bytes[i..]).map(|n| i + n)
}

pub(crate) fn scan_nextline(bytes: &[u8]) -> usize {
    memchr(b'\n', bytes).map_or(bytes.len(), |x| x + 1)
}

// return: end byte for closing code fence, or None
// if the line is not a closing code fence
pub(crate) fn scan_closing_code_fence(
    bytes: &[u8],
    fence_char: u8,
    n_fence_char: usize,
) -> Option<usize> {
    if bytes.is_empty() {
        return Some(0);
    }
    let mut i = 0;
    let num_fence_chars_found = scan_ch_repeat(&bytes[i..], fence_char);
    if num_fence_chars_found < n_fence_char {
        return None;
    }
    i += num_fence_chars_found;
    let num_trailing_spaces = scan_ch_repeat(&bytes[i..], b' ');
    i += num_trailing_spaces;
    scan_eol(&bytes[i..]).map(|_| i)
}

// returned pair is (number of bytes, number of spaces)
fn calc_indent(text: &[u8], max: usize) -> (usize, usize) {
    let mut spaces = 0;
    let mut offset = 0;

    for (i, &b) in text.iter().enumerate() {
        match b {
            b' ' => {
                spaces += 1;
                if spaces == max {
                    break;
                }
            }
            b'\t' => {
                let new_spaces = spaces + 4 - (spaces & 3);
                if new_spaces > max {
                    break;
                }
                spaces = new_spaces;
            }
            _ => break,
        }
        offset = i;
    }

    (offset, spaces)
}

/// Scan code fence.
///
/// Returns number of bytes scanned and the char that is repeated to make the code fence.
pub(crate) fn scan_code_fence(data: &[u8]) -> Option<(usize, u8)> {
    let c = *data.get(0)?;
    if !(c == b'`' || c == b'~') {
        return None;
    }
    let i = 1 + scan_ch_repeat(&data[1..], c);
    if i >= 3 {
        if c == b'`' {
            let suffix = &data[i..];
            let next_line = i + scan_nextline(suffix);
            // FIXME: make sure this is correct
            if suffix[..(next_line - i)].iter().any(|&b| b == b'`') {
                return None;
            }
        }
        Some((i, c))
    } else {
        None
    }
}

pub(crate) fn scan_blockquote_start(data: &[u8]) -> Option<usize> {
    if data.starts_with(b"> ") {
        Some(2)
    } else {
        None
    }
}

/// This already assumes the list item has been scanned.
pub(crate) fn scan_empty_list(data: &[u8]) -> bool {
    let mut ix = 0;
    for _ in 0..2 {
        if let Some(bytes) = scan_blank_line(&data[ix..]) {
            ix += bytes;
        } else {
            return false;
        }
    }
    true
}

// return number of bytes scanned, delimiter, start index, and indent
pub(crate) fn scan_listitem(bytes: &[u8]) -> Option<(usize, u8, usize, usize)> {
    let mut c = *bytes.get(0)?;
    let (w, start) = match c {
        b'-' | b'+' | b'*' => (1, 0),
        b'0'..=b'9' => {
            let (length, start) = parse_decimal(bytes);
            c = *bytes.get(length)?;
            if !(c == b'.' || c == b')') {
                return None;
            }
            (length + 1, start)
        }
        _ => {
            return None;
        }
    };
    // TODO: replace calc_indent with scan_leading_whitespace, for tab correctness
    let (mut postn, mut postindent) = calc_indent(&bytes[w..], 5);
    if postindent == 0 {
        scan_eol(&bytes[w..])?;
        postindent += 1;
    } else if postindent > 4 {
        postn = 1;
        postindent = 1;
    }
    if scan_blank_line(&bytes[w..]).is_some() {
        postn = 0;
        postindent = 1;
    }
    Some((w + postn, c, start, w + postindent))
}

// returns (number of bytes, parsed decimal)
fn parse_decimal(bytes: &[u8]) -> (usize, usize) {
    match bytes
        .iter()
        .take_while(|&&b| is_digit(b))
        .try_fold((0, 0usize), |(count, acc), c| {
            let digit = usize::from(c - b'0');
            match acc
                .checked_mul(10)
                .and_then(|ten_acc| ten_acc.checked_add(digit))
            {
                Some(number) => Ok((count + 1, number)),
                // stop early on overflow
                None => Err((count, acc)),
            }
        }) {
        Ok(p) | Err(p) => p,
    }
}

// returns (number of bytes, parsed hex)
fn parse_hex(bytes: &[u8]) -> (usize, usize) {
    match bytes.iter().try_fold((0, 0usize), |(count, acc), c| {
        let mut c = *c;
        let digit = if c >= b'0' && c <= b'9' {
            usize::from(c - b'0')
        } else {
            // make lower case
            c |= 0x20;
            if c >= b'a' && c <= b'f' {
                usize::from(c - b'a' + 10)
            } else {
                return Err((count, acc));
            }
        };
        match acc
            .checked_mul(16)
            .and_then(|sixteen_acc| sixteen_acc.checked_add(digit))
        {
            Some(number) => Ok((count + 1, number)),
            // stop early on overflow
            None => Err((count, acc)),
        }
    }) {
        Ok(p) | Err(p) => p,
    }
}

fn char_from_codepoint(input: usize) -> Option<char> {
    let mut codepoint = input.try_into().ok()?;
    if codepoint == 0 {
        codepoint = 0xFFFD;
    }
    char::from_u32(codepoint)
}

// doesn't bother to check data[0] == '&'
pub(crate) fn scan_entity(bytes: &[u8]) -> (usize, Option<CowStr<'static>>) {
    let mut end = 1;
    if scan_ch(&bytes[end..], b'#') == 1 {
        end += 1;
        let (bytecount, codepoint) = if end < bytes.len() && bytes[end] | 0x20 == b'x' {
            end += 1;
            parse_hex(&bytes[end..])
        } else {
            parse_decimal(&bytes[end..])
        };
        end += bytecount;
        return if bytecount == 0 || scan_ch(&bytes[end..], b';') == 0 {
            (0, None)
        } else if let Some(c) = char_from_codepoint(codepoint) {
            (end + 1, Some(c.into()))
        } else {
            (0, None)
        };
    }
    end += scan_while(&bytes[end..], is_ascii_alphanumeric);
    if scan_ch(&bytes[end..], b';') == 1 {
        if let Some(value) = entities::get_entity(&bytes[1..end]) {
            return (end + 1, Some(value.into()));
        }
    }
    (0, None)
}

// note: dest returned is raw, still needs to be unescaped
// TODO: check that nested parens are really not allowed for refdefs
// TODO(performance): this func should probably its own unescaping
pub(crate) fn scan_link_dest(
    data: &str,
    start_ix: usize,
    max_next: usize,
) -> Option<(usize, &str)> {
    let bytes = &data.as_bytes()[start_ix..];
    let mut i = scan_ch(bytes, b'<');

    if i != 0 {
        // pointy links
        while i < bytes.len() {
            match bytes[i] {
                b'\n' | b'\r' | b'<' => return None,
                b'>' => return Some((i + 1, &data[(start_ix + 1)..(start_ix + i)])),
                b'\\' if i + 1 < bytes.len() && is_ascii_punctuation(bytes[i + 1]) => {
                    i += 1;
                }
                _ => {}
            }
            i += 1;
        }
        None
    } else {
        // non-pointy links
        let mut nest = 0;
        while i < bytes.len() {
            match bytes[i] {
                0x0..=0x20 => {
                    break;
                }
                b'(' => {
                    if nest > max_next {
                        return None;
                    }
                    nest += 1;
                }
                b')' => {
                    if nest == 0 {
                        break;
                    }
                    nest -= 1;
                }
                b'\\' if i + 1 < bytes.len() && is_ascii_punctuation(bytes[i + 1]) => {
                    i += 1;
                }
                _ => {}
            }
            i += 1;
        }
        Some((i, &data[start_ix..(start_ix + i)]))
    }
}

// Remove backslash escapes and resolve entities
pub(crate) fn unescape(input: &str) -> CowStr<'_> {
    let mut result = String::new();
    let mut mark = 0;
    let mut i = 0;
    let bytes = input.as_bytes();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() && is_ascii_punctuation(bytes[i + 1]) => {
                result.push_str(&input[mark..i]);
                mark = i + 1;
                i += 2;
            }
            b'&' => match scan_entity(&bytes[i..]) {
                (n, Some(value)) => {
                    result.push_str(&input[mark..i]);
                    result.push_str(&value);
                    i += n;
                    mark = i;
                }
                _ => i += 1,
            },
            b'\r' => {
                result.push_str(&input[mark..i]);
                i += 1;
                mark = i;
            }
            _ => i += 1,
        }
    }
    if mark == 0 {
        input.into()
    } else {
        result.push_str(&input[mark..]);
        result.into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn overflow_list() {
        assert!(
            scan_listitem(b"4444444444444444444444444444444444444444444444444444444444!").is_none()
        );
    }

    #[test]
    fn overflow_by_addition() {
        assert!(scan_listitem(b"1844674407370955161615!").is_none());
    }
}
