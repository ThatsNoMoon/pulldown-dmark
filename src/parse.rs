// Copyright 2017 Google Inc. All rights reserved.
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

//! Tree-based two pass parser.

use std::cmp::{max, min};
use std::collections::{HashMap, VecDeque};
use std::iter::FusedIterator;
use std::ops::{Index, Range};

use crate::firstpass::run_first_pass;
use crate::scanners::*;
use crate::strings::CowStr;
use crate::tree::{Tree, TreeIndex};
use crate::{Alignment, Event, Tag};

// Allowing arbitrary depth nested parentheses inside link destinations
// can create denial of service vulnerabilities if we're not careful.
// The simplest countermeasure is to limit their depth, which is
// explicitly allowed by the spec as long as the limit is at least 3:
// https://spec.commonmark.org/0.29/#link-destination
const LINK_MAX_NESTED_PARENS: usize = 5;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Item {
    pub start: usize,
    pub end: usize,
    pub body: ItemBody,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum ItemBody {
    Paragraph,
    Text,
    SoftBreak,
    HardBreak,

    // These are possible inline items, need to be resolved in second pass.

    // repeats, can_open, can_close
    MaybeEmphasis(usize, bool, bool),
    // quote byte, can_open, can_close
    MaybeCode(usize, bool), // number of backticks, preceeded by backslash
    MaybeLinkOpen,
    // bool indicates whether or not the preceeding section could be a reference
    MaybeLinkClose(bool),

    // These are inline items after resolution.
    Emphasis,
    Strong,
    Strikethrough,
    Code(CowIndex),
    Link(LinkIndex),

    FencedCodeBlock(CowIndex),
    BlockQuote,
    SynthesizeText(CowIndex),

    // Dummy node at the top of the tree - should not be used otherwise!
    Root,
}

impl<'a> ItemBody {
    fn is_inline(&self) -> bool {
        matches!(
            *self,
            ItemBody::MaybeEmphasis(..)
                | ItemBody::MaybeCode(..)
                | ItemBody::MaybeLinkOpen
                | ItemBody::MaybeLinkClose(..)
        )
    }
}

impl<'a> Default for ItemBody {
    fn default() -> Self {
        ItemBody::Root
    }
}

/// Markdown event iterator.
pub struct Parser<'input> {
    text: &'input str,
    tree: Tree<Item>,
    allocs: Allocations<'input>,
    // used by inline passes. store them here for reuse
    inline_stack: InlineStack,
    link_stack: LinkStack,
}

impl<'input> Parser<'input> {
    /// Creates a new event iterator for a markdown string.
    pub fn new(text: &'input str) -> Self {
        let (mut tree, allocs) = run_first_pass(text);
        tree.reset();
        let inline_stack = Default::default();
        let link_stack = Default::default();
        Parser {
            text,
            tree,
            allocs,
            inline_stack,
            link_stack,
        }
    }

    /// Handle inline markup.
    ///
    /// When the parser encounters any item indicating potential inline markup, all
    /// inline markup passes are run on the remainder of the chain.
    ///
    /// Note: there's some potential for optimization here, but that's future work.
    fn handle_inline(&mut self) {
        self.handle_inline_pass1();
        self.handle_emphasis();
    }

    /// Handle inline HTML, code spans, and links.
    ///
    /// This function handles both inline HTML and code spans, because they have
    /// the same precedence. It also handles links, even though they have lower
    /// precedence, because the URL of links must not be processed.
    fn handle_inline_pass1(&mut self) {
        let mut code_delims = CodeDelims::new();
        let mut cur = self.tree.cur();
        let mut prev = None;

        let block_end = self.tree[self.tree.peek_up().unwrap()].item.end;
        let block_text = &self.text[..block_end];

        while let Some(mut cur_ix) = cur {
            match self.tree[cur_ix].item.body {
                ItemBody::MaybeCode(mut search_count, preceded_by_backslash) => {
                    if preceded_by_backslash {
                        search_count -= 1;
                        if search_count == 0 {
                            self.tree[cur_ix].item.body = ItemBody::Text;
                            prev = cur;
                            cur = self.tree[cur_ix].next;
                            continue;
                        }
                    }

                    if code_delims.is_populated() {
                        // we have previously scanned all codeblock delimiters,
                        // so we can reuse that work
                        if let Some(scan_ix) = code_delims.find(cur_ix, search_count) {
                            self.make_code_span(cur_ix, scan_ix, preceded_by_backslash);
                        } else {
                            self.tree[cur_ix].item.body = ItemBody::Text;
                        }
                    } else {
                        // we haven't previously scanned all codeblock delimiters,
                        // so walk the AST
                        let mut scan = if search_count > 0 {
                            self.tree[cur_ix].next
                        } else {
                            None
                        };
                        while let Some(scan_ix) = scan {
                            if let ItemBody::MaybeCode(delim_count, _) =
                                self.tree[scan_ix].item.body
                            {
                                if search_count == delim_count {
                                    self.make_code_span(cur_ix, scan_ix, preceded_by_backslash);
                                    code_delims.clear();
                                    break;
                                } else {
                                    code_delims.insert(delim_count, scan_ix);
                                }
                            }
                            scan = self.tree[scan_ix].next;
                        }
                        if scan == None {
                            self.tree[cur_ix].item.body = ItemBody::Text;
                        }
                    }
                }
                ItemBody::MaybeLinkOpen => {
                    self.tree[cur_ix].item.body = ItemBody::Text;
                    self.link_stack.push(LinkStackEl {
                        node: cur_ix,
                        ty: LinkStackTy::Link,
                    });
                }
                ItemBody::MaybeLinkClose(_) => {
                    self.tree[cur_ix].item.body = ItemBody::Text;
                    if let Some(tos) = self.link_stack.pop() {
                        if tos.ty == LinkStackTy::Disabled {
                            continue;
                        }
                        let next = self.tree[cur_ix].next;
                        if let Some((next_ix, url, title)) =
                            self.scan_inline_link(block_text, self.tree[cur_ix].item.end, next)
                        {
                            let next_node = scan_nodes_to_ix(&self.tree, next, next_ix);
                            if let Some(prev_ix) = prev {
                                self.tree[prev_ix].next = None;
                            }
                            cur = Some(tos.node);
                            cur_ix = tos.node;
                            let link_ix = self.allocs.allocate_link(url, title);
                            self.tree[cur_ix].item.body = ItemBody::Link(link_ix);
                            self.tree[cur_ix].child = self.tree[cur_ix].next;
                            self.tree[cur_ix].next = next_node;
                            self.tree[cur_ix].item.end = next_ix;
                            if let Some(next_node_ix) = next_node {
                                self.tree[next_node_ix].item.start =
                                    max(self.tree[next_node_ix].item.start, next_ix);
                            }

                            if tos.ty == LinkStackTy::Link {
                                self.link_stack.disable_all_links();
                            }
                        }
                    }
                }
                _ => (),
            }
            prev = cur;
            cur = self.tree[cur_ix].next;
        }
        self.link_stack.clear();
    }

    fn handle_emphasis(&mut self) {
        let mut prev = None;
        let mut prev_ix: TreeIndex;
        let mut cur = self.tree.cur();

        while let Some(mut cur_ix) = cur {
            match self.tree[cur_ix].item.body {
                ItemBody::MaybeEmphasis(mut count, can_open, can_close) => {
                    let c = self.text.as_bytes()[self.tree[cur_ix].item.start];
                    let both = can_open && can_close;
                    if can_close {
                        while let Some(el) =
                            self.inline_stack.find_match(&mut self.tree, c, count, both)
                        {
                            // have a match!
                            if let Some(prev_ix) = prev {
                                self.tree[prev_ix].next = None;
                            }
                            let match_count = min(count, el.count);
                            // start, end are tree node indices
                            let mut end = cur_ix - 1;
                            let mut start = el.start + el.count;

                            // work from the inside out
                            while start > el.start + el.count - match_count {
                                let (inc, ty) = if c == b'~' {
                                    (2, ItemBody::Strikethrough)
                                } else if start > el.start + el.count - match_count + 1 {
                                    (2, ItemBody::Strong)
                                } else {
                                    (1, ItemBody::Emphasis)
                                };

                                let root = start - inc;
                                end = end + inc;
                                self.tree[root].item.body = ty;
                                self.tree[root].item.end = self.tree[end].item.end;
                                self.tree[root].child = Some(start);
                                self.tree[root].next = None;
                                start = root;
                            }

                            // set next for top most emph level
                            prev_ix = el.start + el.count - match_count;
                            prev = Some(prev_ix);
                            cur = self.tree[cur_ix + match_count - 1].next;
                            self.tree[prev_ix].next = cur;

                            if el.count > match_count {
                                self.inline_stack.push(InlineEl {
                                    start: el.start,
                                    count: el.count - match_count,
                                    c: el.c,
                                    both,
                                })
                            }
                            count -= match_count;
                            if count > 0 {
                                cur_ix = cur.unwrap();
                            } else {
                                break;
                            }
                        }
                    }
                    if count > 0 {
                        if can_open {
                            self.inline_stack.push(InlineEl {
                                start: cur_ix,
                                count,
                                c,
                                both,
                            });
                        } else {
                            for i in 0..count {
                                self.tree[cur_ix + i].item.body = ItemBody::Text;
                            }
                        }
                        prev_ix = cur_ix + count - 1;
                        prev = Some(prev_ix);
                        cur = self.tree[prev_ix].next;
                    }
                }
                _ => {
                    prev = cur;
                    cur = self.tree[cur_ix].next;
                }
            }
        }
        self.inline_stack.pop_all(&mut self.tree);
    }

    /// Returns next byte index, url and title.
    fn scan_inline_link(
        &self,
        underlying: &'input str,
        mut ix: usize,
        node: Option<TreeIndex>,
    ) -> Option<(usize, CowStr<'input>, CowStr<'input>)> {
        if scan_ch(&underlying.as_bytes()[ix..], b'(') == 0 {
            return None;
        }
        ix += 1;
        ix += scan_while(&underlying.as_bytes()[ix..], is_ascii_whitespace);

        let (dest_length, dest) = scan_link_dest(underlying, ix, LINK_MAX_NESTED_PARENS)?;
        let dest = unescape(dest);
        ix += dest_length;

        ix += scan_while(&underlying.as_bytes()[ix..], is_ascii_whitespace);

        let title = if let Some((bytes_scanned, t)) = self.scan_link_title(underlying, ix, node) {
            ix += bytes_scanned;
            ix += scan_while(&underlying.as_bytes()[ix..], is_ascii_whitespace);
            t
        } else {
            "".into()
        };
        if scan_ch(&underlying.as_bytes()[ix..], b')') == 0 {
            return None;
        }
        ix += 1;

        Some((ix, dest, title))
    }

    // returns (bytes scanned, title cow)
    fn scan_link_title(
        &self,
        text: &'input str,
        start_ix: usize,
        node: Option<TreeIndex>,
    ) -> Option<(usize, CowStr<'input>)> {
        let bytes = text.as_bytes();
        let open = match bytes.get(start_ix) {
            Some(b @ b'\'') | Some(b @ b'\"') | Some(b @ b'(') => *b,
            _ => return None,
        };
        let close = if open == b'(' { b')' } else { open };

        let mut title = String::new();
        let mut mark = start_ix + 1;
        let mut i = start_ix + 1;

        while i < bytes.len() {
            let c = bytes[i];

            if c == close {
                let cow = if mark == 1 {
                    (i - start_ix + 1, text[mark..i].into())
                } else {
                    title.push_str(&text[mark..i]);
                    (i - start_ix + 1, title.into())
                };

                return Some(cow);
            }
            if c == open {
                return None;
            }

            if c == b'\n' || c == b'\r' {
                if let Some(node_ix) = scan_nodes_to_ix(&self.tree, node, i + 1) {
                    if self.tree[node_ix].item.start > i {
                        title.push_str(&text[mark..i]);
                        title.push('\n');
                        i = self.tree[node_ix].item.start;
                        mark = i;
                        continue;
                    }
                }
            }
            if c == b'\\' && i + 1 < bytes.len() && is_ascii_punctuation(bytes[i + 1]) {
                title.push_str(&text[mark..i]);
                i += 1;
                mark = i;
            }

            i += 1;
        }

        None
    }

    /// Make a code span.
    ///
    /// Both `open` and `close` are matching MaybeCode items.
    fn make_code_span(&mut self, open: TreeIndex, close: TreeIndex, preceding_backslash: bool) {
        let first_ix = open + 1;
        let last_ix = close - 1;
        let bytes = self.text.as_bytes();
        let mut span_start = self.tree[open].item.end;
        let mut span_end = self.tree[close].item.start;
        let mut buf: Option<String> = None;

        // detect all-space sequences, since they are kept as-is as of commonmark 0.29
        if !bytes[span_start..span_end].iter().all(|&b| b == b' ') {
            let opening = matches!(bytes[span_start], b' ' | b'\r' | b'\n');
            let closing = matches!(bytes[span_end - 1], b' ' | b'\r' | b'\n');
            let drop_enclosing_whitespace = opening && closing;

            if drop_enclosing_whitespace {
                span_start += 1;
                if span_start < span_end {
                    span_end -= 1;
                }
            }

            let mut ix = first_ix;

            while ix < close {
                if let ItemBody::HardBreak | ItemBody::SoftBreak = self.tree[ix].item.body {
                    if drop_enclosing_whitespace {
                        // check whether break should be ignored
                        if ix == first_ix {
                            ix = ix + 1;
                            span_start = min(span_end, self.tree[ix].item.start);
                            continue;
                        } else if ix == last_ix && last_ix > first_ix {
                            ix = ix + 1;
                            continue;
                        }
                    }

                    let end = bytes[self.tree[ix].item.start..]
                        .iter()
                        .position(|&b| b == b'\r' || b == b'\n')
                        .unwrap()
                        + self.tree[ix].item.start;
                    if let Some(ref mut buf) = buf {
                        buf.push_str(&self.text[self.tree[ix].item.start..end]);
                        buf.push(' ');
                    } else {
                        let mut new_buf = String::with_capacity(span_end - span_start);
                        new_buf.push_str(&self.text[span_start..end]);
                        new_buf.push(' ');
                        buf = Some(new_buf);
                    }
                } else if let Some(ref mut buf) = buf {
                    let end = if ix == last_ix {
                        span_end
                    } else {
                        self.tree[ix].item.end
                    };
                    buf.push_str(&self.text[self.tree[ix].item.start..end]);
                }
                ix = ix + 1;
            }
        }

        let cow = if let Some(buf) = buf {
            buf.into()
        } else {
            self.text[span_start..span_end].into()
        };
        if preceding_backslash {
            self.tree[open].item.body = ItemBody::Text;
            self.tree[open].item.end = self.tree[open].item.start + 1;
            self.tree[open].next = Some(close);
            self.tree[close].item.body = ItemBody::Code(self.allocs.allocate_cow(cow));
            self.tree[close].item.start = self.tree[open].item.start + 1;
        } else {
            self.tree[open].item.body = ItemBody::Code(self.allocs.allocate_cow(cow));
            self.tree[open].item.end = self.tree[close].item.end;
            self.tree[open].next = self.tree[close].next;
        }
    }

    /// Consumes the event iterator and produces an iterator that produces
    /// `(Event, Range)` pairs, where the `Range` value maps to the corresponding
    /// range in the markdown source.
    pub fn into_offset_iter(self) -> OffsetIter<'input> {
        OffsetIter { inner: self }
    }
}

/// Returns number of containers scanned.
pub(crate) fn scan_containers(tree: &Tree<Item>, line_start: &mut LineStart) -> usize {
    let mut i = 0;
    for &node_ix in tree.walk_spine() {
        match tree[node_ix].item.body {
            ItemBody::BlockQuote => {
                // `scan_blockquote_marker` saves & restores internally
                if !line_start.scan_blockquote_marker() {
                    break;
                }
            }
            _ => (),
        }
        i += 1;
    }
    i
}

impl<'a> Tree<Item> {
    pub(crate) fn append_text(&mut self, start: usize, end: usize) {
        if end > start {
            if let Some(ix) = self.cur() {
                if ItemBody::Text == self[ix].item.body && self[ix].item.end == start {
                    self[ix].item.end = end;
                    return;
                }
            }
            self.append(Item {
                start,
                end,
                body: ItemBody::Text,
            });
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct InlineEl {
    start: TreeIndex, // offset of tree node
    count: usize,
    c: u8,      // b'*' or b'_'
    both: bool, // can both open and close
}

#[derive(Debug, Clone, Default)]
struct InlineStack {
    stack: Vec<InlineEl>,
    // Lower bounds for matching indices in the stack. For example
    // a strikethrough delimiter will never match with any element
    // in the stack with index smaller than
    // `lower_bounds[InlineStack::TILDES]`.
    lower_bounds: [usize; 7],
}

impl InlineStack {
    /// These are indices into the lower bounds array.
    /// Not both refers to the property that the delimiter can not both
    /// be opener as a closer.
    const UNDERSCORE_NOT_BOTH: usize = 0;
    const ASTERISK_NOT_BOTH: usize = 1;
    const ASTERISK_BASE: usize = 2;
    const TILDES: usize = 5;
    const UNDERSCORE_BOTH: usize = 6;

    fn pop_all(&mut self, tree: &mut Tree<Item>) {
        for el in self.stack.drain(..) {
            for i in 0..el.count {
                tree[el.start + i].item.body = ItemBody::Text;
            }
        }
        self.lower_bounds = [0; 7];
    }

    fn get_lowerbound(&self, c: u8, count: usize, both: bool) -> usize {
        if c == b'_' {
            if both {
                self.lower_bounds[InlineStack::UNDERSCORE_BOTH]
            } else {
                self.lower_bounds[InlineStack::UNDERSCORE_NOT_BOTH]
            }
        } else if c == b'*' {
            let mod3_lower = self.lower_bounds[InlineStack::ASTERISK_BASE + count % 3];
            if both {
                mod3_lower
            } else {
                min(
                    mod3_lower,
                    self.lower_bounds[InlineStack::ASTERISK_NOT_BOTH],
                )
            }
        } else {
            self.lower_bounds[InlineStack::TILDES]
        }
    }

    fn set_lowerbound(&mut self, c: u8, count: usize, both: bool, new_bound: usize) {
        if c == b'_' {
            if both {
                self.lower_bounds[InlineStack::UNDERSCORE_BOTH] = new_bound;
            } else {
                self.lower_bounds[InlineStack::UNDERSCORE_NOT_BOTH] = new_bound;
            }
        } else if c == b'*' {
            self.lower_bounds[InlineStack::ASTERISK_BASE + count % 3] = new_bound;
            if !both {
                self.lower_bounds[InlineStack::ASTERISK_NOT_BOTH] = new_bound;
            }
        } else {
            self.lower_bounds[InlineStack::TILDES] = new_bound;
        }
    }

    fn find_match(
        &mut self,
        tree: &mut Tree<Item>,
        c: u8,
        count: usize,
        both: bool,
    ) -> Option<InlineEl> {
        let lowerbound = min(self.stack.len(), self.get_lowerbound(c, count, both));
        let res = self.stack[lowerbound..]
            .iter()
            .cloned()
            .enumerate()
            .rfind(|(_, el)| {
                el.c == c && (!both && !el.both || (count + el.count) % 3 != 0 || count % 3 == 0)
            });

        if let Some((matching_ix, matching_el)) = res {
            let matching_ix = matching_ix + lowerbound;
            for el in &self.stack[(matching_ix + 1)..] {
                for i in 0..el.count {
                    tree[el.start + i].item.body = ItemBody::Text;
                }
            }
            self.stack.truncate(matching_ix);
            Some(matching_el)
        } else {
            self.set_lowerbound(c, count, both, self.stack.len());
            None
        }
    }

    fn push(&mut self, el: InlineEl) {
        self.stack.push(el)
    }
}

/// Skips forward within a block to a node which spans (ends inclusive) the given
/// index into the source.
fn scan_nodes_to_ix(
    tree: &Tree<Item>,
    mut node: Option<TreeIndex>,
    ix: usize,
) -> Option<TreeIndex> {
    while let Some(node_ix) = node {
        if tree[node_ix].item.end <= ix {
            node = tree[node_ix].next;
        } else {
            break;
        }
    }
    node
}

#[derive(Clone, Default)]
struct LinkStack {
    inner: Vec<LinkStackEl>,
    disabled_ix: usize,
}

impl LinkStack {
    fn push(&mut self, el: LinkStackEl) {
        self.inner.push(el);
    }

    fn pop(&mut self) -> Option<LinkStackEl> {
        let el = self.inner.pop();
        self.disabled_ix = std::cmp::min(self.disabled_ix, self.inner.len());
        el
    }

    fn clear(&mut self) {
        self.inner.clear();
        self.disabled_ix = 0;
    }

    fn disable_all_links(&mut self) {
        for el in &mut self.inner[self.disabled_ix..] {
            if el.ty == LinkStackTy::Link {
                el.ty = LinkStackTy::Disabled;
            }
        }
        self.disabled_ix = self.inner.len();
    }
}

#[derive(Clone, Debug)]
struct LinkStackEl {
    node: TreeIndex,
    ty: LinkStackTy,
}

#[derive(PartialEq, Clone, Debug)]
enum LinkStackTy {
    Link,
    Disabled,
}

/// Contains the destination URL, title and source span of a reference definition.
#[derive(Clone)]
pub struct LinkDef<'a> {
    pub dest: CowStr<'a>,
    pub title: Option<CowStr<'a>>,
    pub span: Range<usize>,
}

/// Tracks tree indices of code span delimiters of each length. It should prevent
/// quadratic scanning behaviours by providing (amortized) constant time lookups.
struct CodeDelims {
    inner: HashMap<usize, VecDeque<TreeIndex>>,
    seen_first: bool,
}

impl CodeDelims {
    fn new() -> Self {
        Self {
            inner: Default::default(),
            seen_first: false,
        }
    }

    fn insert(&mut self, count: usize, ix: TreeIndex) {
        if self.seen_first {
            self.inner
                .entry(count)
                .or_insert_with(Default::default)
                .push_back(ix);
        } else {
            // Skip the first insert, since that delimiter will always
            // be an opener and not a closer.
            self.seen_first = true;
        }
    }

    fn is_populated(&self) -> bool {
        !self.inner.is_empty()
    }

    fn find(&mut self, open_ix: TreeIndex, count: usize) -> Option<TreeIndex> {
        while let Some(ix) = self.inner.get_mut(&count)?.pop_front() {
            if ix > open_ix {
                return Some(ix);
            }
        }
        None
    }

    fn clear(&mut self) {
        self.inner.clear();
        self.seen_first = false;
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct LinkIndex(usize);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct CowIndex(usize);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct AlignmentIndex(usize);

#[derive(Clone)]
pub(crate) struct Allocations<'a> {
    links: Vec<(CowStr<'a>, CowStr<'a>)>,
    cows: Vec<CowStr<'a>>,
    alignments: Vec<Vec<Alignment>>,
}

impl<'a> Allocations<'a> {
    pub fn new() -> Self {
        Self {
            links: Vec::with_capacity(128),
            cows: Vec::new(),
            alignments: Vec::new(),
        }
    }

    pub fn allocate_cow(&mut self, cow: CowStr<'a>) -> CowIndex {
        let ix = self.cows.len();
        self.cows.push(cow);
        CowIndex(ix)
    }

    pub fn allocate_link(&mut self, url: CowStr<'a>, title: CowStr<'a>) -> LinkIndex {
        let ix = self.links.len();
        self.links.push((url, title));
        LinkIndex(ix)
    }
}

impl<'a> Index<CowIndex> for Allocations<'a> {
    type Output = CowStr<'a>;

    fn index(&self, ix: CowIndex) -> &Self::Output {
        self.cows.index(ix.0)
    }
}

impl<'a> Index<LinkIndex> for Allocations<'a> {
    type Output = (CowStr<'a>, CowStr<'a>);

    fn index(&self, ix: LinkIndex) -> &Self::Output {
        self.links.index(ix.0)
    }
}

impl<'a> Index<AlignmentIndex> for Allocations<'a> {
    type Output = Vec<Alignment>;

    fn index(&self, ix: AlignmentIndex) -> &Self::Output {
        self.alignments.index(ix.0)
    }
}

/// Markdown event and source range iterator.
///
/// Generates tuples where the first element is the markdown event and the second
/// is a the corresponding range in the source string.
///
/// Constructed from a `Parser` using its
/// [`into_offset_iter`](struct.Parser.html#method.into_offset_iter) method.
pub struct OffsetIter<'a> {
    inner: Parser<'a>,
}

impl<'a> Iterator for OffsetIter<'a> {
    type Item = (Event<'a>, Range<usize>);

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.tree.cur() {
            None => {
                let ix = self.inner.tree.pop()?;
                let tag = item_to_tag(&self.inner.tree[ix].item, &self.inner.allocs);
                self.inner.tree.next_sibling(ix);
                let span = self.inner.tree[ix].item.start..self.inner.tree[ix].item.end;
                debug_assert!(span.start <= span.end);
                Some((Event::End(tag), span))
            }
            Some(cur_ix) => {
                if self.inner.tree[cur_ix].item.body.is_inline() {
                    self.inner.handle_inline();
                }

                let node = self.inner.tree[cur_ix];
                let item = node.item;
                let event = item_to_event(item, self.inner.text, &self.inner.allocs);
                if let Event::Start(..) = event {
                    self.inner.tree.push();
                } else {
                    self.inner.tree.next_sibling(cur_ix);
                }
                debug_assert!(item.start <= item.end);
                Some((event, item.start..item.end))
            }
        }
    }
}

fn item_to_tag<'a>(item: &Item, allocs: &Allocations<'a>) -> Tag<'a> {
    match item.body {
        ItemBody::Paragraph => Tag::Paragraph,
        ItemBody::Emphasis => Tag::Emphasis,
        ItemBody::Strong => Tag::Strong,
        ItemBody::Strikethrough => Tag::Strikethrough,
        ItemBody::Link(link_ix) => {
            let &(ref url, ref title) = allocs.index(link_ix);
            Tag::Link(url.clone(), title.clone())
        }
        ItemBody::FencedCodeBlock(cow_ix) => Tag::CodeBlock(allocs[cow_ix].clone()),
        ItemBody::BlockQuote => Tag::BlockQuote,
        _ => panic!("unexpected item body {:?}", item.body),
    }
}

fn item_to_event<'a>(item: Item, text: &'a str, allocs: &Allocations<'a>) -> Event<'a> {
    let tag = match item.body {
        ItemBody::Text => return Event::Text(text[item.start..item.end].into()),
        ItemBody::Code(cow_ix) => return Event::Code(allocs[cow_ix].clone()),
        ItemBody::SynthesizeText(cow_ix) => return Event::Text(allocs[cow_ix].clone()),
        ItemBody::SoftBreak => return Event::SoftBreak,
        ItemBody::HardBreak => return Event::HardBreak,

        ItemBody::Paragraph => Tag::Paragraph,
        ItemBody::Emphasis => Tag::Emphasis,
        ItemBody::Strong => Tag::Strong,
        ItemBody::Strikethrough => Tag::Strikethrough,
        ItemBody::Link(link_ix) => {
            let &(ref url, ref title) = allocs.index(link_ix);
            Tag::Link(url.clone(), title.clone())
        }
        ItemBody::FencedCodeBlock(cow_ix) => Tag::CodeBlock(allocs[cow_ix].clone()),
        ItemBody::BlockQuote => Tag::BlockQuote,
        _ => panic!("unexpected item body {:?}", item.body),
    };

    Event::Start(tag)
}

impl<'a> Iterator for Parser<'a> {
    type Item = Event<'a>;

    fn next(&mut self) -> Option<Event<'a>> {
        match self.tree.cur() {
            None => {
                let ix = self.tree.pop()?;
                let tag = item_to_tag(&self.tree[ix].item, &self.allocs);
                self.tree.next_sibling(ix);
                Some(Event::End(tag))
            }
            Some(cur_ix) => {
                if self.tree[cur_ix].item.body.is_inline() {
                    self.handle_inline();
                }

                let node = self.tree[cur_ix];
                let item = node.item;
                let event = item_to_event(item, self.text, &self.allocs);
                if let Event::Start(..) = event {
                    self.tree.push();
                } else {
                    self.tree.next_sibling(cur_ix);
                }
                Some(event)
            }
        }
    }
}

impl FusedIterator for Parser<'_> {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tree::Node;

    // TODO: move these tests to tests/html.rs?

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn node_size() {
        let node_size = std::mem::size_of::<Node<Item>>();
        assert_eq!(48, node_size);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn body_size() {
        let body_size = std::mem::size_of::<ItemBody>();
        assert_eq!(16, body_size);
    }

    #[test]
    fn basic_link() {
        assert_eq!(5, Parser::new("[foo](bar)").count());
    }

    #[test]
    fn single_open_fish_bracket() {
        // dont crash
        assert_eq!(3, Parser::new("<").count());
    }

    #[test]
    fn lone_hashtag() {
        // dont crash
        assert_eq!(3, Parser::new("#").count());
    }

    #[test]
    fn lots_of_backslashes() {
        // dont crash
        Parser::new("\\\\\r\r").count();
        Parser::new("\\\r\r\\.\\\\\r\r\\.\\").count();
    }

    #[test]
    fn issue_320() {
        // dont crash
        Parser::new(":\r\t> |\r:\r\t> |\r").count();
    }

    #[test]
    fn issue_319() {
        // dont crash
        Parser::new("|\r-]([^|\r-]([^").count();
        Parser::new("|\r\r=][^|\r\r=][^car").count();
    }

    #[test]
    fn issue_303() {
        // dont crash
        Parser::new("[^\r\ra]").count();
        Parser::new("\r\r]Z[^\x00\r\r]Z[^\x00").count();
    }

    #[test]
    fn issue_313() {
        // dont crash
        Parser::new("*]0[^\r\r*]0[^").count();
        Parser::new("[^\r> `][^\r> `][^\r> `][").count();
    }

    #[test]
    fn issue_311() {
        // dont crash
        Parser::new("\\\u{0d}-\u{09}\\\u{0d}-\u{09}").count();
    }

    #[test]
    fn issue_283() {
        let input = std::str::from_utf8(b"\xf0\x9b\xb2\x9f<td:^\xf0\x9b\xb2\x9f").unwrap();
        // dont crash
        Parser::new(input).count();
    }

    #[test]
    fn issue_289() {
        // dont crash
        Parser::new("> - \\\n> - ").count();
        Parser::new("- \n\n").count();
    }

    #[test]
    fn issue_306() {
        // dont crash
        Parser::new("*\r_<__*\r_<__*\r_<__*\r_<__").count();
    }

    #[test]
    fn issue_305() {
        // dont crash
        Parser::new("_6**6*_*").count();
    }

    #[test]
    fn another_emphasis_panic() {
        Parser::new("*__#_#__*").count();
    }

    #[test]
    fn offset_iter() {
        let event_offsets: Vec<_> = Parser::new("*hello* world")
            .into_offset_iter()
            .map(|(_ev, range)| range)
            .collect();
        let expected_offsets = vec![(0..13), (0..7), (1..6), (0..7), (7..13), (0..13)];
        assert_eq!(expected_offsets, event_offsets);
    }

    #[test]
    fn offset_iter_issue_378() {
        let event_offsets: Vec<_> = Parser::new("a [b](c) d")
            .into_offset_iter()
            .map(|(_ev, range)| range)
            .collect();
        let expected_offsets = vec![(0..10), (0..2), (2..8), (3..4), (2..8), (8..10), (0..10)];
        assert_eq!(expected_offsets, event_offsets);
    }

    #[test]
    fn code_block_kind_check_fenced() {
        let parser = Parser::new("hello\n```test\ntadam\n```");
        let mut found = 0;
        for (ev, _range) in parser.into_offset_iter() {
            match ev {
                Event::Start(Tag::CodeBlock(syntax)) => {
                    assert_eq!(syntax.as_ref(), "test");
                    found += 1;
                }
                _ => {}
            }
        }
        assert_eq!(found, 1);
    }
}
