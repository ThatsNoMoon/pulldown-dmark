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

//! Pull parser for [CommonMark](https://commonmark.org). This crate provides a [Parser](struct.Parser.html) struct
//! which is an iterator over [Event](enum.Event.html)s. This iterator can be used
//! directly, or to output HTML using the [HTML module](html/index.html).
//!
//! By default, only CommonMark features are enabled. To use extensions like tables,
//! footnotes or task lists, enable them by setting the corresponding flags in the
//! [Options](struct.Options.html) struct.
//!
//! # Example
//! ```rust
//! use pulldown_dmark::{Parser, html};
//!
//! let markdown_input = "Hello world, this is a ~~complicated~~ *very simple* example.";
//!
//! let parser = Parser::new(markdown_input);
//!
//! // Write to String buffer.
//! let mut html_output = String::new();
//! html::push_html(&mut html_output, parser);
//!
//! // Check that the output is what we expected.
//! let expected_html = "<p>Hello world, this is a <del>complicated</del> <em>very simple</em> example.</p>\n";
//! assert_eq!(expected_html, &html_output);
//! ```

// Forbid unsafe code unless the SIMD feature is enabled.
#![forbid(unsafe_code)]
#![cfg_attr(feature = "simd", allow(unsafe_code))]

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod html;

mod entities;
pub mod escape;
mod firstpass;
mod parse;
mod puncttable;
mod scanners;
mod strings;
mod tree;

pub use crate::parse::{LinkDef, OffsetIter, Parser};
pub use crate::strings::{CowStr, InlineStr};

/// Tags for elements that can contain other elements.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Tag<'a> {
    /// A paragraph of text and other inline elements.
    Paragraph,

    BlockQuote,
    /// A code block. The field is the syntax specified.
    #[cfg_attr(feature = "serde", serde(borrow))]
    CodeBlock(CowStr<'a>),

    // span-level tags
    Emphasis,
    Strong,
    Strikethrough,

    /// A link. The first field is the destination URL, and the second is a title.
    Link(CowStr<'a>, CowStr<'a>),
}

/// Markdown events that are generated in a preorder traversal of the document
/// tree, with additional `End` events whenever all of an inner node's children
/// have been visited.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Event<'a> {
    /// Start of a tagged element. Events that are yielded after this event
    /// and before its corresponding `End` event are inside this element.
    /// Start and end events are guaranteed to be balanced.
    #[cfg_attr(feature = "serde", serde(borrow))]
    Start(Tag<'a>),
    /// End of a tagged element.
    #[cfg_attr(feature = "serde", serde(borrow))]
    End(Tag<'a>),
    /// A text node.
    #[cfg_attr(feature = "serde", serde(borrow))]
    Text(CowStr<'a>),
    /// An inline code node.
    #[cfg_attr(feature = "serde", serde(borrow))]
    Code(CowStr<'a>),
    /// A soft line break.
    SoftBreak,
    /// A hard line break.
    HardBreak,
}

/// Table column text alignment.
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub enum Alignment {
    /// Default text alignment.
    None,
    Left,
    Center,
    Right,
}
