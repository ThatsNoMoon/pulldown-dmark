use std::io::Write as _;

use pulldown_dmark::{html, Event, Parser, Tag};

fn main() {
    let markdown_input: &str = "I wrote some code!\n```\nprint(\"hello, world\")\n```";
    println!("Parsing the following markdown string:\n{}", markdown_input);

    // Set up parser. We can treat is as any other iterator. We replace Peter by John
    // and image by its alt text.
    let parser = Parser::new(markdown_input)
        .map(|event| match event {
            Event::Start(Tag::CodeBlock(_)) => Event::Start(Tag::CodeBlock("python".into())),
            _ => event,
        })
        .filter(|event| match event {
            Event::Start(Tag::CodeBlock(..)) | Event::End(Tag::CodeBlock(..)) => true,
            _ => false,
        });

    // Write to anything implementing the `Write` trait. This could also be a file
    // or network socket.
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(b"\nHTML output:\n").unwrap();
    html::write_html(&mut handle, parser).unwrap();
}
