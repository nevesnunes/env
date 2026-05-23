use clap::Parser as ClapParser;
use std::error::Error;
use std::path::PathBuf;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor};

#[derive(ClapParser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Input source file
    #[arg(value_name = "FILE")]
    file: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let src = std::fs::read_to_string(args.file)?;

    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_cpp::LANGUAGE.into())?;

    // [Knee Deep in tree\-sitter Queries](https://parsiya.net/blog/knee-deep-tree-sitter-queries/)
    // [Specify descendant or ancestor in query](https://github.com/tree-sitter/tree-sitter/issues/880)
    let tree = parser.parse(src.clone(), None).unwrap();
    let func_query_tpl = r#"
        (function_definition (function_declarator) @x)
    "#;
    let func_query = Query::new(&tree_sitter_cpp::LANGUAGE.into(), func_query_tpl)?;
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&func_query, tree.root_node(), src.as_bytes());
    while let Some(m) = matches.next() {
        for capture in m.captures.iter() {
            println!("- {}", node_text(capture.node, &src));
        }
    }

    Ok(())
}

fn node_text(node: tree_sitter::Node, src: &str) -> String {
    return src[node.start_byte()..node.end_byte()].to_string();
}
