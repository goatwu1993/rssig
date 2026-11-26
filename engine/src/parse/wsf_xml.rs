//! XML-dependent WSF placement validation, separate from text/block framing.
use alloc::vec::Vec;
use anyhow::{Result, ensure};
pub(super) fn validate(text: &str, start: usize, after: usize) -> Result<()> {
    let doc = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 100_000,
            ..Default::default()
        },
    )
    .map_err(XmlError)?;
    let root = doc.root_element();
    ensure!(
        root.has_tag_name("job") && root.tag_name().namespace().is_none(),
        "WSF requires a single unqualified job root"
    );
    ensure!(
        root.descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "job")
            .count()
            == 1,
        "nested WSF jobs unsupported"
    );
    let signatures: Vec<_> = root
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "signature")
        .collect();
    ensure!(
        signatures.len() == 1,
        "WSF requires exactly one signature element"
    );
    let node = signatures[0];
    ensure!(
        node.tag_name().namespace().is_none()
            && node.attributes().len() == 0
            && node.parent() == Some(root),
        "invalid WSF signature element"
    );
    ensure!(
        root.children().rfind(|n| n.is_element()) == Some(node),
        "WSF signature must be the last child element"
    );
    ensure!(
        node.range() == (start + 2..after - 2) && text[after..].starts_with("</job>"),
        "invalid WSF signature placement"
    );
    Ok(())
}
#[derive(Debug)]
struct XmlError(roxmltree::Error);
impl core::fmt::Display for XmlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}
impl core::error::Error for XmlError {}
