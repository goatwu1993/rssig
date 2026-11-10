//! Stored text encoding metadata. BOM handling remains format-specific.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextEncoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
}
impl TextEncoding {
    pub(crate) fn detect(bytes: &[u8]) -> Self {
        if bytes.starts_with(&[255, 254]) {
            Self::Utf16Le
        } else if bytes.starts_with(&[254, 255]) {
            Self::Utf16Be
        } else if bytes.starts_with(&[239, 187, 191]) {
            Self::Utf8Bom
        } else {
            Self::Utf8
        }
    }
}
