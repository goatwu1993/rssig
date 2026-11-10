//! Inspection arguments deliberately have no verification policy or root loading.
use super::batch;
use crate::{
    domain::{ParseFileResult, ParseFileSuccess},
    inspection,
};
use anyhow::Result;
use clap::ValueEnum;
use serde_json::Value;
use std::path::PathBuf;

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Pe,
    Cms,
    Cab,
    Navx,
}

#[derive(clap::Args)]
pub(super) struct Args {
    #[arg(required = true)]
    files: Vec<PathBuf>,
    /// Input structure: signed PE/CAB/NAVX, or standalone DER CMS SignedData.
    #[arg(long, value_enum, default_value = "pe")]
    format: Format,
}

pub(super) fn execute(args: Args) -> Result<(Value, u8)> {
    batch::execute(
        "parse",
        args.files,
        |_, bytes| match args.format {
            Format::Pe => inspection::pe(bytes),
            Format::Cms => inspection::cms(bytes),
            Format::Cab => inspection::container(bytes, crate::format::Format::Cab),
            Format::Navx => inspection::container(bytes, crate::format::Format::Navx),
        },
        |file, parse| {
            ParseFileResult::Success(ParseFileSuccess {
                file,
                ok: true,
                parse,
            })
        },
        ParseFileResult::Failure,
    )
}
