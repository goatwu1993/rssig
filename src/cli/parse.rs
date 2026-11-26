//! Inspection arguments deliberately have no verification policy or root loading.
use super::batch;
use anyhow::Result;
use clap::ValueEnum;
use rssig_engine::{
    domain::{ParseFileResult, ParseFileSuccess},
    inspect,
};
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
    #[command(flatten)]
    limits: super::limits::Limits,
    /// Input structure: signed PE/CAB/NAVX, or standalone DER CMS SignedData.
    #[arg(long, value_enum, default_value = "pe")]
    format: Format,
}

pub(super) fn execute(args: Args) -> Result<(Value, u8)> {
    args.limits.validate(&args.files)?;
    batch::execute(
        "parse",
        args.files,
        &args.limits,
        |_, bytes| match args.format {
            Format::Pe => inspect::pe(bytes),
            Format::Cms => inspect::cms(bytes),
            Format::Cab => inspect::cab(bytes),
            Format::Navx => inspect::navx(bytes),
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
