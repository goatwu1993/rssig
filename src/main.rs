use std::{io, process::ExitCode};

fn main() -> ExitCode {
    match rssig::cli::run(std::env::args_os(), io::stdout().lock()) {
        Ok(code) => ExitCode::from(code),
        Err(_) => ExitCode::from(2),
    }
}
