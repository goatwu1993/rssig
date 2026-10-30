use std::{io, process::ExitCode};

fn main() -> ExitCode {
    match rssig::cli::run_with_writers(
        std::env::args_os(),
        io::stdout().lock(),
        io::stderr().lock(),
    ) {
        Ok(code) => ExitCode::from(code),
        Err(_) => ExitCode::from(2),
    }
}
