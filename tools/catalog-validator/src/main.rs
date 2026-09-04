mod cargo;
mod deploy;
mod evidence;
mod migrations;
mod model;
mod proto;
mod validate;

use std::env;
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("usage: catalog-validator validate [--strict] [--root <path>]");
    std::process::exit(2);
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else { usage() };
    if command != "validate" {
        usage()
    }

    let mut strict = false;
    let mut root = PathBuf::from(".");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--strict" => strict = true,
            "--root" => root = args.next().map(PathBuf::from).unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }

    let report = validate::run(&root, strict);
    if report.errors.is_empty() {
        println!(
            "Catalog validation successful: {} service(s), {} route(s), {} table(s).",
            report.services, report.routes, report.tables
        );
        for warning in report.warnings {
            eprintln!("warning: {warning}");
        }
    } else {
        for error in report.errors {
            eprintln!("error: {error}");
        }
        std::process::exit(1);
    }
}
