//! Replay one complete synthetic saved input through the actual shared core.
use northstar_test_harness::controlled_admission::{execute, input::MAX_INPUT, parse};
use serde_json::json;
use std::io::Read;
fn main() {
    let result = (|| {
        let mut args = std::env::args_os().skip(1);
        let path = args.next().ok_or("arguments")?;
        if args.next().is_some() {
            return Err("arguments");
        }
        let file = std::fs::File::open(path).map_err(|_| "input_unavailable")?;
        let mut bytes = Vec::new();
        file.take((MAX_INPUT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "input_unavailable")?;
        let (input, hash) = parse(&bytes).map_err(|e| e.code())?;
        execute(&input, &hash).map_err(|e| e.code())
    })();
    match result {
        Ok(value) => println!("{}", serde_json::to_string(&value).expect("bounded JSON")),
        Err(reason) => {
            println!(
                "{}",
                json!({"schema":"northstar-admission-controlled-rejection-v1","class":"InvalidScenario","reason":reason})
            );
            std::process::exit(2);
        }
    }
}
