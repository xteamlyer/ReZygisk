//! The size probe, half one: the work a daemon does, linked against `std`.
//!
//! This and `probe_no_std.rs` are the same program twice, differing only in
//! what they link. Together they answer one question, and the answer is a
//! number rather than an opinion: how much of a size budget does Rust's
//! standard library cost before a single line of the program exists?
//!
//! They are not shipped, not part of the host build, and not reachable without
//! the `probe` feature - see `tools/device-target.sh`, which builds both for
//! the device target and prints the result next to the budgets in
//! `src/bin/ci_size_budget.rs`.
//!
//! The work is deliberately ordinary: build a string with the formatting
//! machinery, growing an allocation as it goes. That is what a daemon's
//! protocol and status code actually does, so the two sizes differ by the
//! runtime and not by the workload.

use std::fmt::Write;

fn work() -> String {
    let mut text = String::new();

    for index in 0..8 {
        if index != 0 {
            text.push('-');
        }

        // Not `format!`: the point is to instantiate the formatting machinery,
        // not to allocate another String per step.
        let _ = write!(text, "part-{index}");
    }

    text
}

fn main() {
    println!("{}", work());
}
