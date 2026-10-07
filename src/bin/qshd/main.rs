//! qshd needs a Unix system (Linux, macOS, BSD): user switching, PTYs and
//! process groups. On Windows, only the client (qsh) is available.

#[cfg(unix)]
mod unix;

#[cfg(unix)]
fn main() {
    unix::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("qshd runs on Linux, macOS and other Unix systems; on Windows only the qsh client is available.");
    std::process::exit(1);
}
