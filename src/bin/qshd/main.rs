#![forbid(unsafe_code)]
//! qshd: the server. On Unix it serves every user (as root) or its own;
//! on Windows only the user it runs as.

mod app;

fn main() {
    app::main()
}
