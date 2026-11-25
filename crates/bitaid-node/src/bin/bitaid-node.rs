//! The Bitaid node binary: runs one role from its command line (see `bitaid_node::roles`).
fn main() {
    std::process::exit(bitaid_node::roles::run(std::env::args().collect()));
}
