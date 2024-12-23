// use ot_primitive::SafePrimeGroup;
use rand::random;
// use sha3::{Digest, Sha3_256};

mod ot_primitive;
// use ot_primitive::PublicKey;
mod common;
mod ote_IKNP;
mod ot_better_network;


fn main() {
    // println!("Testing primitive");
    // ot_primitive::run_tests();
    // println!("Testing first");
    // ote_IKNP::run_tests();
    println!("Testing second");
    ot_better_network::run_tests()
}
