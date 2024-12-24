mod ot_primitive;
mod common;
mod ote_IKNP;
mod ot_better_network;


fn main() {
    println!("Testing primitive");
    ot_primitive::run_tests();
    println!("Testing first");
    ote_IKNP::run_tests();
    println!("Testing second");
    ot_better_network::run_tests()
}
