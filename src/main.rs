mod common;
mod ot_better_network;
mod ot_primitive;
mod ote_IKNP;

use std::fs::OpenOptions;
use std::io::Write;
use std::time::SystemTime;

use rand::random;

const REPEAT: u128 = 5;

fn random_boolvec_len(m: usize) -> Vec<bool> {
    (0..m).map(|_| random()).collect::<Vec<_>>()
}

fn random_messages(m: usize) -> Vec<(Vec<bool>, Vec<bool>)> {
    (0..m)
        .map(|_| {
            (
                random_boolvec_len(common::OUTPUT_SIZE),
                random_boolvec_len(common::OUTPUT_SIZE),
            )
        })
        .collect::<Vec<_>>()
}

/**
 * Format:
 * number of messages in different experiments
 * k in different experiments
 * m one combined with k one
 * m one combined with k two
 * ...
 * m two combined with k one
 * ...
 */
fn run_experiment<T: Iterator<Item = usize> + Clone>(
    ote: &dyn Fn(Vec<(Vec<bool>, Vec<bool>)>, Vec<bool>, usize) -> Vec<Vec<bool>>,
    message_range: &T,
    k_range: &T,
    name: &str,
) {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(name)
        .ok()
        .unwrap();
    let mut first = true;
    for m_num in message_range.clone() {
        if !first {
            file.write(&" ".as_bytes());
        }
        first = false;
        file.write(&m_num.to_string().as_bytes());
    }
    file.write(&"\n".as_bytes());
    first = true;
    for k in k_range.clone() {
        if !first {
            file.write(&" ".as_bytes());
        }
        first = false;
        file.write(&k.to_string().as_bytes());
    }
    for m_num in message_range.clone() {
        file.write(&"\n".as_bytes());
        first = true;
        for k in k_range.clone() {
            if !first {
                file.write(&" ".as_bytes());
            }
            first = false;

            let mut x = 0;
            for _ in 0..REPEAT {
                let messages = random_messages(m_num);
                let choice_bits = random_boolvec_len(m_num);
                let now = SystemTime::now();
                ote(messages, choice_bits, k);
                x += now.elapsed().ok().unwrap().as_nanos()
            }
            x /= REPEAT;
            file.write(x.to_string().as_bytes());
            // file.write(" ".as_bytes());
        }
    }
}

fn run_experiments_for_primitive_vs_otes() {
    let security = vec![128, 256].into_iter();
    let messages = vec![1, 10, 100, 1_000, 10_000, 100_000].into_iter();
    run_experiment(&ote_IKNP::ote, &messages, &security, "ote");
    run_experiment(&ot_better_network::ote, &messages, &security, "ote_net");
    // messages.clone().rev().skip(1).rev();
    run_experiment(&ot_primitive::ote, &messages, &security, "primitive");
}

fn main() {
    println!("Testing primitive");
    ot_primitive::run_tests();
    println!("Testing IKNP");
    ote_IKNP::run_tests();
    println!("Testing network");
    ot_better_network::run_tests();
    // run_experiments_for_primitive_vs_otes();
    // run_experiment(&ot_primitive::ote, &vec![1, 2].into_iter(), &vec![1, 2].into_iter(), "test");
}
