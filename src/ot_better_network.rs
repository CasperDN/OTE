use std::io::Read;

use crate::common::*;
use crate::ot_primitive;
use crate::ot_primitive::bool_vec_to_usize;
use crate::ot_primitive::usize_to_bool_vec;
use crate::ot_primitive::USIZE;
use crypto_bigint::modular::runtime_mod::DynResidueParams;
use crypto_bigint::Encoding;
use crypto_bigint::NonZero;
use ot_primitive::PublicKey;
use ot_primitive::SafePrimeGroup;
use rand::random;

struct Receiver {
    k: Vec<(Vec<bool>, Vec<bool>)>,
    choice_bits: Vec<bool>,
}
struct Sender {
    s: Vec<bool>,
    messages: Vec<(Vec<bool>, Vec<bool>)>,
    k_s: Vec<Vec<bool>>,
}

impl Receiver {
    fn initialize(k: usize, choice_bits: Vec<bool>) -> Receiver {
        let k = (0..k)
            .map(|_| {
                (
                    (0..k).map(|_| random()).collect(),
                    (0..k).map(|_| random()).collect(),
                )
            })
            .collect::<Vec<(Vec<bool>, Vec<bool>)>>();
        return Receiver { k, choice_bits };
    }

    fn do_protocol(&self, sender: &mut Sender, group: &SafePrimeGroup) -> Vec<Vec<bool>> {
        sender.receive_ot_primitive(self, group);
        let m = self.choice_bits.len();
        let t = self
            .k
            .iter()
            .map(|(k_0, _)| pseudo_random_gen(k_0, m))
            .collect::<Vec<Vec<bool>>>();
        let u = self
            .k
            .iter()
            .zip(t.clone())
            .map(|((_, k_1), t_i)| {
                xor_bitvec(
                    &self.choice_bits,
                    &xor_bitvec(&t_i, &pseudo_random_gen(&k_1, m)),
                )
            })
            .collect::<Vec<Vec<bool>>>();

        let y = sender.receive_vectors(u);
        let t_transpose = transpose(&t);
        let z = y
            .iter()
            .zip(t_transpose)
            .enumerate()
            .map(|(j, ((yj_0, yj_1), t_j))| {
                let yj = if self.choice_bits[j] { yj_1 } else { yj_0 };
                xor_bitvec(
                    yj,
                    &hash_bits(&int_to_bool_vec(j), &t_j),
                )
            })
            .collect::<Vec<_>>();
        z
    }

    fn send_ot_primitive(
        &self,
        group: &SafePrimeGroup,
        keys: &Vec<(PublicKey, PublicKey)>,
    ) -> ot_primitive::OTParams {
        let r_input = self
            .k
            .iter()
            .map(|(k_0, k_1)| (bool_vec_to_usize(k_0), bool_vec_to_usize(k_1)))
            // .map(|(k_0, k_1)| (USIZE::from_be_slice(&bool_vec_to_byte_vec(k_0)[..]), USIZE::from_be_slice(&bool_vec_to_byte_vec(k_1)[..])))
            .collect::<Vec<_>>();
        return ot_primitive::send_usize(group, keys, &r_input);
    }
}

impl Sender {
    fn initialize(k: usize, messages: Vec<(Vec<bool>, Vec<bool>)>) -> Sender {
        let s = (0..k).map(|_| random()).collect::<Vec<bool>>();
        return Sender {
            s,
            messages,
            k_s: Vec::new(),
        };
    }

    fn receive_vectors(&self, u: Vec<Vec<bool>>) -> Vec<(Vec<bool>, Vec<bool>)> {
        let m = self.messages.len();
        let q = self
            .k_s
            .iter()
            .zip(u)
            .enumerate()
            .map(|(i, (k_i, u_i))| {
                let g = pseudo_random_gen(k_i, m);
                if self.s[i] {
                    xor_bitvec(&u_i, &g)
                } else {
                    g
                }
            })
            .collect::<Vec<_>>();
        let q_transp = transpose(&q);
        self.messages
            .iter()
            .zip(q_transp)
            .enumerate()
            .map(|(j, ((xj_0, xj_1), q_j))| {
                let yj_0 = xor_bitvec(
                    xj_0,
                    &hash_bits(&int_to_bool_vec(j), &q_j),
                );
                let yj_1 = xor_bitvec(
                    xj_1,
                    &hash_bits(
                        &int_to_bool_vec(j),
                        &xor_bitvec(&q_j, &self.s),
                    ),
                );
                (yj_0, yj_1)
            })
            .collect::<Vec<_>>()
    }

    fn receive_ot_primitive(&mut self, receiver: &Receiver, group: &SafePrimeGroup) {
        let k = self.s.len();
        let sk = ot_primitive::create_secret_keys(group, k);
        let keys = ot_primitive::commit_choice(group, &sk, &self.s);
        let res = receiver.send_ot_primitive(group, &keys);
        let values = ot_primitive::receive_(group, &res, &sk, &self.s);
        self.k_s = values
            .iter()
            // ot_primitive uses 512 bits. Apparently it is stored as in le-bytes.
            .map(usize_to_bool_vec)
            // .map(|x| int_vec_to_bool_vec(x))
            .collect::<Vec<Vec<bool>>>()
    }
}

fn ote(messages: Vec<(Vec<bool>, Vec<bool>)>, choice: Vec<bool>, k: usize) -> Vec<Vec<bool>> {
    let mut sender = Sender::initialize(k, messages);
    let receiver = Receiver::initialize(k, choice);
    let group = &ot_primitive::make_group();

    receiver.do_protocol(&mut sender, group)
}

pub fn run_tests() {
    println!("Starting tests... ");
    for m in 1..5 {
        for k in 256..257 {
            println!("Running protocol with m={} and k={} .", m, k);
            for _ in 0..1 {
                let messages = (0..m)
                    .into_iter()
                    .map(|x| {
                        (
                            int_to_bitvec_len(x, OUTPUT_SIZE),
                            int_to_bitvec_len(x + 1, OUTPUT_SIZE),
                        )
                    })
                    .collect::<Vec<_>>();
                let choice_bits = (0..m).into_iter().map(|_| random()).collect::<Vec<_>>();
                let prediction = ote(messages.clone(), choice_bits.clone(), k);
                let correct = messages
                    .into_iter()
                    .enumerate()
                    .map(|(i, m)| if choice_bits[i] { m.1 } else { m.0 })
                    .collect::<Vec<_>>();
                prediction
                    .into_iter()
                    .zip(correct)
                    .for_each(|(p, c)| assert_eq!(p, c))
            }
        }
    }
    println!("Everything worked")
}
