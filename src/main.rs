use ot_primitive::SafePrimeGroup;
use rand::random;
use sha3::{Digest, Sha3_256};

mod ot_primitive;
use ot_primitive::PublicKey;

struct Receiver {
    t: Vec<Vec<bool>>,
    choice_bits: Vec<bool>,
}

struct Sender {
    s: Vec<bool>,
    messages: Vec<(Vec<bool>, Vec<bool>)>, // Messages must be of size 256
}

/**
 * Hash k_l :: k_r :: i using Sha3-256.
 * Could also do the partial g(A, g(B,i)), but Sha3 takes arbitrary input size, so why not just give it everything at once?
 */
fn hash(v: usize, j: usize) -> Vec<bool> {
    let mut hasher = Sha3_256::new();
    let x: [u8; 128 / 8 * 2 + 64 / 8] =
        array_concat::concat_arrays!(j.to_be_bytes(), v.to_be_bytes());
    hasher.update(x);
    let output: [u8; 32] = *hasher.finalize().as_ref();
    output
        .iter()
        .flat_map(|&x| byte_to_bitvec(x))
        .take(64)
        .collect::<Vec<_>>()
}

fn int_to_bitvec(input: usize) -> Vec<bool> {
    (0..64)
        .rev()
        .map(|i| ((input >> i) & 1) != 0)
        .collect::<Vec<_>>()
}

fn int_to_bitvec_len(input: usize, len: usize) -> Vec<bool> {
    (0..len)
        .rev()
        .map(|i| ((input >> i) & 1) != 0)
        .collect::<Vec<_>>()
}

fn byte_to_bitvec(input: u8) -> Vec<bool> {
    (0..8)
        .rev()
        .map(|i| (input >> i) & 1 != 0)
        .collect::<Vec<_>>()
}

fn bitvec_to_int(input: &Vec<bool>) -> usize {
    input.iter().fold(0, |acc, &b| ((acc << 1) + (b as usize)))
}

fn xor_bitvec(l: &Vec<bool>, r: &Vec<bool>) -> Vec<bool> {
    l.iter().zip(r).map(|(l, r)| l ^ r).collect::<Vec<_>>()
}

impl Receiver {
    fn initialize(k: usize, m: usize, choice_bits: Vec<bool>) -> Receiver {
        let t = (0..m)
            .map(|_| (0..k).map(|_| random()).collect())
            .collect::<Vec<Vec<bool>>>();
        return Receiver { t, choice_bits };
    }

    fn do_protocol(&self, sender: &Sender, group: &SafePrimeGroup) -> Vec<Vec<bool>> {
        let y = sender.receive_ot_primitive(self, group);
        let z = y
            .iter()
            .zip(&self.t)
            .enumerate()
            .map(|(j, ((yj_0, yj_1), t_j))| {
                let yj = if self.choice_bits[j] { yj_1 } else { yj_0 };
                println!("{:?}", t_j);
                println!("{:?}", self.choice_bits[j]);
                xor_bitvec(yj, &hash(j, bitvec_to_int(t_j)))
            })
            .collect::<Vec<_>>();
        z
    }

    fn send_ot_primitive(
        &self,
        group: &SafePrimeGroup,
        keys: &Vec<(PublicKey, PublicKey)>,
        k: usize,
    ) -> ot_primitive::OTParams {
        // let k: usize = self.choice_bits.len();

        // sender.receive_s(receiver);
        let r_input = (0..k)
            .into_iter()
            .map(|col| {
                let mut r_input1 = 0;
                let mut r_input2 = 0;
                // for col in 0..(self.t.get(0).unwrap().len()) {
                for row in 0..self.t.len() {
                    r_input1 = (r_input1 << 1) + (self.t[row][col] as usize);
                    r_input2 = (r_input2 << 1) + ((self.t[row][col] ^ self.choice_bits[row]) as usize);
                }
                // }
                (r_input1, r_input2)
            })
            .collect::<Vec<_>>();
        return ot_primitive::send(group, keys, &r_input);
    }
}

impl Sender {
    fn initialize(k: usize, messages: Vec<(Vec<bool>, Vec<bool>)>) -> Sender {
        let s = (0..k).map(|_| random()).collect::<Vec<bool>>();
        return Sender { s, messages };
    }

    fn receive_ot_primitive(
        &self,
        receiver: &Receiver,
        group: &SafePrimeGroup,
    ) -> Vec<(Vec<bool>, Vec<bool>)> {
        let k = self.s.len();
        let sk = ot_primitive::create_secret_keys(group, k);
        let keys = ot_primitive::commit_choice(group, &sk, &self.s);
        let res = receiver.send_ot_primitive(group, &keys, k);
        let values = ot_primitive::receive(group, &res, &sk, &self.s);
        let m = self.messages.len();

        let mut q: Vec<Vec<bool>> = Vec::new();
        let mut inner = Vec::new();
        inner.resize(k, false);
        q.resize(m, inner);
        values.iter().enumerate().for_each(|(row, &v)| {
            int_to_bitvec_len(v, m)
                .iter()
                .enumerate()
                .for_each(|(col, &s)| q[col][row] = s)
        });
        self.messages
            .iter()
            .zip(q)
            .enumerate()
            .map(|(j, ((xj_0, xj_1), q_j))| {
                println!("start:{:?}", q_j);
                println!("{:?}", &xor_bitvec(&self.s, &q_j));
                let yj_0 = xor_bitvec(xj_0, &hash(j, bitvec_to_int(&q_j)));
                let yj_1 = xor_bitvec(xj_1, &hash(j, bitvec_to_int(&xor_bitvec(&self.s, &q_j))));
                (yj_0, yj_1)
            })
            .collect::<Vec<_>>()
    }
}

fn ote(messages: Vec<(Vec<bool>, Vec<bool>)>, choice: Vec<bool>, k: usize) -> Vec<Vec<bool>> {
    let m = messages.len();
    let sender = Sender::initialize(k, messages);
    let receiver = Receiver::initialize(k, m, choice);
    let group = &ot_primitive::make_group();

    receiver.do_protocol(&sender, group)
}

fn run_tests() {
    println!("Starting tests... ");
    for m in 1..3 {
        for k in 2..4 {
            println!("Running protocol with m={} and k={} .", m, k);
            for _ in 0..1 {
                let messages = (0..m)
                    .into_iter()
                    .map(|x| (int_to_bitvec(x), int_to_bitvec(x + 1)))
                    .collect::<Vec<_>>();
                messages.clone().into_iter().for_each(|(x1, x2)| {
                    print!("x1: [");
                    x1.into_iter().for_each(|x| print!("{},", x));
                    println!("]");
                    print!("x2: [");
                    x2.into_iter().for_each(|x| print!("{},", x));
                    println!("]")
                });
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

fn test_primitive() {
    print!("Testing primitive... ");
    for m in 1..10 {
        let group = ot_primitive::make_group();
        let sk = ot_primitive::create_secret_keys(&group, 500);
        let choice_bits = (0..m).into_iter().map(|_| random()).collect::<Vec<_>>();
        let messages = (0..m).into_iter().map(|x| (x, x + 1)).collect::<Vec<_>>();
        let keys = ot_primitive::commit_choice(&group, &sk, &choice_bits);
        let x = ot_primitive::send(&group, &keys, &messages);
        let prediction = ot_primitive::receive(&group, &x, &sk, &choice_bits);
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
    println!("OK")
}

fn main() {
    // test_primitive();
    run_tests();
}
