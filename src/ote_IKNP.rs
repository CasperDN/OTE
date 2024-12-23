use ot_primitive::SafePrimeGroup;
use rand::random;
use crate::ot_primitive;
use crate::common::*;
use ot_primitive::PublicKey;




struct Receiver {
    t: Vec<Vec<bool>>,
    choice_bits: Vec<bool>,
}
// Could use 256. Maybe do this instead of 64?
struct Sender {
    s: Vec<bool>,
    messages: Vec<(Vec<bool>, Vec<bool>)>, // Messages must be of size 64
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
        let r_input = (0..k)
            .into_iter()
            .map(|col| {
                let mut r_input1 = 0;
                let mut r_input2 = 0;
                // for col in 0..(self.t.get(0).unwrap().len()) {
                for row in 0..self.t.len() {
                    r_input1 = (r_input1 << 1) + (self.t[row][col] as usize);
                    r_input2 =
                        (r_input2 << 1) + ((self.t[row][col] ^ self.choice_bits[row]) as usize);
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
        let values = ot_primitive::receive_as_usize(group, &res, &sk, &self.s);
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

pub fn run_tests() {
    println!("Starting tests... ");
    for m in 1..5 {
        for k in 2..10 {
            println!("Running protocol with m={} and k={} .", m, k);
            for _ in 0..1 {
                let messages = (0..m)
                    .into_iter()
                    .map(|x| (int_to_bitvec_len(x, OUTPUT_SIZE), int_to_bitvec_len(x + 1, OUTPUT_SIZE)))
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