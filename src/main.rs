mod ch;
mod common;

use crate::{ch::*, common::*};
use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg};
use std::fs;

fn main() {
    const ALL_CHALLENGES: &'static [&'static str] = &["c1", "c2", "c3"];
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name("CHALLENGES")
                .help("The challenges to complete. If not specified, all challenges are run.")
                .possible_values(ALL_CHALLENGES)
                .multiple(true),
        )
        .arg(
            Arg::with_name("corpus")
                .long("corpus")
                .takes_value(true)
                .value_name("CORPUS")
                .default_value("corpus.txt")
                .help("The file to use to create an ASCII frequency model."),
        )
        .get_matches();

    let ascii_frequencies: FrequencyMap =
        { byte_frequencies(&fs::read(matches.value_of("corpus").unwrap()).unwrap()) };

    let challenges = if let Some(challenges) = matches.values_of("CHALLENGES") {
        challenges.collect()
    } else {
        ALL_CHALLENGES.to_vec()
    };

    for challenge in challenges {
        let mut ch: Box<dyn Challenge> = match challenge {
            "c1" => Box::new(C1::default()),
            "c2" => Box::new(C2::default()),
            "c3" => Box::new(C3::new(&ascii_frequencies)),
            _ => {
                println!("unknown challenge {}", challenge);
                continue;
            }
        };
        ch.run();
        ch.report();
    }
}

/// Challenge 1: Convert hex to base64.
#[derive(Default)]
struct C1 {
    success: Option<bool>,
    result: String,
}

impl C1 {
    const fn input() -> &'static str {
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    }
    const fn output() -> &'static str {
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    }
}

impl Challenge for C1 {
    fn name(&self) -> &'static str {
        "Convert hex to base64"
    }

    fn run(&mut self) {
        let bytes = hex_bytes(Self::input());
        self.result = bytes_b64(&bytes);
        self.success = Some(&self.result == Self::output());
    }

    fn fail_message(&self) -> Option<String> {
        Some(format!(
            "Result: {} (expected {})",
            self.result,
            Self::output()
        ))
    }

    fn success(&self) -> Option<bool> {
        self.success
    }
}

#[derive(Default)]
struct C2 {
    success: Option<bool>,
    result: String,
}

impl C2 {
    const fn input() -> &'static str {
        "1c0111001f010100061a024b53535009181c"
    }
    const fn output() -> &'static str {
        "746865206b696420646f6e277420706c6179"
    }
}

impl Challenge for C2 {
    fn name(&self) -> &'static str {
        "Fixed XOR"
    }

    fn run(&mut self) {
        const KEY: &str = "686974207468652062756c6c277320657965";
        self.result = apply_key(&hex_bytes(Self::input()), &hex_bytes(KEY))
            .iter()
            .map(|byte| format!("{:x}", byte))
            .collect();
        self.success = Some(&self.result == Self::output());
    }

    fn success(&self) -> Option<bool> {
        self.success
    }

    fn fail_message(&self) -> Option<String> {
        Some(format!(
            "Result: {} (expected {})",
            self.result,
            Self::output()
        ))
    }
}

struct C3<'fmap> {
    frequencies: &'fmap FrequencyMap,
    success: Option<bool>,
    key: u8,
    score: f64,
    result: String,
}

impl<'fmap> C3<'fmap> {
    fn new(frequencies: &'fmap FrequencyMap) -> Self {
        C3 {
            frequencies,
            success: None,
            key: Default::default(),
            score: Default::default(),
            result: Default::default(),
        }
    }

    fn input() -> &'static str {
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    }

    fn output() -> &'static str {
        "Cooking MC's like a pound of bacon"
    }
}

impl Challenge for C3<'_> {
    fn name(&self) -> &'static str {
        "Single-byte XOR cipher"
    }

    fn run(&mut self) {
        let input_bytes = hex_bytes(Self::input());
        let mut frequencies: Vec<_> = (0u8..=255u8)
            .map(|key| {
                let message = apply_key(&input_bytes, &[key]);
                (key, frequency_score(&message, self.frequencies), message)
            })
            .collect();
        frequencies
            .sort_unstable_by(|(_, score1, _), (_, score2, _)| score1.partial_cmp(score2).unwrap());
        let (key, score, message) = frequencies.remove(0);
        self.key = key;
        self.score = score;
        self.result = message.iter().map(|v| *v as char).collect();
        self.success = Some(&self.result == Self::output());
    }

    fn finish_message(&self) -> Option<String> {
        Some(format!(
            "Encoded message with key {} and score {:.4}: {:?}",
            self.key, self.score, self.result
        ))
    }

    fn success(&self) -> Option<bool> { self.success }
}
