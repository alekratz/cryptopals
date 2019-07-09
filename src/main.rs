mod ch;
mod common;

use crate::{ch::*, common::*};
use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg};
use std::fs;

fn main() {
    const ALL_CHALLENGES: &'static [&'static str] = &["c1", "c2", "c3", "c4", "c5"];
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
                .value_name("FILE")
                .default_value("corpus.txt")
                .help("The file to use to create an ASCII frequency model."),
        )
        .arg(
            Arg::with_name("c4_input")
                .long("c4-input")
                .takes_value(true)
                .value_name("FILE")
                .default_value("4.txt")
                .help("The input for challenge 4."),
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
            "c4" => {
                let inputs = fs::read_to_string(matches.value_of("c4_input").unwrap()).unwrap()
                    .split("\n")
                    .map(String::from)
                    .collect();
                Box::new(C4::new(&ascii_frequencies, inputs))
            },
            "c5" => Box::new(C5::default()),
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
    const INPUT: &'static str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const OUTPUT: &'static str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
}

impl Challenge for C1 {
    fn name(&self) -> &'static str {
        "Convert hex to base64"
    }

    fn run(&mut self) {
        let bytes = hex_bytes(Self::INPUT);
        self.result = bytes_b64(&bytes);
        self.success = Some(&self.result == Self::OUTPUT);
    }

    fn fail_message(&self) -> Option<String> {
        Some(format!(
            "Result: {} (expected {})",
            self.result,
            Self::OUTPUT
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
    const INPUT: &'static str = "1c0111001f010100061a024b53535009181c";
    const OUTPUT: &'static str = "746865206b696420646f6e277420706c6179";
}

impl Challenge for C2 {
    fn name(&self) -> &'static str {
        "Fixed XOR"
    }

    fn run(&mut self) {
        const KEY: &str = "686974207468652062756c6c277320657965";
        self.result = apply_key(&hex_bytes(Self::INPUT), &hex_bytes(KEY))
            .iter()
            .map(|byte| format!("{:x}", byte))
            .collect();
        self.success = Some(&self.result == Self::OUTPUT);
    }

    fn success(&self) -> Option<bool> {
        self.success
    }

    fn fail_message(&self) -> Option<String> {
        Some(format!(
            "Result: {} (expected {})",
            self.result,
            Self::OUTPUT
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

    const INPUT: &'static str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const OUTPUT: &'static str = "Cooking MC's like a pound of bacon";
}

impl Challenge for C3<'_> {
    fn name(&self) -> &'static str {
        "Single-byte XOR cipher"
    }

    fn run(&mut self) {
        let input_bytes = hex_bytes(Self::INPUT);
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
        self.success = Some(&self.result == Self::OUTPUT);
    }

    fn finish_message(&self) -> Option<String> {
        Some(format!(
            "Encoded message with key {} and score {:.4}: {:?}",
            self.key, self.score, self.result
        ))
    }

    fn success(&self) -> Option<bool> { self.success }
}

struct C4<'fmap> {
    frequencies: &'fmap FrequencyMap,
    inputs: Vec<String>,
    success: Option<bool>,
    key: u8,
    score: f64,
    result: String,
}

impl<'fmap> C4<'fmap> {
    fn new(frequencies: &'fmap FrequencyMap, inputs: Vec<String>) -> Self {
        C4 {
            frequencies,
            inputs,
            success: None,
            key: Default::default(),
            score: Default::default(),
            result: Default::default(),
        }
    }

    const OUTPUT: &'static str = "Now that the party is jumping\n";
}

impl Challenge for C4<'_> {
    fn name(&self) -> &'static str {
        "Detect single-character XOR"
    }

    fn run(&mut self) {
        let mut frequencies = Vec::new();
        
        for input in self.inputs.iter() {
            let input_bytes = hex_bytes(input);
            frequencies.extend((1u8..=255u8)
                .map(|key| {
                    let message = apply_key(&input_bytes, &[key]);
                    (key, frequency_score(&message, self.frequencies), message)
                }));
        }
        frequencies
            .sort_unstable_by(|(_, score1, _), (_, score2, _)| score1.partial_cmp(score2).unwrap());
        let (key, score, message) = frequencies.remove(0);
        self.key = key;
        self.score = score;
        self.result = message.iter().map(|v| *v as char).collect();
        self.success = Some(&self.result == Self::OUTPUT);
    }

    fn finish_message(&self) -> Option<String> {
        Some(format!(
            "Encoded message with key {} and score {:.4}: {:?}",
            self.key, self.score, self.result
        ))
    }

    fn success(&self) -> Option<bool> { self.success }
}

#[derive(Default)]
struct C5 {
    success: Option<bool>,
    result: String,
}

impl C5 {
    const INPUT: &'static str = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const OUTPUT: &'static str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const KEY: &'static str = "ICE";
}

impl Challenge for C5 {
    fn name(&self) -> &'static str {
        "Repeating-key XOR"
    }

    fn run(&mut self) {
        let key: Vec<_> = Self::KEY.chars().map(|c| c as u8).collect();
        self.result = bytes_hex(&apply_key(&Self::INPUT.bytes().collect::<Vec<_>>(), &key));
        self.success = Some(self.result == Self::OUTPUT)
    }

    fn fail_message(&self) -> Option<String> {
        Some(format!("Result: {:?} (expected {:?})", self.result, Self::OUTPUT))
    }

    fn success(&self) -> Option<bool> {
        self.success
    }
}
