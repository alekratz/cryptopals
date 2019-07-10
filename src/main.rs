mod ch;
mod common;

use crate::{ch::*, common::*};
use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg};
use std::{collections::HashMap, fs};

fn main() {
    const ALL_CHALLENGES: &'static [&'static str] = &["c1", "c2", "c3", "c4", "c5", "c6"];
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
        .arg(
            Arg::with_name("c6_input")
                .long("c6-input")
                .takes_value(true)
                .value_name("FILE")
                .default_value("6.txt")
                .help("The input for challenge 6."),
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
                let inputs = fs::read_to_string(matches.value_of("c4_input").unwrap())
                    .unwrap()
                    .split("\n")
                    .map(String::from)
                    .collect();
                Box::new(C4::new(&ascii_frequencies, inputs))
            }
            "c5" => Box::new(C5::default()),
            "c6" => {
                let inputs = fs::read_to_string(matches.value_of("c6_input").unwrap())
                    .unwrap()
                    .replace("\n", "");
                Box::new(C6::new(&ascii_frequencies, inputs))
            }
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

    const INPUT: &'static str =
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
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

    fn success(&self) -> Option<bool> {
        self.success
    }
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
            frequencies.extend((1u8..=255u8).map(|key| {
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

    fn success(&self) -> Option<bool> {
        self.success
    }
}

#[derive(Default)]
struct C5 {
    success: Option<bool>,
    result: String,
}

impl C5 {
    const INPUT: &'static str =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
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
        Some(format!(
            "Result: {:?} (expected {:?})",
            self.result,
            Self::OUTPUT
        ))
    }

    fn success(&self) -> Option<bool> {
        self.success
    }
}

struct C6<'fmap> {
    frequencies: &'fmap FrequencyMap,
    input: String,
    success: Option<bool>,
    //key_size: usize,
    //score: f64,
}

impl<'fmap> C6<'fmap> {
    fn new(frequencies: &'fmap FrequencyMap, input: String) -> Self {
        C6 {
            frequencies,
            input,
            success: None,
            //key_size: Default::default(),
            //score: Default::default(),
        }
    }

    const OUTPUT: &'static str = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
}

impl Challenge for C6<'_> {
    fn name(&self) -> &'static str {
        "Break repeating-key XOR"
    }

    fn run(&mut self) {
        const MIN_BLOCK_COUNT: usize = 1;
        const MAX_BLOCK_COUNT: usize = 5;
        const MAX_CANDIDATES: usize = 3;
        let input = b64_bytes(&self.input);
        let mut distances = HashMap::new();

        // Step 1: try to infer the key size by finding the smallest average hamming distance between N blocks of M size
        //
        // Key lengths with the smallest hamming distance averaged across the number of blocks
        // checked are good candidates to try.
        for block_count in MIN_BLOCK_COUNT..=MAX_BLOCK_COUNT {
            for key_length in 2..=40 {
                let block = input
                    .chunks(key_length)
                    .take(block_count)
                    .collect::<Vec<_>>();
                let next_block = input
                    .chunks(key_length)
                    .skip(block_count)
                    .take(block_count)
                    .collect::<Vec<_>>();
                let distance_total = block
                    .into_iter()
                    .zip(next_block.into_iter())
                    .map(|(a, b)| hamming_distance(a, b))
                    .sum::<u32>() as f64
                    / (block_count as f64 * key_length as f64);
                let total = distances.entry(key_length).or_insert(0.);
                *total += distance_total;
            }
        }
        let mut distances = distances
            .into_iter()
            .map(|(k, dist)| (k, dist / (MAX_BLOCK_COUNT - MIN_BLOCK_COUNT + 1) as f64))
            .collect::<Vec<_>>();

        // Sort by the smallest distances
        distances.sort_unstable_by(|(_, d1), (_, d2)| d1.partial_cmp(d2).unwrap());

        // Step 2: choose the first MAX_CANDIDATES number of key lengths to try to solve.

        let candidates: Vec<_> = distances
            .into_iter()
            .map(|(k, _)| k)
            .take(MAX_CANDIDATES)
            .collect();

        /*
        println!("Top {} candidate key sizes:", MAX_CANDIDATES);
        for k in candidates.iter() {
            println!(". {}", k);
        }
        */

        let mut key_length_scores = Vec::new();
        // For every key size M, transpose the blocks into M blocks of the Nth byte of each block.
        // Then, bruteforce the XOR for each of the KEYSIZE number of blocks, checking the score
        // against the byte frequency table.
        for key_size in candidates.iter().copied() {
            let blocks = (0..key_size)
                .map(|offset| {
                    input
                        .iter()
                        .copied()
                        .skip(offset)
                        .step_by(key_size)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let mut final_key = Vec::new();
            // For every block, find the best single-byte key.
            for block in blocks.iter() {
                let mut scores = Vec::new();
                for key in 1..=255 {
                    let message = apply_key(block, &[key]);
                    scores.push((key, frequency_score(&message, self.frequencies)));
                }
                scores.sort_unstable_by(|(_, s1), (_, s2)| s1.partial_cmp(s2).unwrap());
                let (key, _) = scores.remove(0);
                final_key.push(key);
            }

            assert_eq!(final_key.len(), key_size);

            // decrypt the message
            let message = apply_key(&input, &final_key);
            let score = frequency_score(&message, self.frequencies);

            key_length_scores.push((key_size, bytes_ascii(&message), score));
        }

        key_length_scores.sort_unstable_by(|(_, _, s1), (_, _, s2)| s1.partial_cmp(s2).unwrap());
        let (_key_size, message, _score) = key_length_scores.remove(0);

        self.success = Some(message == Self::OUTPUT);
        //self.key_size = key_size;
        //self.score = score;
    }

    fn success(&self) -> Option<bool> {
        self.success
    }
}
