use base64;
use std::{collections::HashMap, slice, str};

pub type FrequencyMap = HashMap<u8, f64>;

pub fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

pub fn hex_bytes(s: &str) -> Vec<u8> {
    let odd_count = s.len() % 2 == 1;
    let mut result = Vec::with_capacity((s.len() + 1) / 2);
    for i in 0..s.len() / 2 {
        let digits = unsafe {
            let len = if odd_count && i == s.len() - 1 { 1 } else { 2 };
            str::from_utf8(slice::from_raw_parts(
                s.as_ptr().offset(i as isize * 2),
                len,
            ))
            .unwrap()
        };
        result.push(u8::from_str_radix(digits, 16).unwrap());
    }
    result
}

pub fn bytes_b64(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

pub fn byte_frequencies(bytes: &[u8]) -> FrequencyMap {
    let mut counts = HashMap::new();
    for b in bytes.iter().copied() {
        let count = counts.entry(b).or_insert(0);
        *count += 1;
    }
    let max_count = *counts.iter()
        .map(|(_, v)| v)
        .max()
        .unwrap();
    counts
        .into_iter()
        .map(|(k, v)| (k, (v as f64) / (max_count as f64)))
        .collect()
}

pub fn frequency_score(bytes: &[u8], baseline: &FrequencyMap) -> f64 {
    let freqs = byte_frequencies(bytes);
    freqs
        .into_iter()
        .map(|(b, f)| {
            let expected = baseline.get(&b).unwrap_or(&0.);
            (*expected - f).powf(2.)
        })
        .sum()
}

pub fn apply_key(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

#[test]
fn test_hex_digits() {
    assert_eq!(
        hex_bytes("0011223344").as_slice(),
        &[0, 0x11, 0x22, 0x33, 0x44]
    );
}
