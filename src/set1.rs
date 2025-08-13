use base64::prelude::*;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::OnceLock;

static FREQ_MAP: OnceLock<HashMap<char, f64>> = OnceLock::new();

pub fn english_monogram_frequency(letter: char) -> f64 {
    let freq_map = FREQ_MAP.get_or_init(|| {
        let mut map = HashMap::new();
        let file = File::open("data/english_monograms.txt").expect("Cannot open monogram file");
        let reader = BufReader::new(file);

        for line in reader.lines() {
            if let Ok(line) = line {
                let parts: Vec<&str> = line.split(":").map(|x| x.trim()).collect();
                if parts.len() == 2 {
                    if let (Some(ch), Ok(freq)) = (parts[0].chars().next(), parts[1].parse::<f64>())
                    {
                        map.insert(ch, freq);
                    }
                }
            }
        }
        map
    });

    return freq_map[&letter];
}

pub fn hex_to_bin(s_hex: &str) -> Vec<u8> {
    return (0..s_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s_hex[i..i + 2], 16).unwrap())
        .collect();
}

pub fn bin_to_hex(s_bin: &[u8]) -> String {
    return s_bin
        .into_iter()
        .map(|byte| format!("{:x}", byte))
        .collect();
}

pub fn plaintext_to_bin(s_bin: &str) -> Vec<u8> {
    return s_bin.chars().map(|c| c as u8).collect();
}

pub fn hex_to_base64(s_hex: &str) -> String {
    return BASE64_STANDARD.encode(hex_to_bin(s_hex));
}

pub fn fixed_xor(s_bin: &[u8], t_bin: &[u8]) -> Vec<u8> {
    assert_eq!(s_bin.len(), t_bin.len());
    return s_bin
        .into_iter()
        .zip(t_bin.into_iter())
        .map(|(s, t)| s ^ t)
        .collect();
}

pub fn distance(text: &str) -> usize {
    let characters: HashSet<char> = String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZ").chars().collect();
    let text = text.to_uppercase();

    // compute distance as the sum of the differences between the real frequencies
    // over the text and the English monogram frequencies over the English alphabet
    let mut distance: f64 = characters
        .clone()
        .into_iter()
        .map(|letter| {
            (english_monogram_frequency(letter)
                - text.matches(letter).count() as f64 / text.len() as f64)
                .abs()
        })
        .sum();

    // add the count of unknown characters (characters which are not English letters
    // or spaces) to the distance
    let mut text_characters: HashSet<char> = text.chars().collect();
    text_characters.remove(&' ');
    distance += text_characters
        .symmetric_difference(&characters)
        .collect::<HashSet<&char>>()
        .len() as f64;

    // convert and normalize by multiplying by 100 for precision
    return (distance * 100.) as usize;
}

fn decrypt_with_single_character_cypher(encrypted_bin: &[u8], cypher: u8) -> Vec<u8> {
    let equal_length_cypher: Vec<u8> = (0..encrypted_bin.len()).map(|_| cypher).collect();
    return fixed_xor(&encrypted_bin, &equal_length_cypher);
}

pub fn decrypt_with_repeating_key_xor(encrypted_bin: &[u8], cypher: &[u8]) -> Vec<u8> {
    let equal_length_cypher: Vec<u8> = cypher
        .iter()
        .cloned()
        .cycle()
        .take(encrypted_bin.len())
        .collect();
    return fixed_xor(&encrypted_bin, &equal_length_cypher);
}

pub fn brute_force_single_character_xor(encrypted_bin: &[u8]) -> (Vec<u8>, u8) {
    let characters: Vec<char> = (32..=126).map(|i| i as u8 as char).collect();
    let decrypteds: Vec<Vec<u8>> = characters
        .clone()
        .into_iter()
        .map(|c| decrypt_with_single_character_cypher(encrypted_bin, c as u8))
        .collect();
    let distances: Vec<usize> = decrypteds
        .into_iter()
        .map(|v| match String::from_utf8(v) {
            Ok(s) => distance(&s),
            Err(_) => usize::MAX,
        })
        .collect();
    let (cypher, _) = characters
        .into_iter()
        .zip(distances)
        .min_by_key(|(_, d)| *d)
        .unwrap();
    return (
        decrypt_with_single_character_cypher(encrypted_bin, cypher as u8),
        cypher as u8,
    );
}

pub fn detect_single_character_xor(texts_bin: &[&[u8]]) -> Vec<u8> {
    // find the string which was encrypted with single character xor and return
    // it unencrypted
    return texts_bin
        .into_iter()
        .map(|text| brute_force_single_character_xor(*text).0)
        .min_by_key(
            |decrypted_bin| match String::from_utf8(decrypted_bin.to_vec()) {
                Ok(decrypted_bin_utf8) => distance(&decrypted_bin_utf8),
                Err(_) => usize::MAX,
            },
        )
        .unwrap();
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    let a_bits: String = a
        .iter()
        .map(|byte| format!("{:b}", byte))
        .map(|bits| "0".repeat(8 - bits.len()) + &bits)
        .collect();
    let b_bits: String = b
        .iter()
        .map(|byte| format!("{:b}", byte))
        .map(|bits| "0".repeat(8 - bits.len()) + &bits)
        .collect();
    return a_bits
        .chars()
        .zip(b_bits.chars())
        .map(|(bit_a, bit_b)| (bit_a != bit_b) as usize)
        .sum();
}

pub fn break_repeating_key_xor(encrypted_bin: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut keysizes: Vec<usize> = (2..=40).collect();

    let keysize_distance = |ks: &usize| {
        (2..=4)
            .map(|i| {
                ((hamming_distance(
                    &encrypted_bin[..*ks],
                    &encrypted_bin[(i - 1) * (*ks)..i * (*ks)],
                ) as f64
                    / *ks as f64)
                    * 100.) as usize
            })
            .sum::<usize>()
            / 4
    };

    keysizes.sort_by_key(keysize_distance);

    let make_cypher = |ks: &usize| -> Vec<u8> {
        let blocks: Vec<&[u8]> = encrypted_bin.chunks(*ks).collect();
        let transposed_blocks: Vec<Vec<u8>> = (0..*ks)
            .map(|i| {
                blocks
                    .iter()
                    .filter(|b| b.len() > i)
                    .map(|b| b[i])
                    .collect()
            })
            .collect();
        let solved_transposed_blocks: Vec<(Vec<u8>, u8)> = transposed_blocks
            .into_iter()
            .map(|block| brute_force_single_character_xor(&block))
            .collect();
        return solved_transposed_blocks
            .into_iter()
            .map(|(_, key)| key)
            .collect();
    };

    let cyphers: Vec<Vec<u8>> = keysizes[..3].into_iter().map(make_cypher).collect();

    let cypher_distance = |cypher: &Vec<u8>| -> usize {
        match String::from_utf8(decrypt_with_repeating_key_xor(&encrypted_bin, cypher)) {
            Ok(decrypted_str) => distance(&decrypted_str),
            Err(_) => usize::MAX,
        }
    };

    let cypher: Vec<u8> = cyphers.into_iter().min_by_key(cypher_distance).unwrap();
    let decrypted_bin: Vec<u8> = decrypt_with_repeating_key_xor(&encrypted_bin, &cypher);

    return (decrypted_bin, cypher);
}
