use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as Base64Engine};
use hex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::OnceLock;

static FREQ_MAP: OnceLock<HashMap<char, f32>> = OnceLock::new();

pub fn english_monogram_frequency(letter: char) -> f32 {
    let freq_map = FREQ_MAP.get_or_init(|| {
        let mut map = HashMap::new();
        let file = File::open("data/english_monograms.txt").expect("Cannot open monogram file");
        let reader = BufReader::new(file);

        for line in reader.lines() {
            if let Ok(line) = line {
                let parts: Vec<&str> = line.split(":").map(|x| x.trim()).collect();
                if parts.len() == 2 {
                    if let (Some(ch), Ok(freq)) = (parts[0].chars().next(), parts[1].parse::<f32>())
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

pub fn bin_to_hex(s_bin: &Vec<u8>) -> String {
    return s_bin
        .into_iter()
        .map(|byte| format!("{:x}", byte))
        .collect();
}

pub fn hex_to_base64(s_hex: &str) -> String {
    // convert utf-8 hex encoding to base64 encoding

    return (0..s_hex.len())
        .step_by(6)
        .map(|i| {
            if i + 6 <= s_hex.len() {
                &s_hex[i..i + 6]
            } else {
                &s_hex[i..]
            }
        })
        .map(|three_bytes_hex| Base64Engine.encode(hex_to_bin(three_bytes_hex)))
        .collect();
}

pub fn fixed_xor(s_bin: &Vec<u8>, t_bin: &Vec<u8>) -> Vec<u8> {
    assert_eq!(s_bin.len(), t_bin.len());
    return s_bin
        .into_iter()
        .zip(t_bin.into_iter())
        .map(|(s, t)| s ^ t)
        .collect();
}

pub fn distance(text: &str) -> usize {
    let distance: f32 = String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        .chars()
        .map(|letter| {
            (english_monogram_frequency(letter)
                - text.to_uppercase().matches(letter).count() as f32 / text.len() as f32)
                .abs()
        })
        .sum();
    return (distance * 100.) as usize;
}

fn decrypt_with_single_character_cypher(encrypted_bin: &Vec<u8>, cypher: u8) -> Vec<u8> {
    // let hex_cypher = format!("{:x}", cypher as u32).repeat(encrypted_text.len() / 2);
    let equal_length_cypher: Vec<u8> = (0..encrypted_bin.len()).map(|_| cypher).collect();
    return fixed_xor(&encrypted_bin, &equal_length_cypher);
}

pub fn brute_force_single_character_xor(encrypted_bin: &Vec<u8>) -> Vec<u8> {
    let characters: Vec<char> = (32..=126).map(|i| i as u8 as char).collect();
    let cypher: char = characters
        .into_iter()
        .min_by_key(|cypher| {
            let decrypted_bin = decrypt_with_single_character_cypher(encrypted_bin, *cypher as u8);
            match String::from_utf8(decrypted_bin) {
                Ok(decrypted_text_utf8) => distance(&decrypted_text_utf8),
                Err(_) => usize::MAX,
            }
        })
        .unwrap();
    return decrypt_with_single_character_cypher(encrypted_bin, cypher as u8);
}

pub fn detect_single_character_xor(texts_bin: &Vec<Vec<u8>>) -> Vec<u8> {
    // find the string which was encrypted with single character xor and return
    // it unencrypted
    return texts_bin
        .into_iter()
        .map(|text| brute_force_single_character_xor(text))
        .min_by_key(
            |decrypted_bin| match String::from_utf8(decrypted_bin.to_vec()) {
                Ok(decrypted_bin_utf8) => distance(&decrypted_bin_utf8),
                Err(_) => usize::MAX,
            },
        )
        .unwrap();
}
