// use base64;
use base64::{engine::general_purpose::STANDARD_NO_PAD as Base64Engine, Engine};
use std::collections::HashMap;
use distance::levenshtein;

fn pad(s_bin: &str) -> String {
    // pad binary string to 4 digits
    return String::from("0").repeat(4 - s_bin.len()) + s_bin;
}

fn hex_to_bin(s_hex: &str) -> String {
    return s_hex
        .chars()
        .map(|hex_digit| pad(&format!("{:b}", hex_digit.to_digit(16).unwrap())))
        .collect();
}

fn bin_to_hex(s_bin: &str) -> String {
    return (0..s_bin.len())
        .step_by(4)
        .map(|i| i16::from_str_radix(&s_bin[i..i + 4], 2).unwrap())
        .map(|n| format!("{:x}", n))
        .collect();
}

pub fn hex_to_base64(s_hex: &str) -> String {
    // convert utf-8 hex encoding to base64 encoding

    fn strip_leading_zeroes(bytes: &[u8]) -> &[u8] {
        // strip leading zeroes from byte array
        return bytes
            .iter()
            .position(|&b| b != 0)
            .map(|pos| &bytes[pos..])
            .unwrap_or(&bytes[bytes.len() - 1..]); // keep at least 1 byte
    }

    let s_b64: String = (0..s_hex.len())
        .step_by(3)
        .map(|i| &s_hex[i..i + 3]) // -> 3-digit strings
        .map(|three_digits_hex: &str| hex_to_bin(three_digits_hex)) // --> 12-digit
        // binary strings
        .map(|twelve_digits_bin: String| {
            (0..twelve_digits_bin.len())
                .step_by(6)
                .map(|j| u8::from_str_radix(&twelve_digits_bin[j..j + 6], 2).unwrap() << 2)
                .collect()
        }) // --> integer pairs for each 6-digit binary string slice
        .map(|two_integers: Vec<u8>| {
            two_integers
                .iter()
                .map(|n| {
                    Base64Engine.encode(strip_leading_zeroes(&(n.to_be_bytes())))[0..1].to_owned()
                })
                .collect::<String>()
        }) // --> b64 digit pairs concatenated into Strings
        .collect(); // --> concatenate all the b64 digit Strings

    return s_b64;
}

pub fn fixed_xor(s_hex: &str, t_hex: &str) -> String {
    assert_eq!(s_hex.len(), t_hex.len());
    let (s_bin, t_bin): (String, String) = (hex_to_bin(s_hex), hex_to_bin(t_hex));
    let r_bin: String = s_bin
        .chars()
        .zip(t_bin.chars())
        .map(|(s, t): (char, char)| (s.to_digit(2).unwrap() as u8) ^ (t.to_digit(2).unwrap() as u8))
        .map(|d: u8| format!("{:b}", d))
        .collect();
    return bin_to_hex(&r_bin);
}

fn frequency_sequence(text: &str) -> String {
    let mut letters: Vec<char> = String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZ").chars().collect();
    let frequencies: Vec<f32> = letters.clone().into_iter()
        .map(|letter| text.matches(letter).count() as f32 / text.len() as f32)
        .collect();
    let map: HashMap<char, f32> = letters.clone().into_iter()
        .zip(frequencies)
        .collect::<Vec::<(char, f32)>>()
        .iter()
        .cloned()
        .collect();
    letters.sort_by(|a, b| map[b].partial_cmp(&map[a]).unwrap());
    return letters.into_iter().collect();
}

pub fn score(text: &str) -> usize {
    let golden_frequency_sequence = String::from("ETAONRISHDLFCMUGYPWBVKJXZQ");
    let actual_frequency_sequence = frequency_sequence(&text.to_uppercase());
    println!("{}", golden_frequency_sequence);
    println!("{}", actual_frequency_sequence);
    let distance = 26 as usize - levenshtein(&golden_frequency_sequence, &actual_frequency_sequence);
    return distance;
}
