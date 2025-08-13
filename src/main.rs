mod set1;
use base64::prelude::*;

fn main() {
    println!(
        "{}",
        set1::hex_to_base64(
            &"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        )
    );

    println!(
        "{:?}",
        set1::bin_to_hex(&set1::fixed_xor(
            &set1::hex_to_bin(&"1c0111001f010100061a024b53535009181c"),
            &set1::hex_to_bin(&"686974207468652062756c6c277320657965"),
        ))
    );

    println!(
        "{}",
        String::from_utf8(
            set1::brute_force_single_character_xor(&set1::hex_to_bin(
                &"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
            ))
            .0
        )
        .unwrap()
    );

    let text = std::fs::read_to_string("data/4.txt").expect("Failed to read file");
    let texts_bin: Vec<Vec<u8>> = text.lines().map(|text| set1::hex_to_bin(text)).collect();
    let texts_bin_typecast: Vec<&[u8]> = (0..texts_bin.len())
        .map(|i| texts_bin[i].as_slice())
        .collect();
    println!(
        "{}",
        String::from_utf8(set1::detect_single_character_xor(&texts_bin_typecast)).unwrap()
    );

    let text = std::fs::read_to_string("data/5.txt").expect("Failed to read file");
    let text_bin: Vec<u8> = set1::plaintext_to_bin(&text);
    let cypher: Vec<u8> = set1::plaintext_to_bin(&"ICE");
    println!(
        "{}",
        set1::bin_to_hex(&set1::decrypt_with_repeating_key_xor(&text_bin, &cypher))
    );

    assert_eq!(
        37,
        set1::hamming_distance(
            &set1::plaintext_to_bin(&"this is a test"),
            &set1::plaintext_to_bin(&"wokka wokka!!!")
        )
    );
    let text: String = std::fs::read_to_string("data/6.txt")
        .expect("Failed to read file")
        .lines()
        .collect();
    let text_bin = BASE64_STANDARD.decode(text).unwrap();
    // println!("{:?}", text_bin);
    // for bin in &text_bin {
    //     print!("{:b}", bin);
    // }
    let (decrypted_text_bin, _) = set1::break_repeating_key_xor(&text_bin);
    println!("{}", String::from_utf8(decrypted_text_bin).unwrap());
}
