mod set1;
use hex;

fn main() {
    println!(
        "{}",
        set1::hex_to_base64(
            &"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        )
    );

    println!(
        "{}",
        set1::fixed_xor(
            &"1c0111001f010100061a024b53535009181c",
            &"686974207468652062756c6c277320657965",
        )
    );

    println!(
        "{}",
        String::from_utf8(
            hex::decode(set1::brute_force_single_character_xor(
                &"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
            ))
            .unwrap()
        )
        .unwrap()
    );
}
