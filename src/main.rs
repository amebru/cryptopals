mod set1;

fn main() {
    println!("{}", set1::hex_to_base64(&"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"));

    println!("{}", set1::fixed_xor(
        &"1c0111001f010100061a024b53535009181c",
        &"686974207468652062756c6c277320657965",
    ));

    println!("{}", set1::score("Arrays are useful when you want your data allocated on the stack, the same as the other types we have seen so far, rather than the heap (we will discuss the stack and the heap more in Chapter 4) or when you want to ensure you always have a fixed number of elements. An array isn’t as flexible as the vector type, though. A vector is a similar collection type provided by the standard library that is allowed to grow or shrink in size. If you’re unsure whether to use an array or a vector, chances are you should use a vector. Chapter 8 discusses vectors in more detail."));
}
