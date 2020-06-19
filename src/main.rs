use std::{error::Error, fs};

fn get_payload(input: &str) -> Result<&str, Box<dyn Error>> {
    Ok(input
        .split("==[ Payload ]===============================================")
        .nth(1)
        .ok_or("Error")?)
}

fn step_1() -> Result<(), Box<dyn Error>> {
    let input = fs::read_to_string("step_1.txt")?;
    let payload = get_payload(&input)?;

    let decoded = ascii85::decode(payload)?;

    fs::write("step_2.txt", String::from_utf8_lossy(&decoded).as_bytes())?;

    Ok(())
}

fn step_2() -> Result<(), Box<dyn Error>> {
    let input = fs::read_to_string("step_2.txt")?;

    let payload = get_payload(&input)?;

    let mut decoded = ascii85::decode(payload)?;

    for byte in &mut decoded {
        *byte = (*byte ^ 0b01010101).rotate_right(1)
    }

    fs::write("step_3.txt", String::from_utf8_lossy(&decoded).as_bytes())?;

    Ok(())
}

fn step_3() -> Result<(), Box<dyn Error>> {
    let input = fs::read_to_string("step_3.txt")?;

    let payload = get_payload(&input)?;

    let decoded = ascii85::decode(payload)?;

    let decoded = decoded
        .into_iter()
        .filter(|byte| {
            let data = *byte & 0b1111_1110;
            let parity = *byte & 0b1;
            data.count_ones() & 0b1 == parity as u32
        })
        .collect::<Vec<_>>();

    let mut result = Vec::new();

    for chunk in decoded.chunks_exact(8) {
        result.push(((chunk[0] & 0b1111_1110) << 0) | ((chunk[1] & 0b1000_0000) >> 7));
        result.push(((chunk[1] & 0b0111_1110) << 1) | ((chunk[2] & 0b1100_0000) >> 6));
        result.push(((chunk[2] & 0b0011_1110) << 2) | ((chunk[3] & 0b1110_0000) >> 5));
        result.push(((chunk[3] & 0b0001_1110) << 3) | ((chunk[4] & 0b1111_0000) >> 4));
        result.push(((chunk[4] & 0b0000_1110) << 4) | ((chunk[5] & 0b1111_1000) >> 3));
        result.push(((chunk[5] & 0b0000_0110) << 5) | ((chunk[6] & 0b1111_1100) >> 2));
        result.push(((chunk[6] & 0b0000_0010) << 6) | ((chunk[7] & 0b1111_1110) >> 1));
    }

    fs::write("step_4.txt", String::from_utf8_lossy(&result).as_bytes())?;

    Ok(())
}

fn step_4() -> Result<(), Box<dyn Error>> {
    let input = fs::read_to_string("step_4.txt")?;

    let payload = get_payload(&input)?;

    let decoded = ascii85::decode(payload)?;

    let key: [u8; 32] = [
        decoded[0] ^ b'=',
        decoded[1] ^ b'=',
        decoded[2] ^ b'[',
        decoded[3] ^ b' ',
        decoded[4] ^ b'L',
        decoded[5] ^ b'a',
        decoded[6] ^ b'y',
        decoded[7] ^ b'e',
        decoded[8] ^ b'r',
        decoded[9] ^ b' ',
        decoded[10] ^ b'4',
        decoded[11] ^ b'/',
        decoded[12] ^ b'5',
        decoded[45] ^ b'=',
        decoded[46] ^ b'=',
        decoded[47] ^ b'=',
        decoded[48] ^ b'=',
        decoded[49] ^ b'=',
        decoded[50] ^ b'=',
        decoded[51] ^ b'=',
        decoded[52] ^ b'=',
        decoded[53] ^ b'=',
        decoded[54] ^ b'=',
        decoded[55] ^ b'=',
        decoded[56] ^ b'=',
        decoded[57] ^ b'=',
        decoded[58] ^ b'=',
        decoded[59] ^ b'=',
        decoded[60] ^ b'\n',
        decoded[29] ^ b'c',
        decoded[30] ^ b' ',
        decoded[31] ^ b']',
    ];

    let decrypted = decoded
        .iter()
        .zip(key.iter().cycle())
        .map(|(ciphertext, key)| *ciphertext ^ *key)
        .collect::<Vec<_>>();

    fs::write("step_5.txt", String::from_utf8_lossy(&decrypted).as_bytes())?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    step_1()?;
    step_2()?;
    step_3()?;
    step_4()?;

    Ok(())
}
