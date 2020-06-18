use std::{error::Error, fs};

fn get_payload(input: &str) -> Result<&str, Box<dyn Error>> {
    Ok(input
        .split("==[ Payload ]===============================================")
        .nth(1)
        .ok_or("Error")?)
}

fn decode_ascii85_digit(digit: u8, counter: &mut usize, chunk: &mut u32, result: &mut Vec<u8>) {
    const TABLE: [u32; 5] = [85 * 85 * 85 * 85, 85 * 85 * 85, 85 * 85, 85, 1];

    let byte = digit - 33;

    *chunk += byte as u32 * TABLE[*counter];

    if *counter == 4 {
        result.extend_from_slice(&chunk.to_be_bytes());
        *chunk = 0;
        *counter = 0;
    } else {
        *counter += 1;
    }
}

fn decode_ascii85(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut result = Vec::with_capacity(4 * (input.len() / 5 + 16));

    let mut counter = 0;
    let mut chunk = 0;

    for digit in input
        .split("<~")
        .nth(1)
        .ok_or("Error")?
        .rsplit("~>")
        .nth(1)
        .ok_or("Error")?
        .bytes()
        .filter(|c| !c.is_ascii_whitespace())
    {
        if digit == b'z' {
            if counter == 0 {
                result.extend_from_slice(&[0, 0, 0, 0]);
            } else {
                return Err("Bad input".into());
            }
        }

        if digit < 33 || digit > 117 {
            return Err("Bad input".into());
        }

        decode_ascii85_digit(digit, &mut counter, &mut chunk, &mut result);
    }

    let mut to_remove = 0;

    while counter != 0 {
        decode_ascii85_digit(b'u', &mut counter, &mut chunk, &mut result);
        to_remove += 1;
    }

    result.drain((result.len() - to_remove)..result.len());

    Ok(result)
}

fn main() -> Result<(), Box<dyn Error>> {
    let step_1 = fs::read_to_string("step_1.txt")?;

    let payload_1 = get_payload(&step_1)?;

    let decoded = decode_ascii85(payload_1)?;

    fs::write("step_2.txt", String::from_utf8_lossy(&decoded).as_bytes())?;

    Ok(())
}
