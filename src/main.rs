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

pub fn decode_ascii85(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
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

#[cfg(test)]
mod tests {

    use super::decode_ascii85;

    #[test]
    fn decode_ascii85_test() {
        assert_eq!(
            decode_ascii85("<~9jqo^F*2M7/c~>").unwrap(),
            [77, 97, 110, 32, 115, 117, 114, 101, 46]
        );
        assert!(
            &decode_ascii85(r#"
                <~9jqo^BlbD-BleB1DJ+*+F(f,q/0JhKF<GL>Cj@.4Gp$d7F!,L7@<6@)/0JDEF<G%<+EV:2F!,
                O<DJ+*.@<*K0@<6L(Df-\0Ec5e;DffZ(EZee.Bl.9pF"AGXBPCsi+DGm>@3BB/F*&OCAfu2/AKY
                i(DIb:@FD,*)+C]U=@3BN#EcYf8ATD3s@q?d$AftVqCh[NqF<G:8+EV:.+Cf>-FD5W8ARlolDIa
                l(DId<j@<?3r@:F%a+D58'ATD4$Bl@l3De:,-DJs`8ARoFb/0JMK@qB4^F!,R<AKZ&-DfTqBG%G
                >uD.RTpAKYo'+CT/5+Cei#DII?(E,9)oF*2M7/c~>"#
            ).unwrap().iter().zip(b"Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.".iter())
            .all(|(a, b)| a == b)
        );
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let step_1 = fs::read_to_string("step_1.txt")?;

    let payload_1 = get_payload(&step_1)?;

    let decoded = decode_ascii85(payload_1)?;

    fs::write("step_2.txt", String::from_utf8_lossy(&decoded).as_bytes())?;

    Ok(())
}
