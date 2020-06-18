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

fn main() -> Result<(), Box<dyn Error>> {

    step_1()?;
    step_2()?;

    Ok(())
}
