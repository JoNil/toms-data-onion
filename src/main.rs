use std::{error::Error, fs};

fn get_payload(input: &str) -> Result<&str, Box<dyn Error>> {
    Ok(input
        .split("==[ Payload ]===============================================")
        .nth(1)
        .ok_or("Error")?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let step_1 = fs::read_to_string("step_1.txt")?;

    let payload_1 = get_payload(&step_1)?;

    let decoded = ascii85::decode(payload_1)?;

    fs::write("step_2.txt", String::from_utf8_lossy(&decoded).as_bytes())?;

    Ok(())
}
