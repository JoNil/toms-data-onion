use std::{error::Error, fs};

fn main() -> Result<(), Box<dyn Error>>{

    let step_1 = fs::read_to_string("step_1.txt")?;

    let payload_1 = step_1.split("==[ Payload ]===============================================").nth(1).ok_or("Error")?;

    println!("{}", payload_1);

    Ok(())
}
