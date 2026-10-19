#![no_std]
// Illustrative no_std API. Compiles in a Rust crate with a suitable target toolchain.
// Every 32-bit target still serializes the canonical eight big-endian octets.
#[derive(Copy,Clone,Debug,PartialEq,Eq)]
pub struct Fields {
    pub core:u32, pub scale:u8, pub stream_slot:u8, pub form_id:u8,
    pub step_index:u8, pub gate:u8, pub structure:u8, pub wheel_unit:u8, pub cycle_step:u8
}
pub fn pack(f:Fields)->Result<[u8;8], &'static str> {
    if f.scale>15 || f.stream_slot>15 || f.form_id>15 ||
       f.step_index>15 || f.structure>3 || f.wheel_unit>7 || f.cycle_step>7 {
        return Err("range");
    }
    let word = (f.core as u64) | ((f.scale as u64)<<32) |
        ((f.stream_slot as u64)<<36) | ((f.form_id as u64)<<40) |
        ((f.step_index as u64)<<44) | ((f.gate as u64)<<48) |
        ((f.structure as u64)<<56) | ((f.wheel_unit as u64)<<58) |
        ((f.cycle_step as u64)<<61);
    Ok(word.to_be_bytes())
}
pub fn unpack(bytes:[u8;8])->Fields {
    let w=u64::from_be_bytes(bytes);
    Fields {core:w as u32, scale:((w>>32)&15)as u8,
        stream_slot:((w>>36)&15)as u8, form_id:((w>>40)&15)as u8,
        step_index:((w>>44)&15)as u8, gate:((w>>48)&255)as u8,
        structure:((w>>56)&3)as u8, wheel_unit:((w>>58)&7)as u8,
        cycle_step:((w>>61)&7)as u8}
}
