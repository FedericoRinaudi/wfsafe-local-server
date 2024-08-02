use std::mem;
use std::ops::Deref;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Keys {
    padding_key: [u8; 32],
    dummy_packet_key: [u8; 32],
}

impl Deref for Keys {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Keys as *const u8,
                mem::size_of::<Keys>(),
            )
        }
    }
}
