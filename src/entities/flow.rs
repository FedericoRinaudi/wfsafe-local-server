use std::mem;
use std::ops::Deref;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
pub struct Flow {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

impl Deref for Flow {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Flow as *const u8,
                mem::size_of::<Flow>(),
            )
        }
    }
}