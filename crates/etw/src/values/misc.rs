use std::mem;

use windows::Win32::Security::{GetLengthSid, IsValidSid, PSID};

#[derive(Debug)]
pub struct Sid<'a> {
    psid: PSID,
    data: &'a [u8],
}

impl<'a> Sid<'a> {
    pub fn new<'b>(data: &'a [u8]) -> Option<Self>
    where
        'b: 'a,
    {
        unsafe {
            let psid = mem::transmute::<*const u8, PSID>(data.as_ptr());
            if IsValidSid(psid).as_bool() {
                None
            } else {
                let length = usize::try_from(GetLengthSid(psid)).ok()?;
                Some(Self {
                    psid,
                    data: &data[0..length],
                })
            }
        }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn is_valid(&self) -> bool {
        unsafe { IsValidSid(self.psid).into() }
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}
