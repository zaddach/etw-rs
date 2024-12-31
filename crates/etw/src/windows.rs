use std::{ffi, fmt};

use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Authorization::ConvertSidToStringSidW,
    },
};

use crate::error::ParseError;

pub mod core {
    pub use windows::core::{GUID, Error, Result};
}

#[allow(non_snake_case)]
pub mod Win32 {
    #[allow(non_snake_case)]
    pub mod System {
        #[allow(non_snake_case)]
        pub mod Diagnostics {
            #[allow(non_snake_case)]
            pub mod Etw {
                pub use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, EVENT_DESCRIPTOR};
            }
        }
    }

    #[allow(non_snake_case)]
    pub mod Foundation {
        pub use windows::Win32::Foundation::ERROR_NOT_FOUND;
    }
}


impl TryFrom<&Sid> for String {
    type Error = ParseError;

    fn try_from(value: &Sid) -> Result<Self, Self::Error> {
        let mut stringsid = PWSTR::null();
        unsafe {
            match ConvertSidToStringSidW(value.0, &mut stringsid) {
                Ok(()) => {
                    let result = stringsid.to_string();
                    let _ = LocalFree(HLOCAL(stringsid.as_ptr() as *mut ffi::c_void));
                    match result {
                        Ok(string) => Ok(string),
                        Err(err) => Err(ParseError::Utf16Decode(err)),
                    }
                }
                Err(err) => Err(ParseError::Windows(err)),
            }
        }
    }
}

#[repr(transparent)]
pub struct Sid(pub windows::Win32::Security::PSID);

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match String::try_from(self) {
            Ok(string) => f.write_str(&string),
            Err(err) => f.write_fmt(format_args!("<error decoding SID: {}>", err)),
        }
    }
}
