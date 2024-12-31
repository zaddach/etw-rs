use std::{collections::BTreeMap, ffi, fmt};
use std::os::windows::ffi::OsStringExt;

use super::value::Value;

pub enum Property<'a> {
    Scalar(Value<'a>),
    Struct(StructProperty<'a>),
    Array(ArrayProperty),
}

pub struct StructProperty<'a> {
    _properties: BTreeMap<usize, Property<'a>>,
}

pub struct ArrayProperty;

pub struct RawU16StringRef<'a>(&'a [u8]);

impl<'a> RawU16StringRef<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self(data)
    }

    pub fn to_string(&self) -> Result<String, std::string::FromUtf16Error> {
        let chars = self.to_vec();
        if chars.last() == Some(&0) {
            String::from_utf16(&chars[ .. chars.len() - 1])
        } else {
            String::from_utf16(&chars)
        }
    }

    pub fn to_os_string(&self) -> ffi::OsString {
        ffi::OsString::from_wide(&self.to_vec())
    }

    pub fn to_vec(&self) -> Vec<u16> {
        self.0.chunks_exact(2).map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])).collect()
    }

}

impl fmt::Debug for RawU16StringRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawU16StringRef")
        .field("data", &self.to_string())
        .finish()
    }
}

#[derive(Debug)]
pub enum StringOrStruct<'a> {
    String(RawU16StringRef<'a>),
    Struct(Struct<'a>),
}

#[derive(Debug)]
pub struct Struct<'a> {
    pub values: Vec<StructOrValue<'a>>,
}

#[derive(Debug)]
pub struct StructArray<'a> {
    pub values: Vec<Struct<'a>>,
    pub is_array: bool,
}

#[derive(Debug)]
pub enum StructOrValue<'a> {
    Struct(StructArray<'a>),
    Value(Value<'a>),
}
