use crate::schema::in_type::InType;

use super::{
    misc::Sid,
    primitives::{
        DoubleRef, FileTimeRef, FloatRef, GuidRef, Int16Ref, Int32Ref, Int64Ref, Int8Ref,
        SystemTimeRef, UInt16Ref, UInt32Ref, UInt64Ref, UInt8Ref, USizeRef,
    },
    strings::{CountedEtwString, EtwString},
};

#[derive(Debug)]
pub enum InValue<'a> {
    Null,
    UnicodeString(Vec<EtwString<'a, u16>>),
    AnsiString(Vec<EtwString<'a, u8>>),
    Int8(Int8Ref<'a>),
    UInt8(UInt8Ref<'a>),
    Int16(Int16Ref<'a>),
    UInt16(UInt16Ref<'a>),
    Int32(Int32Ref<'a>),
    UInt32(UInt32Ref<'a>),
    Int64(Int64Ref<'a>),
    UInt64(UInt64Ref<'a>),
    Float(FloatRef<'a>),
    Double(DoubleRef<'a>),
    Boolean(UInt32Ref<'a>),
    Binary(Vec<&'a [u8]>),
    Guid(GuidRef<'a>),
    Pointer(USizeRef<'a>),
    FileTime(FileTimeRef<'a>),
    SystemTime(SystemTimeRef<'a>),
    Sid(Vec<Sid<'a>>),
    HexInt32(UInt32Ref<'a>),
    HexInt64(UInt64Ref<'a>),
    //ManifestCountedString(&'a [UInt16<'a>]),
    //ManifestCountedAnsiString(&'a [u8]),
    //ManifestCountedBinary(&'a [u8]),
    CountedString(Vec<CountedEtwString<'a, u16>>),
    CountedAnsiString(Vec<CountedEtwString<'a, u8>>),
    ReversedCountedString(Vec<CountedEtwString<'a, u16>>),
    ReversedCountedAnsiString(Vec<CountedEtwString<'a, u8>>),
    NonNullTerminatedString(&'a [u16]),
    NonNullTerminatedAnsiString(&'a [u8]),
    UnicodeChar(UInt16Ref<'a>),
    AnsiChar(UInt8Ref<'a>),
    SizeT(USizeRef<'a>),
    HexDump(&'a [u8]),
    WbemSid(&'a [u8]),
}

impl<'a> InValue<'a> {
    pub fn datatype(&self) -> InType {
        match self {
            Self::Null => InType::Null,
            Self::UnicodeString(_) => InType::UnicodeString,
            Self::AnsiString(_) => InType::AnsiString,
            Self::Int8(_) => InType::Int8,
            Self::UInt8(_) => InType::UInt8,
            Self::Int16(_) => InType::Int16,
            Self::UInt16(_) => InType::UInt16,
            Self::Int32(_) => InType::Int32,
            Self::UInt32(_) => InType::UInt32,
            Self::Int64(_) => InType::Int64,
            Self::UInt64(_) => InType::UInt64,
            Self::Float(_) => InType::Float,
            Self::Double(_) => InType::Double,
            Self::Boolean(_) => InType::Boolean,
            Self::Binary(_) => InType::Binary,
            Self::Guid(_) => InType::Guid,
            Self::Pointer(_) => InType::Pointer,
            Self::FileTime(_) => InType::FileTime,
            Self::SystemTime(_) => InType::SystemTime,
            Self::Sid(_) => InType::Sid,
            Self::HexInt32(_) => InType::HexInt32,
            Self::HexInt64(_) => InType::HexInt64,
            //Self::ManifestCountedString(_) => InType::ManifestCountedString,
            //Self::ManifestCountedAnsiString(_) => InType::ManifestCountedAnsiString,
            //Self::ManifestCountedBinary(_) => InType::ManifestCountedBinary,
            Self::CountedString(_) => InType::CountedString,
            Self::CountedAnsiString(_) => InType::CountedAnsiString,
            Self::ReversedCountedString(_) => InType::ReversedCountedString,
            Self::ReversedCountedAnsiString(_) => InType::ReversedCountedAnsiString,
            Self::NonNullTerminatedString(_) => InType::NonNullTerminatedString,
            Self::NonNullTerminatedAnsiString(_) => InType::NonNullTerminatedAnsiString,
            Self::UnicodeChar(_) => InType::UnicodeChar,
            Self::AnsiChar(_) => InType::AnsiChar,
            Self::SizeT(_) => InType::SizeT,
            Self::HexDump(_) => InType::HexDump,
            Self::WbemSid(_) => InType::WbemSid,
        }
    }
}
