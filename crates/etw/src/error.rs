use std::{convert::Infallible, num::TryFromIntError, string::FromUtf16Error};

use windows::{core::GUID, Win32::Foundation::WIN32_ERROR};

use crate::schema::in_type::InType;

#[derive(thiserror::Error, Debug)]
pub enum TraceError {
    #[error("Windows API error: {0}")]
    Windows(#[from] windows::core::Error),
    #[error("Configuration error")]
    Configuration(String),
    #[error("Unexpected provider")]
    UnexpectedProvider(GUID),
    #[error("Unexpected event for provider")]
    UnexpectedProviderEvent(GUID, u16),
    #[error("Decode error")]
    Decode(#[from] ParseError),
    #[error("Thread join error")]
    ThreadJoin,
}

impl From<WIN32_ERROR> for TraceError {
    fn from(value: WIN32_ERROR) -> Self {
        TraceError::from(windows::core::Error::from(value))
    }
}

impl From<Infallible> for TraceError {
    fn from(_value: Infallible) -> Self {
        unreachable!()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Type hasn't finished parsing but there is no data left")]
    PrematureEndOfData,
    #[error("UTF16 decode error")]
    Utf16Decode(#[from] FromUtf16Error),
    #[error("Integer conversion error")]
    IntegerConversion(#[from] TryFromIntError),
    #[error("Component range")]
    ComponentRange(#[from] time::error::ComponentRange),
    #[error("ANSI decode error")]
    AnsiDecode(#[from] std::io::Error),
    #[error("Windows API error: {0}")]
    Windows(#[from] windows::core::Error),
    #[error("Unexpected size")]
    UnexpectedSize,
    #[error("Unexpected count")]
    UnexpectedCount,
    #[error("Invalid SID")]
    InvalidSid,
    #[error("Unknown in-type: {0}")]
    UnknownInType(InType),
    #[error("Unaligned data for type: {0}")]
    UnalignedData(String),
    #[error("Invalid property reference {0}")]
    InvalidPropertyReference(usize),
    #[error("Invalid property data type {0} for size or count")]
    InvalidPropertySizeType(InType),
    #[error("Property size or data type is not a scalar")]
    PropertySizeNotAScalar,
    #[error("Invalid index {index}/{count}")]
    IndexOutOfBounds { index: usize, count: usize },
    #[error("Cache mutex is poisoned")]
    CacheMutexPoisoned,
    #[error("Data left after decoding finished")]
    DataLeftAfterDecoding,
    #[error("Invalid type")]
    InvalidType,
    #[error("No map name")]
    NoMapName,
    #[error("Not implemented")]
    NotImplemented,
}

impl From<Infallible> for ParseError {
    fn from(_value: Infallible) -> Self {
        unreachable!()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParserBuilderError {
    #[error("Invalid index {index}/{count}")]
    IndexOutOfBounds { index: usize, count: usize },
    #[error("Invalid property reference {index}/{count}")]
    InvalidPropertyReference { index: usize, count: usize },
    #[error("Windows API error: {0}")]
    Windows(#[from] windows::core::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum EventPropertyInfoError {
    #[error("Invalid property index {index}/{count}")]
    IndexOutOfBounds { index: usize, count: usize },
    #[error("UTF16 decode error: {0}")]
    Utf16(#[from] FromUtf16Error),
}
