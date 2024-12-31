use std::{
    mem::{
        self,
        size_of,
    }, slice
};

use crate::error::ParseError;

use super::RawBytes;

pub trait ParseString<'a> {
    fn parse<'b>(data: &'b [u8]) -> Result<(Self, &'b [u8]), ParseError>
    where
        'b: 'a,
        Self: Sized;
}

#[derive(Debug)]
pub struct EtwString<'a, T> {
    pub data: &'a [u8],
    _phantom: std::marker::PhantomData<T>,
}

impl<'a, T> EtwString<'a, T> {
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn len(&self) -> usize {
        self.data.len() / size_of::<T>()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<'a, T> RawBytes for EtwString<'a, T>
{
    fn raw_size(&self) -> usize {
        self.data.len()
    }

    fn raw_data(&self) -> &[u8] {
        self.data
    }
}

impl<'a> EtwString<'a, u8> {
    pub fn has_trailing_null(&self) -> bool {
        self.data.last().map(|c| *c == 0).unwrap_or(false)
    }
}

impl<'a> EtwString<'a, u16> {
    pub fn has_trailing_null(&self) -> bool {
        self.data.last().map(|c| *c == 0).unwrap_or(false)
    }
}

impl<'a, T> ParseString<'a> for EtwString<'a, T>
{
    fn parse<'b>(data: &'b [u8]) -> Result<(Self, &'b [u8]), ParseError>
    where
        'b: 'a,
    {
        let chunks = data.chunks_exact(size_of::<T>());
        let remainder = chunks.remainder();
        for (idx, chunk) in chunks.enumerate() {
            if chunk.iter().all(|c| *c == 0) {
                let length = idx + 1;
                return Ok((
                    Self {
                        data: (&data[..length * size_of::<T>()]),
                        _phantom: std::marker::PhantomData,
                    },
                    &data[length * size_of::<T>()..],
                ));
            }
        }

        let length = data.len() / size_of::<T>();
        Ok((
            Self {
                data: (&data[..length * size_of::<T>()]),
                _phantom: std::marker::PhantomData,
            },
            remainder,
        ))
    }
}

impl<'a> std::fmt::Display for EtwString<'a, u8> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = if self.has_trailing_null() {self.data.split_last().map(|d| d.1).unwrap_or(&[])} else {self.data};
        f.write_str(std::str::from_utf8(data).map_err(|_| std::fmt::Error)?)
    }
}

impl<'a> std::fmt::Display for EtwString<'a, u16> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let data = std::slice::from_raw_parts(self.data.as_ptr() as *const u16, self.data.len() / std::mem::size_of::<u16>());
            let data = if self.has_trailing_null() {data.split_last().map(|d| d.1).unwrap_or(&[])} else {data};
            f.write_str(& String::from_utf16(data).map_err(|_| std::fmt::Error)?)
        }
    }
}

#[derive(Debug)]
pub struct CountedEtwString<'a, T> {
    pub data: &'a [T],
}

impl<'a, T> CountedEtwString<'a, T> {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn data(&self) -> &'a [T] {
        self.data
    }
}

impl<'a, T> RawBytes for CountedEtwString<'a, T>
{
    fn raw_size(&self) -> usize {
        mem::size_of_val(self.data)
    }

    fn raw_data(&self) -> &'a [u8] {
        unsafe {
            slice::from_raw_parts(
                self.data.as_ptr() as *const u8,
                mem::size_of_val(self.data),
            )
        }
    }
}

impl<'a, T> ParseString<'a> for CountedEtwString<'a, T>
{
    fn parse<'b>(data: &'b [u8]) -> Result<(Self, &'b [u8]), ParseError>
    where
        'b: 'a,
    {
        let length = usize::from(u16::from_le_bytes(
            data[0..size_of::<u16>()]
                .try_into()
                .map_err(|_| ParseError::PrematureEndOfData)?,
        ));
        if data.len() < size_of::<u16>() + length * size_of::<u16>() {
            return Err(ParseError::PrematureEndOfData);
        }
        let string_data = &data[size_of::<u16>()..size_of::<u16>() + length * mem::size_of::<u16>()];
        let remaining_data = &data[size_of::<u16>() + length * mem::size_of::<u16>() .. ];
        if mem::size_of_val(string_data) % mem::size_of::<T>() != 0 {
            return Err(ParseError::UnexpectedSize);
        }
        #[cfg(not(feature = "unchecked_cast"))]
        if mem::align_of_val(&data) < mem::align_of::<T>() {
            return Err(ParseError::UnalignedData(stringify!($name).to_string()));
        }
        unsafe {
            Ok((
                Self {
                    data: slice::from_raw_parts(string_data.as_ptr() as *const T, string_data.len() / mem::size_of::<T>()),
                },
                remaining_data,
            ))
        }
    }
}

impl<'a, T> CountedEtwString<'a, T>
{
    pub fn raw_data(&self) -> &'a [u8] {
        unsafe {
            slice::from_raw_parts(
                self.data.as_ptr() as *const u8,
                mem::size_of_val(self.data),
            )
        }
    }
}

pub fn parse_string_array<'a, T>(
    data: &'a [u8],
    length: usize,
    count: usize,
) -> Result<(Vec<T>, usize, &'a [u8]), ParseError>
where
    T: RawBytes + ParseString<'a>,
{
    if length != 0 {
        return Err(ParseError::UnexpectedSize);
    }
    let mut strings = Vec::with_capacity(count);

    let mut remainder = data;
    let mut raw_size = 0;
    for _ in 0..count {
        let (string, rest) = T::parse(remainder)?;
        remainder = rest;
        raw_size += string.raw_size();
        strings.push(string);
    }
    Ok((strings, raw_size, remainder))
}
