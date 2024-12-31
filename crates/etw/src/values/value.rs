use crate::{
    error::ParseError,
    schema::in_type::InType,
    values::{primitives::SystemTimeRef, ItemSize},
};

use super::{
    in_value::InValue,
    misc::Sid,
    primitives::{
        DoubleRef, FileTimeRef, FloatRef, GuidRef, Int16Ref, Int32Ref, Int64Ref, Int8Ref,
        UInt16Ref, UInt32Ref, UInt64Ref, UInt8Ref, USizeRef,
    },
    strings::{parse_string_array, CountedEtwString, EtwString},
};

#[derive(Debug)]
pub struct Value<'a> {
    pub(crate) raw: &'a [u8],
    pub value: InValue<'a>,
    pub is_array: bool,
}

impl<'a> Value<'a> {
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn value(&self) -> &InValue<'a> {
        &self.value
    }

    pub fn is_array(&self) -> bool {
        self.is_array
    }
}

macro_rules! decode_plain_type {
    ($ty: ident, $variant: ident, $data: ident, $length: ident, $count: ident) => {
        if $length != $ty::ITEM_SIZE {
            return Err(ParseError::UnexpectedSize);
        } else {
            if $data.len() < $length * $count {
                return Err(ParseError::PrematureEndOfData);
            } else {
                (
                    InValue::$variant(
                        ($ty {
                            data: &$data[..$length * $count],
                        }),
                    ),
                    &$data[..$length * $count],
                    &$data[$length * $count..],
                )
            }
        }
    };
}

impl<'a> Value<'a> {
    pub fn parse<'b>(
        data: &'b [u8],
        value_type: InType,
        length: usize,
        count: usize,
        is_array: bool,
    ) -> Result<(Value<'a>, &'b [u8]), ParseError>
    where
        'b: 'a,
    {
        let (value, raw, remainder) = match value_type {
            InType::Null => (InValue::Null, &[] as &[u8], data),
            InType::UnicodeString => {
                if length != 0 {
                    return Err(ParseError::UnexpectedSize);
                }
                let (strings, raw_size, remainder) =
                    parse_string_array::<EtwString<u16>>(data, length, count)?;

                (
                    InValue::UnicodeString(strings),
                    &data[0..raw_size],
                    remainder,
                )
            }
            InType::AnsiString => {
                if length != 0 {
                    return Err(ParseError::UnexpectedSize);
                }
                let (strings, raw_size, remainder) =
                    parse_string_array::<EtwString<u8>>(data, length, count)?;

                (InValue::AnsiString(strings), &data[0..raw_size], remainder)
            }
            InType::Int8 => decode_plain_type!(Int8Ref, Int8, data, length, count),
            InType::UInt8 => decode_plain_type!(UInt8Ref, UInt8, data, length, count),
            InType::Int16 => decode_plain_type!(Int16Ref, Int16, data, length, count),
            InType::UInt16 => decode_plain_type!(UInt16Ref, UInt16, data, length, count),
            InType::Int32 => decode_plain_type!(Int32Ref, Int32, data, length, count),
            InType::UInt32 => decode_plain_type!(UInt32Ref, UInt32, data, length, count),
            InType::Int64 => decode_plain_type!(Int64Ref, Int64, data, length, count),
            InType::UInt64 => decode_plain_type!(UInt64Ref, UInt64, data, length, count),
            InType::Float => decode_plain_type!(FloatRef, Float, data, length, count),
            InType::Double => decode_plain_type!(DoubleRef, Double, data, length, count),
            InType::Boolean => decode_plain_type!(UInt32Ref, Boolean, data, length, count),
            InType::Binary => {
                if length == 0 {
                    return Err(ParseError::UnexpectedSize);
                }

                let mut values = Vec::with_capacity(count);

                for idx in 0..count {
                    values.push(&data[idx * length..(idx + 1) * length]);
                }

                (
                    InValue::Binary(values),
                    &data[0..length * count],
                    &data[length * count..],
                )
            }
            InType::Guid => decode_plain_type!(GuidRef, Guid, data, length, count),
            InType::Pointer => decode_plain_type!(USizeRef, Pointer, data, length, count),
            InType::FileTime => decode_plain_type!(FileTimeRef, FileTime, data, length, count),
            InType::SystemTime => {
                decode_plain_type!(SystemTimeRef, SystemTime, data, length, count)
            }
            InType::Sid => {
                if length != 0 {
                    return Err(ParseError::UnexpectedSize);
                }
                let mut sids = Vec::with_capacity(count);

                let mut raw_size = 0;
                let mut remainder = data;

                for _ in 0..count {
                    match Sid::new(remainder) {
                        Some(sid) => {
                            let size = sid.size();
                            raw_size += size;
                            remainder = &remainder[size..];
                            sids.push(sid);
                        }
                        None => return Err(ParseError::InvalidSid),
                    }
                }

                (InValue::Sid(sids), &data[0..raw_size], remainder)
            }
            InType::HexInt32 => decode_plain_type!(UInt32Ref, HexInt32, data, length, count),
            InType::HexInt64 => decode_plain_type!(UInt64Ref, HexInt64, data, length, count),
            InType::CountedString => {
                if length != 0 {
                    return Err(ParseError::UnexpectedSize);
                }

                let (strings, raw_size, remainder) =
                    parse_string_array::<CountedEtwString<u16>>(data, length, count)?;
                (
                    InValue::CountedString(strings),
                    &data[0..raw_size],
                    remainder,
                )
            }
            InType::CountedAnsiString => {
                if length != 0 {
                    return Err(ParseError::UnexpectedSize);
                }

                let (strings, raw_size, remainder) =
                    parse_string_array::<CountedEtwString<u8>>(data, length, count)?;
                (
                    InValue::CountedAnsiString(strings),
                    &data[0..raw_size],
                    remainder,
                )
            }
            InType::ReversedCountedString => {
                if length != 0 {
                    return Err(ParseError::UnexpectedSize);
                }

                let (strings, raw_size, remainder) =
                    parse_string_array::<CountedEtwString<u16>>(data, length, count)?;
                (
                    InValue::ReversedCountedString(strings),
                    &data[0..raw_size],
                    remainder,
                )
            }
            InType::ReversedCountedAnsiString => {
                if length != 0 {
                    return Err(ParseError::UnexpectedSize);
                }

                let (strings, raw_size, remainder) =
                    parse_string_array::<CountedEtwString<u8>>(data, length, count)?;
                (
                    InValue::ReversedCountedAnsiString(strings),
                    &data[0..raw_size],
                    remainder,
                )
            }
            InType::NonNullTerminatedString => return Err(ParseError::UnknownInType(value_type)),
            InType::NonNullTerminatedAnsiString => {
                return Err(ParseError::UnknownInType(value_type))
            }
            InType::UnicodeChar => decode_plain_type!(UInt16Ref, UnicodeChar, data, length, count),
            InType::AnsiChar => decode_plain_type!(UInt8Ref, AnsiChar, data, length, count),
            InType::SizeT => decode_plain_type!(USizeRef, SizeT, data, length, count),
            InType::HexDump => return Err(ParseError::UnknownInType(value_type)),
            InType::WbemSid => return Err(ParseError::UnknownInType(value_type)),
            _ => return Err(ParseError::UnknownInType(value_type)),
        };

        Ok((
            Value {
                raw,
                value,
                is_array,
            },
            remainder,
        ))
    }
}
