use std::mem;

use windows::{
    core::GUID,
    Win32::Foundation::{FILETIME, SYSTEMTIME},
};

#[cfg(not(feature = "unchecked_cast"))]
use super::FromLeBytes;
use super::{ItemSize, TypeName};

#[cfg(not(feature = "unchecked_cast"))]
macro_rules! impl_from_le_bytes {
    ($ty: ty) => {
        impl FromLeBytes for $ty {
            type Array = [u8; mem::size_of::<$ty>()];

            fn from_le_bytes(bytes: &Self::Array) -> Self {
                <$ty>::from_le_bytes(*bytes)
            }
        }
    };
}
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(i8);
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(u8);
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(i16);
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(u16);
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(i32);
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(u32);
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(i64);
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(u64);
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(f32);
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(f64);
#[cfg(not(feature = "unchecked_cast"))]
impl_from_le_bytes!(usize);

static_assertions::assert_eq_size!(FILETIME, [u32; 2]);

#[cfg(not(feature = "unchecked_cast"))]
impl FromLeBytes for FILETIME {
    type Array = [u8; mem::size_of::<FILETIME>()];

    fn from_le_bytes(bytes: &Self::Array) -> Self {
        FILETIME {
            dwLowDateTime: u32::from_le_bytes(bytes[..mem::size_of::<u32>()].try_into().unwrap()),
            dwHighDateTime: u32::from_le_bytes(bytes[mem::size_of::<u32>()..].try_into().unwrap()),
        }
    }
}

static_assertions::assert_eq_size!(SYSTEMTIME, [u16; 8]);

#[cfg(not(feature = "unchecked_cast"))]
impl FromLeBytes for SYSTEMTIME {
    type Array = [u8; mem::size_of::<SYSTEMTIME>()];

    fn from_le_bytes(bytes: &Self::Array) -> Self {
        SYSTEMTIME {
            wYear: u16::from_le_bytes(bytes[ .. mem::size_of::<u16>()].try_into().unwrap()),
            wMonth: u16::from_le_bytes(bytes[mem::size_of::<u16>() .. mem::size_of::<u16>() * 2].try_into().unwrap()),
            wDayOfWeek: u16::from_le_bytes(bytes[mem::size_of::<u16>() * 2 .. mem::size_of::<u16>() * 3].try_into().unwrap()),
            wDay: u16::from_le_bytes(bytes[mem::size_of::<u16>() * 3 .. mem::size_of::<u16>() * 4].try_into().unwrap()),
            wHour: u16::from_le_bytes(bytes[mem::size_of::<u16>() * 4 .. mem::size_of::<u16>() * 5].try_into().unwrap()),
            wMinute: u16::from_le_bytes(bytes[mem::size_of::<u16>() * 5 .. mem::size_of::<u16>() * 6].try_into().unwrap()),
            wSecond: u16::from_le_bytes(bytes[mem::size_of::<u16>() * 6 .. mem::size_of::<u16>() * 7].try_into().unwrap()),
            #[allow(clippy::manual_bits)] // FP, not trying to get bit size here
            wMilliseconds: u16::from_le_bytes(bytes[mem::size_of::<u16>() * 7 .. mem::size_of::<u16>() * 8].try_into().unwrap()),
        }
    }
}

static_assertions::assert_eq_size!(GUID, u128);

#[cfg(not(feature = "unchecked_cast"))]
impl FromLeBytes for GUID {
    type Array = [u8; mem::size_of::<GUID>()];

    fn from_le_bytes(bytes: &Self::Array) -> Self {
        GUID::from_u128(u128::from_le_bytes(*bytes))
    }
}

// I tried to do the same with byte_slice_cast before,
// but the data in the ETW event record blob isn't necessarily aligned,
// and the byte slice cast doesn't like that. So define a reference type
// that uses .from_le_bytes(...) to correctly decode the type in any alignment.
macro_rules! define_primitive_type_ref {
    ($name: ident, $ty: ty) => {
        #[derive(Debug)]
        #[repr(transparent)]
        pub struct $name<'a> {
            pub data: &'a [u8],
        }

        impl TypeName for $name<'_> {
            const TYPE_NAME: &'static str = stringify!($name);
        }

        impl ItemSize for $name<'_> {
            const ITEM_SIZE: usize = mem::size_of::<$ty>();
        }

        impl<'a> $name<'a> {
            pub fn get(&self, idx: usize) -> Option<$ty> {
                let subslice = self
                    .data
                    .get(idx * mem::size_of::<$ty>()..(idx + 1) * mem::size_of::<$ty>())?;
                #[cfg(feature = "unchecked_cast")]
                unsafe {
                    Some((subslice.as_ptr() as *const $ty).read_unaligned())
                }
                #[cfg(not(feature = "unchecked_cast"))]
                Some(<$ty as FromLeBytes>::from_le_bytes(
                    subslice.try_into().ok()?,
                ))
            }

            #[inline]
            pub fn len(&self) -> usize {
                self.data.len() / mem::size_of::<$ty>()
            }

            #[inline]
            pub fn is_empty(&self) -> bool {
                self.data.is_empty()
            }

            #[inline]
            pub fn raw_data(&self) -> &[u8] {
                self.data
            }

            #[inline]
            pub fn item_size() -> usize {
                mem::size_of::<$ty>()
            }
        }
    };
}

define_primitive_type_ref!(Int8Ref, i8);
define_primitive_type_ref!(UInt8Ref, u8);
define_primitive_type_ref!(Int16Ref, i16);
define_primitive_type_ref!(UInt16Ref, u16);
define_primitive_type_ref!(Int32Ref, i32);
define_primitive_type_ref!(UInt32Ref, u32);
define_primitive_type_ref!(Int64Ref, i64);
define_primitive_type_ref!(UInt64Ref, u64);
define_primitive_type_ref!(FloatRef, f32);
define_primitive_type_ref!(DoubleRef, f64);
define_primitive_type_ref!(FileTimeRef, FILETIME);
define_primitive_type_ref!(SystemTimeRef, SYSTEMTIME);
define_primitive_type_ref!(GuidRef, GUID);
define_primitive_type_ref!(USizeRef, usize);
