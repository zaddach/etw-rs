pub mod compound;
pub mod in_value;
pub mod misc;
pub mod primitives;
pub mod strings;
pub mod value;
pub mod event;

pub trait RawBytes {
    fn raw_size(&self) -> usize;
    fn raw_data(&self) -> &[u8];
}

trait ItemSize {
    const ITEM_SIZE: usize;
}

#[cfg(not(feature = "unchecked_cast"))]
trait FromLeBytes {
    type Array;

    fn from_le_bytes(bytes: &Self::Array) -> Self;
}

#[allow(dead_code)]
trait TypeName {
    const TYPE_NAME: &'static str;
}
