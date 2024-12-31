use windows::Win32::System::Diagnostics::Etw::{
    TDH_OUTTYPE_BOOLEAN, TDH_OUTTYPE_BYTE, TDH_OUTTYPE_CIMDATETIME,
    TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME, TDH_OUTTYPE_DATETIME, TDH_OUTTYPE_DOUBLE,
    TDH_OUTTYPE_ERRORCODE, TDH_OUTTYPE_ETWTIME, TDH_OUTTYPE_FLOAT, TDH_OUTTYPE_GUID,
    TDH_OUTTYPE_HEXBINARY, TDH_OUTTYPE_HEXINT16, TDH_OUTTYPE_HEXINT32, TDH_OUTTYPE_HEXINT64,
    TDH_OUTTYPE_HEXINT8, TDH_OUTTYPE_HRESULT, TDH_OUTTYPE_INT, TDH_OUTTYPE_IPV4, TDH_OUTTYPE_IPV6,
    TDH_OUTTYPE_JSON, TDH_OUTTYPE_LONG, TDH_OUTTYPE_NOPRINT, TDH_OUTTYPE_NTSTATUS,
    TDH_OUTTYPE_NULL, TDH_OUTTYPE_PID, TDH_OUTTYPE_PORT, TDH_OUTTYPE_REDUCEDSTRING,
    TDH_OUTTYPE_SHORT, TDH_OUTTYPE_SOCKETADDRESS, TDH_OUTTYPE_STRING, TDH_OUTTYPE_TID,
    TDH_OUTTYPE_UNSIGNEDBYTE, TDH_OUTTYPE_UNSIGNEDINT, TDH_OUTTYPE_UNSIGNEDLONG,
    TDH_OUTTYPE_UNSIGNEDSHORT, TDH_OUTTYPE_UTF8, TDH_OUTTYPE_WIN32ERROR, TDH_OUTTYPE_XML,
    _TDH_OUT_TYPE,
};

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
pub enum OutType {
    Null,
    String,
    DateTime,
    Byte,
    UnsignedByte,
    Short,
    UnsignedShort,
    Int,
    UnsignedInt,
    Long,
    UnsignedLong,
    Float,
    Double,
    Boolean,
    Guid,
    HexBinary,
    HexInt8,
    HexInt16,
    HexInt32,
    HexInt64,
    Pid,
    Tid,
    Port,
    IpV4,
    IpV6,
    SocketAddress,
    CimDateTime,
    EtwTime,
    Xml,
    ErrorCode,
    Win32Error,
    NtStatus,
    CultureInsensitiveDateTime,

    Json,
    Utf8,
    HResult,
    ReducedString,
    NoPrint,
    Unknown(u16),
}

impl From<u16> for OutType {
    fn from(val: u16) -> Self {
        match _TDH_OUT_TYPE(val.into()) {
            TDH_OUTTYPE_NULL => Self::Null,
            TDH_OUTTYPE_STRING => Self::String,
            TDH_OUTTYPE_DATETIME => Self::DateTime,

            TDH_OUTTYPE_UNSIGNEDBYTE => Self::UnsignedByte,
            TDH_OUTTYPE_UNSIGNEDSHORT => Self::UnsignedShort,
            TDH_OUTTYPE_UNSIGNEDINT => Self::UnsignedInt,
            TDH_OUTTYPE_UNSIGNEDLONG => Self::UnsignedLong,

            TDH_OUTTYPE_BYTE => Self::Byte,
            TDH_OUTTYPE_SHORT => Self::Short,
            TDH_OUTTYPE_INT => Self::Int,
            TDH_OUTTYPE_LONG => Self::Long,

            TDH_OUTTYPE_FLOAT => Self::Float,
            TDH_OUTTYPE_DOUBLE => Self::Double,

            TDH_OUTTYPE_BOOLEAN => Self::Boolean,
            TDH_OUTTYPE_GUID => Self::Guid,

            TDH_OUTTYPE_PORT => Self::Port,
            TDH_OUTTYPE_IPV4 => Self::IpV4,
            TDH_OUTTYPE_IPV6 => Self::IpV6,

            TDH_OUTTYPE_HEXBINARY => Self::HexBinary,
            TDH_OUTTYPE_HEXINT8 => Self::HexInt8,
            TDH_OUTTYPE_HEXINT16 => Self::HexInt16,
            TDH_OUTTYPE_HEXINT32 => Self::HexInt32,
            TDH_OUTTYPE_HEXINT64 => Self::HexInt64,

            TDH_OUTTYPE_PID => Self::Pid,
            TDH_OUTTYPE_TID => Self::Tid,

            TDH_OUTTYPE_SOCKETADDRESS => Self::SocketAddress,
            TDH_OUTTYPE_CIMDATETIME => Self::CimDateTime,
            TDH_OUTTYPE_ETWTIME => Self::EtwTime,
            TDH_OUTTYPE_XML => Self::Xml,

            TDH_OUTTYPE_ERRORCODE => Self::ErrorCode,
            TDH_OUTTYPE_WIN32ERROR => Self::Win32Error,
            TDH_OUTTYPE_NTSTATUS => Self::NtStatus,
            TDH_OUTTYPE_HRESULT => Self::HResult,

            TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME => Self::CultureInsensitiveDateTime,
            TDH_OUTTYPE_JSON => Self::Json,

            TDH_OUTTYPE_REDUCEDSTRING => Self::ReducedString,
            TDH_OUTTYPE_NOPRINT => Self::NoPrint,
            _ => Self::Unknown(val),
        }
    }
}

impl From<OutType> for _TDH_OUT_TYPE {
    fn from(value: OutType) -> Self {
        match value {
            OutType::Null => TDH_OUTTYPE_NULL,
            OutType::String => TDH_OUTTYPE_STRING,
            OutType::DateTime => TDH_OUTTYPE_DATETIME,
            OutType::UnsignedByte => TDH_OUTTYPE_UNSIGNEDBYTE,
            OutType::UnsignedShort => TDH_OUTTYPE_UNSIGNEDSHORT,
            OutType::UnsignedInt => TDH_OUTTYPE_UNSIGNEDINT,
            OutType::UnsignedLong => TDH_OUTTYPE_UNSIGNEDLONG,
            OutType::Byte => TDH_OUTTYPE_BYTE,
            OutType::Short => TDH_OUTTYPE_SHORT,
            OutType::Int => TDH_OUTTYPE_INT,
            OutType::Long => TDH_OUTTYPE_LONG,
            OutType::Float => TDH_OUTTYPE_FLOAT,
            OutType::Double => TDH_OUTTYPE_DOUBLE,
            OutType::Boolean => TDH_OUTTYPE_BOOLEAN,
            OutType::Guid => TDH_OUTTYPE_GUID,
            OutType::Port => TDH_OUTTYPE_PORT,
            OutType::IpV4 => TDH_OUTTYPE_IPV4,
            OutType::IpV6 => TDH_OUTTYPE_IPV6,
            OutType::HexBinary => TDH_OUTTYPE_HEXBINARY,
            OutType::HexInt8 => TDH_OUTTYPE_HEXINT8,
            OutType::HexInt16 => TDH_OUTTYPE_HEXINT16,
            OutType::HexInt32 => TDH_OUTTYPE_HEXINT32,
            OutType::HexInt64 => TDH_OUTTYPE_HEXINT64,
            OutType::Pid => TDH_OUTTYPE_PID,
            OutType::Tid => TDH_OUTTYPE_TID,
            OutType::SocketAddress => TDH_OUTTYPE_SOCKETADDRESS,
            OutType::CimDateTime => TDH_OUTTYPE_CIMDATETIME,
            OutType::EtwTime => TDH_OUTTYPE_ETWTIME,
            OutType::Xml => TDH_OUTTYPE_XML,
            OutType::ErrorCode => TDH_OUTTYPE_ERRORCODE,
            OutType::Win32Error => TDH_OUTTYPE_WIN32ERROR,
            OutType::NtStatus => TDH_OUTTYPE_NTSTATUS,
            OutType::HResult => TDH_OUTTYPE_HRESULT,
            OutType::CultureInsensitiveDateTime => TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME,
            OutType::Json => TDH_OUTTYPE_JSON,
            OutType::Utf8 => TDH_OUTTYPE_UTF8,
            OutType::ReducedString => TDH_OUTTYPE_REDUCEDSTRING,
            OutType::NoPrint => TDH_OUTTYPE_NOPRINT,
            OutType::Unknown(out_type) => _TDH_OUT_TYPE(out_type.into()),
        }
    }
}
