use windows::{
    core::GUID,
    Win32::System::Diagnostics::Etw::{
        TRACE_LEVEL_CRITICAL, TRACE_LEVEL_ERROR, TRACE_LEVEL_INFORMATION, TRACE_LEVEL_NONE,
        TRACE_LEVEL_VERBOSE, TRACE_LEVEL_WARNING,
    },
};

#[rustfmt::skip]
mod constants {
    use windows::core::GUID;
    
    pub const ALPC_GUID:               GUID = GUID::from_u128(0x45d8cccd539f4b72a8b75c683142609a);
    pub const DISK_IO_GUID:            GUID = GUID::from_u128(0x3d6fa8d4fe0511d09dda00c04fd7ba7c);
    pub const EVENT_TRACE_CONFIG_GUID: GUID = GUID::from_u128(0x1853a65418f4f36aefcdc0f1d2fd235);
    pub const FILE_IO_GUID:            GUID = GUID::from_u128(0x90cbdc394a3e11d184f40000f80464e3);
    pub const IMAGE_LOAD_GUID:         GUID = GUID::from_u128(0x2cb15d1d5fc111d2abe100a0c911f518);
    pub const PAGE_FAULT_GUID:         GUID = GUID::from_u128(0x3d6fa8d3fe0511d09dda00c04fd7ba7c);
    pub const PERF_INFO_GUID:          GUID = GUID::from_u128(0xce1dbfb4137e4da687b03f59aa102cbc);
    pub const PROCESS_GUID:            GUID = GUID::from_u128(0x3d6fa8d0fe0511d09dda00c04fd7ba7c);
    pub const REGISTRY_GUID:           GUID = GUID::from_u128(0xae53722ec86311d2865900c04fa321a1);
    pub const SPLIT_IO_GUID:           GUID = GUID::from_u128(0xd837ca9212b944a5ad6a3a65b3578aa8);
    pub const TCP_IP_GUID:             GUID = GUID::from_u128(0x9a280ac0c8e011d184e200c04fb998a2);
    pub const THREAD_GUID:             GUID = GUID::from_u128(0x3d6fa8d1fe0511d09dda00c04fd7ba7c);
}

pub use constants::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TraceLevel(u8);

impl TraceLevel {
    pub const NONE: TraceLevel = TraceLevel(TRACE_LEVEL_NONE as u8);
    pub const CRITICAL: TraceLevel = TraceLevel(TRACE_LEVEL_CRITICAL as u8);
    pub const ERROR: TraceLevel = TraceLevel(TRACE_LEVEL_ERROR as u8);
    pub const WARNING: TraceLevel = TraceLevel(TRACE_LEVEL_WARNING as u8);
    pub const INFORMATION: TraceLevel = TraceLevel(TRACE_LEVEL_INFORMATION as u8);
    pub const VERBOSE: TraceLevel = TraceLevel(TRACE_LEVEL_VERBOSE as u8);
}

impl From<TraceLevel> for u8 {
    fn from(level: TraceLevel) -> u8 {
        level.0
    }
}

impl From<u8> for TraceLevel {
    fn from(level: u8) -> TraceLevel {
        TraceLevel(level)
    }
}

pub struct ProviderBuilder {
    id: GUID,
    any: u64,
    all: u64,
    level: TraceLevel,
}

impl ProviderBuilder {
    pub fn from_guid(id: &GUID) -> Self {
        Self {
            id: *id,
            any: 0,
            all: 0,
            level: TraceLevel::VERBOSE,
        }
    }

    pub fn any(mut self, any: u64) -> Self {
        self.any = any;
        self
    }

    pub fn all(mut self, all: u64) -> Self {
        self.all = all;
        self
    }

    pub fn level(mut self, level: TraceLevel) -> Self {
        self.level = level;
        self
    }

    pub fn build(&self) -> Provider {
        Provider {
            id: self.id,
            any: self.any,
            all: self.all,
            level: self.level,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Provider {
    id: GUID,
    any: u64,
    all: u64,
    level: TraceLevel,
}

impl Provider {
    pub fn id(&self) -> &GUID {
        &self.id
    }

    pub fn level(&self) -> TraceLevel {
        self.level
    }

    pub fn any(&self) -> u64 {
        self.any
    }

    pub fn all(&self) -> u64 {
        self.all
    }
}
