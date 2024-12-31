pub mod guid {
    use serde::{Deserialize, Deserializer, Serializer};
    use windows::core::GUID;

    pub fn serialize<S>(guid: &GUID, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let guid_string = format!("{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0], guid.data4[1],
            guid.data4[2], guid.data4[3], guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]
        );
        serializer.serialize_str(&guid_string)
    }


    /// Deserialize a GUID from a string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<GUID, D::Error>
    where
        D: Deserializer<'de>,
    {
        let guid_str = String::deserialize(deserializer)?;
        parse_guid(&guid_str).map_err(serde::de::Error::custom)
    }
    
    /// Helper function to parse a GUID string into a `GUID`.
    fn parse_guid(guid_str: &str) -> Result<GUID, String> {
        // Check if the GUID string is the correct length
        if guid_str.len() != 36 {
            return Err("Invalid GUID string length".to_string());
        }

        // Split the GUID string into parts
        let parts: Vec<&str> = guid_str.split('-').collect();
        if parts.len() != 5 {
            return Err("Invalid GUID format".to_string());
        }

        // Parse each part
        let data1 = u32::from_str_radix(parts[0], 16).map_err(|_| "Failed to parse Data1")?;
        let data2 = u16::from_str_radix(parts[1], 16).map_err(|_| "Failed to parse Data2")?;
        let data3 = u16::from_str_radix(parts[2], 16).map_err(|_| "Failed to parse Data3")?;

        let data4_part1 = u8::from_str_radix(&parts[3][0..2], 16).map_err(|_| "Failed to parse Data4 part 1")?;
        let data4_part2 = u8::from_str_radix(&parts[3][2..4], 16).map_err(|_| "Failed to parse Data4 part 2")?;

        let data4_remaining: Result<Vec<u8>, _> = parts[4]
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16))
            .collect();

        let mut data4 = [0u8; 8];
        data4[0] = data4_part1;
        data4[1] = data4_part2;
        data4[2..].copy_from_slice(&data4_remaining.map_err(|_| "Failed to parse Data4 remaining bytes")?);

        Ok(GUID {
            data1,
            data2,
            data3,
            data4,
        })
    }
}