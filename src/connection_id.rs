//! Lossless decimal connection identifiers; zero is reserved for an unset wire value.
use std::{fmt, str::FromStr};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionId(u32);
impl ConnectionId {
    pub fn from_encoded(value: u32) -> anyhow::Result<Self> {
        for length in 1..=9 {
            let base = 10u32.pow(length);
            if (base..base * 2).contains(&value) {
                return Ok(Self(value));
            }
        }
        anyhow::bail!("无效的连接 ID 编码")
    }
    pub fn encoded(self) -> u32 {
        self.0
    }
    // Adapter for existing four-byte transport keys, never an IP network address.
    pub fn transport_key(self) -> std::net::Ipv4Addr {
        self.0.into()
    }
}
impl FromStr for ConnectionId {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        anyhow::ensure!(
            (1..=9).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit()),
            "连接 ID 必须为 1～9 位纯数字"
        );
        Ok(Self(10u32.pow(value.len() as u32) + value.parse::<u32>()?))
    }
}
impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let length = self.0.ilog10() as usize;
        write!(
            f,
            "{:0width$}",
            self.0 - 10u32.pow(length as u32),
            width = length
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decimal_identifiers_round_trip_without_losing_zeroes() {
        for (text, encoded) in [
            ("0", 10),
            ("00", 100),
            ("001", 1001),
            ("0001", 10001),
            ("123456789", 1123456789),
            ("999999999", 1999999999),
        ] {
            let id: ConnectionId = text.parse().unwrap();
            assert_eq!(id.encoded(), encoded);
            assert_eq!(
                ConnectionId::from_encoded(encoded).unwrap().to_string(),
                text
            );
        }
        for n in 1..=9 {
            for text in ["0".repeat(n), "9".repeat(n)] {
                let id: ConnectionId = text.parse().unwrap();
                assert_eq!(
                    ConnectionId::from_encoded(id.encoded())
                        .unwrap()
                        .to_string(),
                    text
                );
            }
        }
        for text in ["", "0000000000", "-1", "+1", " 1", "1.2", "１２３", "1a"] {
            assert!(text.parse::<ConnectionId>().is_err());
        }
        for value in [0, 1, 9, 20, 99, 200, 999, 2000000000, u32::MAX] {
            assert!(ConnectionId::from_encoded(value).is_err());
        }
    }
}
