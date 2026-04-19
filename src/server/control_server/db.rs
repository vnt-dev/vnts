use anyhow::Context;
use futures::TryStreamExt;
use ipnet::Ipv4Net;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, SqlitePool, sqlite::SqlitePoolOptions};
use std::net::Ipv4Addr;
use std::path::Path;

static DB_POOL: OnceCell<SqlitePool> = OnceCell::new();
const DB_FILE: &str = "network_control.db";

pub fn db_pool_initialized() -> bool {
    DB_POOL.get().is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkSource {
    Config = 0,
    Manual = 1,
    DeviceRegister = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerServerSource {
    Config = 0,
    Manual = 1,
}

impl PeerServerSource {
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => PeerServerSource::Config,
            1 => PeerServerSource::Manual,
            _ => PeerServerSource::Config,
        }
    }

    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerServerSource::Config => "config",
            PeerServerSource::Manual => "manual",
        }
    }
}

impl NetworkSource {
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => NetworkSource::Config,
            1 => NetworkSource::Manual,
            2 => NetworkSource::DeviceRegister,
            _ => NetworkSource::Config,
        }
    }

    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkSource::Config => "config",
            NetworkSource::Manual => "manual",
            NetworkSource::DeviceRegister => "device_register",
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct NetworkRecord {
    pub network_code: String,
    pub gateway: String,
    pub netmask: u8,
    pub secret: String,
    pub lease_duration: i64,
    pub source: NetworkSource,
    pub created_at: i64,
}

impl NetworkRecord {
    pub fn to_ipv4_net(&self) -> Option<Ipv4Net> {
        let gateway: Ipv4Addr = self.gateway.parse().ok()?;
        let network_ip = Ipv4Addr::from(u32::from(gateway).checked_sub(1)?);
        Ipv4Net::new(network_ip, self.netmask).ok()
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct DeviceRecord {
    pub device_id: String,
    pub network_code: String,
    pub ip: Option<String>,
    pub device_name: String,
    pub device_version: String,
    pub last_connect_time: i64,
    pub tx_bytes: i64,
    pub rx_bytes: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct PeerServerRecord {
    pub server_addr: String,
    pub source: PeerServerSource,
    pub created_at: i64,
}

pub async fn init_db_pool() -> anyhow::Result<()> {
    if !Path::new(DB_FILE).exists() {
        log::info!("Create database");
        std::fs::File::create(DB_FILE)?;
    }
    let database_url = format!("sqlite://{}", DB_FILE);
    log::info!("Initializing database pool {database_url}");
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to SQLite database")?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS networks (
            network_code TEXT PRIMARY KEY,
            gateway TEXT NOT NULL,
            netmask INTEGER NOT NULL,
            secret TEXT NOT NULL DEFAULT '',
            lease_duration INTEGER NOT NULL,
            source INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .context("Failed to create networks table")?;

    // migration: 旧表可能缺少 source 字段
    let _ = sqlx::query("ALTER TABLE networks ADD COLUMN source INTEGER NOT NULL DEFAULT 0")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE networks ADD COLUMN secret TEXT NOT NULL DEFAULT ''")
        .execute(&pool)
        .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            network_code TEXT NOT NULL,
            ip TEXT,
            device_name TEXT NOT NULL,
            device_version TEXT NOT NULL,
            last_connect_time INTEGER NOT NULL,
            tx_bytes INTEGER NOT NULL DEFAULT 0,
            rx_bytes INTEGER NOT NULL DEFAULT 0,
            UNIQUE(device_id, network_code)
        )",
    )
    .execute(&pool)
    .await
    .context("Failed to create devices table")?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS peer_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_addr TEXT NOT NULL UNIQUE,
            source INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .context("Failed to create peer_servers table")?;

    DB_POOL.set(pool).unwrap_or_else(|_| ());
    Ok(())
}

pub async fn save_network(record: &NetworkRecord) -> anyhow::Result<()> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(());
    };

    sqlx::query(
        r#"INSERT OR REPLACE INTO networks (network_code, gateway, netmask, secret, lease_duration, source, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(&record.network_code)
    .bind(&record.gateway)
    .bind(record.netmask as i32)
    .bind(&record.secret)
    .bind(record.lease_duration)
    .bind(record.source as i32)
    .bind(record.created_at)
    .execute(pool)
    .await
    .context("Failed to save network")?;

    Ok(())
}

pub async fn save_network_if_not_exists(record: &NetworkRecord) -> anyhow::Result<bool> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(false);
    };

    let result = sqlx::query(
        r#"INSERT OR IGNORE INTO networks (network_code, gateway, netmask, secret, lease_duration, source, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(&record.network_code)
    .bind(&record.gateway)
    .bind(record.netmask as i32)
    .bind(&record.secret)
    .bind(record.lease_duration)
    .bind(record.source as i32)
    .bind(record.created_at)
    .execute(pool)
    .await
    .context("Failed to save network")?;

    Ok(result.rows_affected() > 0)
}

pub async fn update_network(
    network_code: &str,
    gateway: &str,
    netmask: u8,
    secret: &str,
    lease_duration: i64,
) -> anyhow::Result<bool> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(false);
    };

    let result = sqlx::query(
        r#"UPDATE networks SET gateway = ?, netmask = ?, secret = ?, lease_duration = ? WHERE network_code = ?"#,
    )
    .bind(gateway)
    .bind(netmask as i32)
    .bind(secret)
    .bind(lease_duration)
    .bind(network_code)
    .execute(pool)
    .await
    .context("Failed to update network")?;

    Ok(result.rows_affected() > 0)
}

pub async fn delete_network(network_code: &str) -> anyhow::Result<bool> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(false);
    };

    let result = sqlx::query(r#"DELETE FROM networks WHERE network_code = ?"#)
        .bind(network_code)
        .execute(pool)
        .await
        .context("Failed to delete network")?;

    Ok(result.rows_affected() > 0)
}

#[allow(dead_code)]
pub async fn get_network(network_code: &str) -> anyhow::Result<Option<NetworkRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(None);
    };

    let row_option = sqlx::query(
        r#"SELECT network_code, gateway, netmask, secret, lease_duration, source, created_at FROM networks WHERE network_code = ?"#,
    )
    .bind(network_code)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch network")?;

    match row_option {
        Some(row) => {
            let netmask: i32 = row.get("netmask");
            let source: i32 = row.get("source");
            Ok(Some(NetworkRecord {
                network_code: row.get("network_code"),
                gateway: row.get("gateway"),
                netmask: netmask as u8,
                secret: row.get("secret"),
                lease_duration: row.get("lease_duration"),
                source: NetworkSource::from_i32(source),
                created_at: row.get("created_at"),
            }))
        }
        None => Ok(None),
    }
}

pub async fn load_all_networks() -> anyhow::Result<Vec<NetworkRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(Vec::new());
    };

    let records: Vec<NetworkRecord> = sqlx::query(
        r#"SELECT network_code, gateway, netmask, secret, lease_duration, source, created_at FROM networks ORDER BY created_at"#,
    )
    .fetch(pool)
    .try_filter_map(|row| async move {
        let netmask: i32 = row.try_get("netmask")?;
        let source: i32 = row.try_get("source")?;
        Ok(Some(NetworkRecord {
            network_code: row.try_get("network_code")?,
            gateway: row.try_get("gateway")?,
            netmask: netmask as u8,
            secret: row.try_get("secret")?,
            lease_duration: row.try_get("lease_duration")?,
            source: NetworkSource::from_i32(source),
            created_at: row.try_get("created_at")?,
        }))
    })
    .try_collect()
    .await
    .context("Failed to load all networks")?;

    Ok(records)
}

pub async fn network_has_devices(network_code: &str) -> anyhow::Result<bool> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(false);
    };

    let row = sqlx::query(r#"SELECT COUNT(*) as cnt FROM devices WHERE network_code = ?"#)
        .bind(network_code)
        .fetch_one(pool)
        .await
        .context("Failed to check network devices")?;

    let count: i32 = row.get("cnt");
    Ok(count > 0)
}

pub async fn save_or_update_device(device: &DeviceRecord) -> anyhow::Result<()> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(());
    };

    sqlx::query(
        r#"INSERT INTO devices (device_id, network_code, ip, device_name, device_version, last_connect_time, tx_bytes, rx_bytes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(device_id, network_code) DO UPDATE SET
               ip = excluded.ip,
               device_name = excluded.device_name,
               device_version = excluded.device_version,
               last_connect_time = excluded.last_connect_time,
               tx_bytes = excluded.tx_bytes,
               rx_bytes = excluded.rx_bytes"#,
    )
    .bind(&device.device_id)
    .bind(&device.network_code)
    .bind(&device.ip)
    .bind(&device.device_name)
    .bind(&device.device_version)
    .bind(device.last_connect_time)
    .bind(device.tx_bytes)
    .bind(device.rx_bytes)
    .execute(pool)
    .await
    .context("Failed to save or update device")?;

    Ok(())
}

/// 回收 IP：清空字段但保留记录
pub async fn release_device_ip(network_code: &str, device_id: &str) -> anyhow::Result<()> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(());
    };

    sqlx::query(r#"UPDATE devices SET ip = NULL WHERE network_code = ? AND device_id = ?"#)
        .bind(network_code)
        .bind(device_id)
        .execute(pool)
        .await
        .context("Failed to release device IP")?;

    Ok(())
}

#[allow(dead_code)]
pub async fn get_device(
    network_code: &str,
    device_id: &str,
) -> anyhow::Result<Option<DeviceRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(None);
    };

    let row_option = sqlx::query(
        r#"SELECT device_id, network_code, ip, device_name, device_version, last_connect_time,
           COALESCE(tx_bytes, 0) as tx_bytes, COALESCE(rx_bytes, 0) as rx_bytes
           FROM devices WHERE network_code = ? AND device_id = ?"#,
    )
    .bind(network_code)
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch device")?;

    match row_option {
        Some(row) => Ok(Some(DeviceRecord {
            device_id: row.get("device_id"),
            network_code: row.get("network_code"),
            ip: row.get("ip"),
            device_name: row.get("device_name"),
            device_version: row.get("device_version"),
            last_connect_time: row.get("last_connect_time"),
            tx_bytes: row.get("tx_bytes"),
            rx_bytes: row.get("rx_bytes"),
        })),
        None => Ok(None),
    }
}

pub async fn load_all_devices(network_code: &str) -> anyhow::Result<Vec<DeviceRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(Vec::new());
    };

    let records: Vec<DeviceRecord> = sqlx::query(
        r#"SELECT device_id, network_code, ip, device_name, device_version, last_connect_time,
           COALESCE(tx_bytes, 0) as tx_bytes, COALESCE(rx_bytes, 0) as rx_bytes
           FROM devices WHERE network_code = ?"#,
    )
    .bind(network_code)
    .fetch(pool)
    .try_filter_map(|row| async move {
        Ok(Some(DeviceRecord {
            device_id: row.try_get("device_id")?,
            network_code: row.try_get("network_code")?,
            ip: row.try_get("ip")?,
            device_name: row.try_get("device_name")?,
            device_version: row.try_get("device_version")?,
            last_connect_time: row.try_get("last_connect_time")?,
            tx_bytes: row.try_get("tx_bytes")?,
            rx_bytes: row.try_get("rx_bytes")?,
        }))
    })
    .try_collect()
    .await
    .context("Failed to load all devices")?;

    Ok(records)
}

pub async fn delete_device(network_code: &str, device_id: &str) -> anyhow::Result<bool> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(false);
    };

    let result = sqlx::query(r#"DELETE FROM devices WHERE network_code = ? AND device_id = ?"#)
        .bind(network_code)
        .bind(device_id)
        .execute(pool)
        .await
        .context("Failed to delete device")?;

    Ok(result.rows_affected() > 0)
}

#[allow(dead_code)]
pub async fn delete_devices_by_network(network_code: &str) -> anyhow::Result<u64> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(0);
    };

    let result = sqlx::query(r#"DELETE FROM devices WHERE network_code = ?"#)
        .bind(network_code)
        .execute(pool)
        .await
        .context("Failed to delete devices by network")?;

    Ok(result.rows_affected())
}

pub async fn save_peer_server_if_not_exists(record: &PeerServerRecord) -> anyhow::Result<bool> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(false);
    };

    let result = sqlx::query(
        r#"INSERT OR IGNORE INTO peer_servers (server_addr, source, created_at)
           VALUES (?, ?, ?)"#,
    )
    .bind(&record.server_addr)
    .bind(record.source as i32)
    .bind(record.created_at)
    .execute(pool)
    .await
    .context("Failed to save peer server")?;

    Ok(result.rows_affected() > 0)
}

pub async fn save_peer_server(record: &PeerServerRecord) -> anyhow::Result<()> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(());
    };

    sqlx::query(
        r#"INSERT OR REPLACE INTO peer_servers (server_addr, source, created_at)
           VALUES (?, ?, ?)"#,
    )
    .bind(&record.server_addr)
    .bind(record.source as i32)
    .bind(record.created_at)
    .execute(pool)
    .await
    .context("Failed to save peer server")?;

    Ok(())
}

pub async fn load_all_peer_servers() -> anyhow::Result<Vec<PeerServerRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(Vec::new());
    };

    let records: Vec<PeerServerRecord> = sqlx::query(
        r#"SELECT server_addr, source, created_at FROM peer_servers ORDER BY created_at"#,
    )
    .fetch(pool)
    .try_filter_map(|row| async move {
        let source: i32 = row.try_get("source")?;
        Ok(Some(PeerServerRecord {
            server_addr: row.try_get("server_addr")?,
            source: PeerServerSource::from_i32(source),
            created_at: row.try_get("created_at")?,
        }))
    })
    .try_collect()
    .await
    .context("Failed to load all peer servers")?;

    Ok(records)
}

pub async fn delete_peer_server(server_addr: &str) -> anyhow::Result<bool> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(false);
    };

    let result = sqlx::query(r#"DELETE FROM peer_servers WHERE server_addr = ?"#)
        .bind(server_addr)
        .execute(pool)
        .await
        .context("Failed to delete peer server")?;

    Ok(result.rows_affected() > 0)
}
