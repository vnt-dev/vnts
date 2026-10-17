use anyhow::Context;
use futures::TryStreamExt;
use ipnet::Ipv4Net;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::{
    FromRow, Row, SqlitePool,
    sqlite::{SqlitePoolOptions, SqliteRow},
};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;

static DB_POOL: OnceCell<SqlitePool> = OnceCell::new();
const DB_FILE: &str = "network_control.db";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkSource {
    Config = 0,
    Manual = 1,
    DeviceRegister = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkType {
    Public = 0,
    Private = 1,
}

impl NetworkType {
    pub fn from_i32(value: i32) -> Self {
        match value {
            1 => Self::Private,
            _ => Self::Public,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceIpType {
    Dynamic = 0,
    Static = 1,
    Fixed = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClientType {
    #[default]
    Vnt = 0,
    Ikev2 = 1,
    Wireguard = 2,
}

impl ClientType {
    pub fn from_i32(value: i32) -> Self {
        match value {
            1 => Self::Ikev2,
            2 => Self::Wireguard,
            _ => Self::Vnt,
        }
    }
}

impl DeviceIpType {
    pub fn from_i32(value: i32) -> Self {
        match value {
            1 => Self::Static,
            2 => Self::Fixed,
            _ => Self::Dynamic,
        }
    }
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
    pub lease_duration: i64,
    pub source: NetworkSource,
    pub network_type: NetworkType,
    pub created_at: i64,
}

impl NetworkRecord {
    pub fn to_ipv4_net(&self) -> Option<Ipv4Net> {
        let gateway: Ipv4Addr = self.gateway.parse().ok()?;
        Ipv4Net::new(gateway, self.netmask)
            .ok()
            .map(|net| net.trunc())
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct DeviceRecord {
    pub device_id: String,
    pub network_code: String,
    pub ip: Option<String>,
    pub ip_type: DeviceIpType,
    pub client_type: ClientType,
    pub ikev2_password: Option<String>,
    pub ikev2_output_subnets: Vec<Ipv4Net>,
    pub ikev2_input_routes: Vec<Ikev2InputRoute>,
    pub wireguard_output_subnets: Vec<Ipv4Net>,
    pub wireguard_input_routes: Vec<Ikev2InputRoute>,
    pub wireguard_dns: Vec<Ipv4Addr>,
    pub wireguard_private_key: Option<String>,
    pub wireguard_public_key: Option<String>,
    pub device_name: String,
    pub device_version: String,
    pub last_connect_time: i64,
    pub tx_bytes: i64,
    pub rx_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedConfigRecord {
    pub network_code: String,
    pub device_id: String,
    pub revision: i64,
    pub config_toml: String,
    /// Per-device control endpoint embedded in its subscription. Empty values
    /// from records created before this column fall back to the global endpoint.
    pub subscription_server: String,
    /// NULL inherits the global traffic server list; Some(empty) explicitly
    /// falls back to the subscription server.
    pub traffic_servers_override: Option<Vec<String>>,
    #[serde(skip_serializing)]
    pub credential_key: Option<String>,
    #[serde(skip_serializing)]
    pub subscription: Option<String>,
    /// 服务端签发的设备唯一订阅接入 ID（UUID）。订阅链接只携带它，
    /// 客户端经它认证后再从信封获得 network_code/device_id。
    pub join_id: String,
    pub updated_at: i64,
    /// Authoritative device-table values used to rebuild protected TOML fields.
    #[serde(skip)]
    pub configured_device_name: String,
    #[serde(skip)]
    pub configured_ip: Option<Ipv4Addr>,
    #[serde(skip)]
    pub fixed_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ikev2InputRoute {
    pub subnet: Ipv4Net,
    pub target_ip: Ipv4Addr,
}

fn decode_json_column<T: DeserializeOwned>(
    row: &SqliteRow,
    column: &str,
) -> Result<T, sqlx::Error> {
    let value: String = row.try_get(column)?;
    serde_json::from_str(&value).map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

/// SQLite has no `ADD COLUMN IF NOT EXISTS`.  Treat only the expected
/// duplicate-column result as success so an old managed-config table is
/// upgraded before any query starts selecting the new state columns.
async fn add_column_if_missing(
    pool: &SqlitePool,
    statement: &str,
    column: &str,
) -> anyhow::Result<()> {
    if let Err(error) = sqlx::query(statement).execute(pool).await
        && !error
            .to_string()
            .to_ascii_lowercase()
            .contains("duplicate column name")
    {
        return Err(error)
            .with_context(|| format!("Failed to migrate vnt_device_configs column '{column}'"));
    }
    Ok(())
}

async fn migrate_managed_config_schema(pool: &SqlitePool) -> anyhow::Result<()> {
    // `CREATE TABLE IF NOT EXISTS` does not upgrade installations created by
    // earlier managed-configuration releases.  These columns are all read by
    // `get_managed_config`, so migrate them before exposing the HTTP editor.
    // Sync-state columns (applied_revision, apply_status, apply_error,
    // overridden_fields) deliberately stay behind on old databases: that state
    // now lives in the live subscription session, and unused leftover columns
    // are harmless.
    add_column_if_missing(
        pool,
        "ALTER TABLE vnt_device_configs ADD COLUMN credential_key TEXT",
        "credential_key",
    )
    .await?;
    add_column_if_missing(
        pool,
        "ALTER TABLE vnt_device_configs ADD COLUMN traffic_servers_override TEXT",
        "traffic_servers_override",
    )
    .await?;
    add_column_if_missing(
        pool,
        "ALTER TABLE vnt_device_configs ADD COLUMN subscription_server TEXT NOT NULL DEFAULT ''",
        "subscription_server",
    )
    .await?;
    add_column_if_missing(
        pool,
        "ALTER TABLE vnt_device_configs ADD COLUMN subscription TEXT",
        "subscription",
    )
    .await?;
    add_column_if_missing(
        pool,
        "ALTER TABLE vnt_device_configs ADD COLUMN join_id TEXT NOT NULL DEFAULT ''",
        "join_id",
    )
    .await?;
    add_column_if_missing(
        pool,
        "ALTER TABLE vnt_device_configs ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0",
        "updated_at",
    )
    .await
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
            lease_duration INTEGER NOT NULL,
            source INTEGER NOT NULL DEFAULT 0,
            network_type INTEGER NOT NULL DEFAULT 0,
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
    let _ = sqlx::query("ALTER TABLE networks ADD COLUMN network_type INTEGER NOT NULL DEFAULT 0")
        .execute(&pool)
        .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            network_code TEXT NOT NULL,
            ip TEXT,
            ip_type INTEGER NOT NULL DEFAULT 0,
            client_type INTEGER NOT NULL DEFAULT 0,
            ikev2_password TEXT,
            ikev2_output_subnets TEXT NOT NULL DEFAULT '[]',
            ikev2_input_routes TEXT NOT NULL DEFAULT '[]',
            wireguard_output_subnets TEXT NOT NULL DEFAULT '[]',
            wireguard_input_routes TEXT NOT NULL DEFAULT '[]',
            wireguard_dns TEXT NOT NULL DEFAULT '[]',
            wireguard_private_key TEXT,
            wireguard_public_key TEXT,
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

    let _ = sqlx::query("ALTER TABLE devices ADD COLUMN ip_type INTEGER NOT NULL DEFAULT 0")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE devices ADD COLUMN client_type INTEGER NOT NULL DEFAULT 0")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE devices ADD COLUMN ikev2_password TEXT")
        .execute(&pool)
        .await;
    let _ = sqlx::query(
        "ALTER TABLE devices ADD COLUMN ikev2_output_subnets TEXT NOT NULL DEFAULT '[]'",
    )
    .execute(&pool)
    .await;
    let _ =
        sqlx::query("ALTER TABLE devices ADD COLUMN ikev2_input_routes TEXT NOT NULL DEFAULT '[]'")
            .execute(&pool)
            .await;
    let _ = sqlx::query("ALTER TABLE devices ADD COLUMN wireguard_private_key TEXT")
        .execute(&pool)
        .await;
    let _ = sqlx::query(
        "ALTER TABLE devices ADD COLUMN wireguard_output_subnets TEXT NOT NULL DEFAULT '[]'",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query(
        "ALTER TABLE devices ADD COLUMN wireguard_input_routes TEXT NOT NULL DEFAULT '[]'",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query("ALTER TABLE devices ADD COLUMN wireguard_dns TEXT NOT NULL DEFAULT '[]'")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE devices ADD COLUMN wireguard_public_key TEXT")
        .execute(&pool)
        .await;

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_network_ip_unique
         ON devices(network_code, ip) WHERE ip IS NOT NULL",
    )
    .execute(&pool)
    .await
    .context("Failed to enforce unique device IPs; check existing duplicate IP records")?;

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_network_device_unique
         ON devices(network_code, device_id)",
    )
    .execute(&pool)
    .await
    .context("Failed to enforce unique network/device identities")?;

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ikev2_username_unique
         ON devices(device_id) WHERE client_type = 1",
    )
    .execute(&pool)
    .await
    .context("Failed to enforce globally unique IKEv2 usernames")?;

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_wireguard_public_key_unique
         ON devices(wireguard_public_key) WHERE client_type = 2 AND wireguard_public_key IS NOT NULL",
    )
    .execute(&pool)
    .await
    .context("Failed to enforce unique WireGuard public keys")?;

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

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS vnt_device_configs (
            network_code TEXT NOT NULL,
            device_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            config_toml TEXT NOT NULL,
            subscription_server TEXT NOT NULL DEFAULT '',
            traffic_servers_override TEXT,
            credential_key TEXT,
            subscription TEXT,
            join_id TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(network_code, device_id),
            FOREIGN KEY(network_code, device_id)
                REFERENCES devices(network_code, device_id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .context("Failed to create vnt_device_configs table")?;

    // The join_id unique index below references a column that databases
    // created by earlier releases don't have yet, so upgrade the table
    // before enforcing uniqueness.
    migrate_managed_config_schema(&pool).await?;

    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vnt_device_configs_join_id_unique
         ON vnt_device_configs(join_id) WHERE join_id != ''",
    )
    .execute(&pool)
    .await
    .context("Failed to enforce unique subscription join ids")?;

    let _ = DB_POOL.set(pool);
    Ok(())
}

pub async fn save_network(record: &NetworkRecord) -> anyhow::Result<()> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(());
    };

    sqlx::query(
        r#"INSERT OR REPLACE INTO networks (network_code, gateway, netmask, lease_duration, source, network_type, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(&record.network_code)
    .bind(&record.gateway)
    .bind(record.netmask as i32)
    .bind(record.lease_duration)
    .bind(record.source as i32)
    .bind(record.network_type as i32)
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
        r#"INSERT OR IGNORE INTO networks (network_code, gateway, netmask, lease_duration, source, network_type, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(&record.network_code)
    .bind(&record.gateway)
    .bind(record.netmask as i32)
    .bind(record.lease_duration)
    .bind(record.source as i32)
    .bind(record.network_type as i32)
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
    lease_duration: i64,
    network_type: NetworkType,
) -> anyhow::Result<bool> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(false);
    };

    let result = sqlx::query(
        r#"UPDATE networks SET gateway = ?, netmask = ?, lease_duration = ?, network_type = ? WHERE network_code = ?"#,
    )
    .bind(gateway)
    .bind(netmask as i32)
    .bind(lease_duration)
    .bind(network_type as i32)
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
        r#"SELECT network_code, gateway, netmask, lease_duration, source, network_type, created_at FROM networks WHERE network_code = ?"#,
    )
    .bind(network_code)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch network")?;

    match row_option {
        Some(row) => {
            let netmask: i32 = row.get("netmask");
            let source: i32 = row.get("source");
            let network_type: i32 = row.get("network_type");
            Ok(Some(NetworkRecord {
                network_code: row.get("network_code"),
                gateway: row.get("gateway"),
                netmask: netmask as u8,
                lease_duration: row.get("lease_duration"),
                source: NetworkSource::from_i32(source),
                network_type: NetworkType::from_i32(network_type),
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
        r#"SELECT network_code, gateway, netmask, lease_duration, source, network_type, created_at FROM networks ORDER BY created_at"#,
    )
    .fetch(pool)
    .try_filter_map(|row| async move {
        let netmask: i32 = row.try_get("netmask")?;
        let source: i32 = row.try_get("source")?;
        let network_type: i32 = row.try_get("network_type")?;
        Ok(Some(NetworkRecord {
            network_code: row.try_get("network_code")?,
            gateway: row.try_get("gateway")?,
            netmask: netmask as u8,
            lease_duration: row.try_get("lease_duration")?,
            source: NetworkSource::from_i32(source),
            network_type: NetworkType::from_i32(network_type),
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

pub async fn load_device_counts() -> anyhow::Result<HashMap<String, u32>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(HashMap::new());
    };

    let rows =
        sqlx::query(r#"SELECT network_code, COUNT(*) AS cnt FROM devices GROUP BY network_code"#)
            .fetch_all(pool)
            .await
            .context("Failed to load device counts")?;

    rows.into_iter()
        .map(|row| {
            let network_code = row.try_get("network_code")?;
            let count = row.try_get::<i64, _>("cnt")?;
            Ok((network_code, u32::try_from(count).unwrap_or(u32::MAX)))
        })
        .collect::<Result<HashMap<_, _>, sqlx::Error>>()
        .context("Failed to decode device counts")
}

pub async fn save_or_update_device(device: &DeviceRecord) -> anyhow::Result<()> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(());
    };

    sqlx::query(
        r#"INSERT INTO devices (device_id, network_code, ip, ip_type, client_type, ikev2_password, ikev2_output_subnets, ikev2_input_routes, wireguard_output_subnets, wireguard_input_routes, wireguard_dns, wireguard_private_key, wireguard_public_key, device_name, device_version, last_connect_time, tx_bytes, rx_bytes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(device_id, network_code) DO UPDATE SET
               ip = excluded.ip,
               ip_type = excluded.ip_type,
               client_type = excluded.client_type,
               ikev2_password = excluded.ikev2_password,
               ikev2_output_subnets = excluded.ikev2_output_subnets,
               ikev2_input_routes = excluded.ikev2_input_routes,
               wireguard_output_subnets = excluded.wireguard_output_subnets,
               wireguard_input_routes = excluded.wireguard_input_routes,
               wireguard_dns = excluded.wireguard_dns,
               wireguard_private_key = excluded.wireguard_private_key,
               wireguard_public_key = excluded.wireguard_public_key,
               device_name = excluded.device_name,
               device_version = excluded.device_version,
               last_connect_time = excluded.last_connect_time,
               tx_bytes = excluded.tx_bytes,
               rx_bytes = excluded.rx_bytes"#,
    )
    .bind(&device.device_id)
    .bind(&device.network_code)
    .bind(&device.ip)
    .bind(device.ip_type as i32)
    .bind(device.client_type as i32)
    .bind(&device.ikev2_password)
    .bind(serde_json::to_string(&device.ikev2_output_subnets)?)
    .bind(serde_json::to_string(&device.ikev2_input_routes)?)
    .bind(serde_json::to_string(&device.wireguard_output_subnets)?)
    .bind(serde_json::to_string(&device.wireguard_input_routes)?)
    .bind(serde_json::to_string(&device.wireguard_dns)?)
    .bind(&device.wireguard_private_key)
    .bind(&device.wireguard_public_key)
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

/// 回收普通动态设备的 IP：清空字段但保留记录。
///
/// 受管 VNT 的目标地址属于 revisioned subscription envelope，客户端在注册前
/// 就必须取得它；因此不能在离线租约清理时抹掉该设备表值。
pub async fn release_device_ip(network_code: &str, device_id: &str) -> anyhow::Result<()> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(());
    };
    release_device_ip_on(pool, network_code, device_id).await
}

/// Pool-parameterized core of [`release_device_ip`] so tests can exercise the
/// query against a local pool without initializing the process-global one.
async fn release_device_ip_on(
    pool: &SqlitePool,
    network_code: &str,
    device_id: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"UPDATE devices
           SET ip = NULL
           WHERE network_code = ? AND device_id = ?
             AND NOT EXISTS (
                 SELECT 1 FROM vnt_device_configs
                 WHERE vnt_device_configs.network_code = devices.network_code
                   AND vnt_device_configs.device_id = devices.device_id
             )"#,
    )
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
        r#"SELECT device_id, network_code, ip, ip_type, client_type, ikev2_password, ikev2_output_subnets, ikev2_input_routes, wireguard_output_subnets, wireguard_input_routes, wireguard_dns, wireguard_private_key, wireguard_public_key, device_name, device_version, last_connect_time,
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
            ip_type: DeviceIpType::from_i32(row.get("ip_type")),
            client_type: ClientType::from_i32(row.get("client_type")),
            ikev2_password: row.get("ikev2_password"),
            ikev2_output_subnets: decode_json_column(&row, "ikev2_output_subnets")?,
            ikev2_input_routes: decode_json_column(&row, "ikev2_input_routes")?,
            wireguard_output_subnets: decode_json_column(&row, "wireguard_output_subnets")?,
            wireguard_input_routes: decode_json_column(&row, "wireguard_input_routes")?,
            wireguard_dns: decode_json_column(&row, "wireguard_dns")?,
            wireguard_private_key: row.get("wireguard_private_key"),
            wireguard_public_key: row.get("wireguard_public_key"),
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
        r#"SELECT device_id, network_code, ip, ip_type, client_type, ikev2_password, ikev2_output_subnets, ikev2_input_routes, wireguard_output_subnets, wireguard_input_routes, wireguard_dns, wireguard_private_key, wireguard_public_key, device_name, device_version, last_connect_time,
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
            ip_type: DeviceIpType::from_i32(row.try_get("ip_type")?),
            client_type: ClientType::from_i32(row.try_get("client_type")?),
            ikev2_password: row.try_get("ikev2_password")?,
            ikev2_output_subnets: decode_json_column(&row, "ikev2_output_subnets")?,
            ikev2_input_routes: decode_json_column(&row, "ikev2_input_routes")?,
            wireguard_output_subnets: decode_json_column(&row, "wireguard_output_subnets")?,
            wireguard_input_routes: decode_json_column(&row, "wireguard_input_routes")?,
            wireguard_dns: decode_json_column(&row, "wireguard_dns")?,
            wireguard_private_key: row.try_get("wireguard_private_key")?,
            wireguard_public_key: row.try_get("wireguard_public_key")?,
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

pub async fn load_all_ikev2_devices() -> anyhow::Result<Vec<DeviceRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(
        r#"SELECT device_id, network_code, ip, ip_type, client_type, ikev2_password, ikev2_output_subnets, ikev2_input_routes, wireguard_output_subnets, wireguard_input_routes, wireguard_dns, wireguard_private_key, wireguard_public_key, device_name, device_version, last_connect_time,
           COALESCE(tx_bytes, 0) as tx_bytes, COALESCE(rx_bytes, 0) as rx_bytes
           FROM devices WHERE client_type = 1"#,
    )
    .fetch_all(pool)
    .await
    .context("Failed to load IKEv2 devices")?;
    rows.into_iter()
        .map(|row| {
            Ok(DeviceRecord {
                device_id: row.try_get("device_id")?,
                network_code: row.try_get("network_code")?,
                ip: row.try_get("ip")?,
                ip_type: DeviceIpType::from_i32(row.try_get("ip_type")?),
                client_type: ClientType::from_i32(row.try_get("client_type")?),
                ikev2_password: row.try_get("ikev2_password")?,
                ikev2_output_subnets: decode_json_column(&row, "ikev2_output_subnets")?,
                ikev2_input_routes: decode_json_column(&row, "ikev2_input_routes")?,
                wireguard_output_subnets: decode_json_column(&row, "wireguard_output_subnets")?,
                wireguard_input_routes: decode_json_column(&row, "wireguard_input_routes")?,
                wireguard_dns: decode_json_column(&row, "wireguard_dns")?,
                wireguard_private_key: row.try_get("wireguard_private_key")?,
                wireguard_public_key: row.try_get("wireguard_public_key")?,
                device_name: row.try_get("device_name")?,
                device_version: row.try_get("device_version")?,
                last_connect_time: row.try_get("last_connect_time")?,
                tx_bytes: row.try_get("tx_bytes")?,
                rx_bytes: row.try_get("rx_bytes")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .context("Failed to decode IKEv2 devices")
}

pub async fn load_all_wireguard_devices() -> anyhow::Result<Vec<DeviceRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(
        r#"SELECT device_id, network_code, ip, ip_type, client_type, ikev2_password, ikev2_output_subnets, ikev2_input_routes, wireguard_output_subnets, wireguard_input_routes, wireguard_dns, wireguard_private_key, wireguard_public_key, device_name, device_version, last_connect_time,
           COALESCE(tx_bytes, 0) as tx_bytes, COALESCE(rx_bytes, 0) as rx_bytes
           FROM devices WHERE client_type = 2"#,
    )
    .fetch_all(pool)
    .await
    .context("Failed to load WireGuard devices")?;
    rows.into_iter()
        .map(|row| {
            Ok(DeviceRecord {
                device_id: row.try_get("device_id")?,
                network_code: row.try_get("network_code")?,
                ip: row.try_get("ip")?,
                ip_type: DeviceIpType::from_i32(row.try_get("ip_type")?),
                client_type: ClientType::from_i32(row.try_get("client_type")?),
                ikev2_password: row.try_get("ikev2_password")?,
                ikev2_output_subnets: decode_json_column(&row, "ikev2_output_subnets")?,
                ikev2_input_routes: decode_json_column(&row, "ikev2_input_routes")?,
                wireguard_output_subnets: decode_json_column(&row, "wireguard_output_subnets")?,
                wireguard_input_routes: decode_json_column(&row, "wireguard_input_routes")?,
                wireguard_dns: decode_json_column(&row, "wireguard_dns")?,
                wireguard_private_key: row.try_get("wireguard_private_key")?,
                wireguard_public_key: row.try_get("wireguard_public_key")?,
                device_name: row.try_get("device_name")?,
                device_version: row.try_get("device_version")?,
                last_connect_time: row.try_get("last_connect_time")?,
                tx_bytes: row.try_get("tx_bytes")?,
                rx_bytes: row.try_get("rx_bytes")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .context("Failed to decode WireGuard devices")
}

pub async fn delete_device(network_code: &str, device_id: &str) -> anyhow::Result<bool> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(false);
    };

    sqlx::query(r#"DELETE FROM vnt_device_configs WHERE network_code = ? AND device_id = ?"#)
        .bind(network_code)
        .bind(device_id)
        .execute(pool)
        .await
        .context("Failed to delete managed device config")?;
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

    sqlx::query(r#"DELETE FROM vnt_device_configs WHERE network_code = ?"#)
        .bind(network_code)
        .execute(pool)
        .await
        .context("Failed to delete managed configs by network")?;
    let result = sqlx::query(r#"DELETE FROM devices WHERE network_code = ?"#)
        .bind(network_code)
        .execute(pool)
        .await
        .context("Failed to delete devices by network")?;

    Ok(result.rows_affected())
}

fn managed_record_from_row(row: SqliteRow) -> Result<ManagedConfigRecord, sqlx::Error> {
    Ok(ManagedConfigRecord {
        network_code: row.try_get("network_code")?,
        device_id: row.try_get("device_id")?,
        revision: row.try_get("revision")?,
        config_toml: row.try_get("config_toml")?,
        subscription_server: row.try_get("subscription_server")?,
        traffic_servers_override: row
            .try_get::<Option<String>, _>("traffic_servers_override")?
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        credential_key: row.try_get("credential_key")?,
        subscription: row.try_get("subscription")?,
        join_id: row.try_get("join_id")?,
        updated_at: row.try_get("updated_at")?,
        configured_device_name: row.try_get("configured_device_name")?,
        configured_ip: row
            .try_get::<Option<String>, _>("configured_ip")?
            .map(|value| value.parse())
            .transpose()
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        fixed_ip: row
            .try_get::<Option<String>, _>("fixed_ip")?
            .map(|value| value.parse())
            .transpose()
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
    })
}

pub async fn get_managed_config(
    network_code: &str,
    device_id: &str,
) -> anyhow::Result<Option<ManagedConfigRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(None);
    };
    let row = sqlx::query(
        "SELECT c.network_code, c.device_id, c.revision, c.config_toml, c.subscription_server, c.traffic_servers_override, c.credential_key, c.subscription,
                COALESCE(c.join_id, '') AS join_id,
                c.updated_at, d.device_name AS configured_device_name, d.ip AS configured_ip,
                CASE WHEN d.ip_type = 2 THEN d.ip ELSE NULL END AS fixed_ip
         FROM vnt_device_configs c
         JOIN devices d ON d.network_code = c.network_code AND d.device_id = c.device_id
         WHERE c.network_code = ? AND c.device_id = ?",
    )
    .bind(network_code)
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch managed config")?;
    row.map(managed_record_from_row)
        .transpose()
        .map_err(Into::into)
}

/// 按订阅接入 ID 查找受管配置记录。链接被删除设备后此查找必然落空，
/// 是“删除即失效”的认证入口。
pub async fn get_managed_config_by_join_id(
    join_id: &str,
) -> anyhow::Result<Option<ManagedConfigRecord>> {
    if join_id.is_empty() {
        return Ok(None);
    }
    let Some(pool) = DB_POOL.get() else {
        return Ok(None);
    };
    let row = sqlx::query(
        "SELECT c.network_code, c.device_id, c.revision, c.config_toml, c.subscription_server, c.traffic_servers_override, c.credential_key, c.subscription,
                COALESCE(c.join_id, '') AS join_id,
                c.updated_at, d.device_name AS configured_device_name, d.ip AS configured_ip,
                CASE WHEN d.ip_type = 2 THEN d.ip ELSE NULL END AS fixed_ip
         FROM vnt_device_configs c
         JOIN devices d ON d.network_code = c.network_code AND d.device_id = c.device_id
         WHERE c.join_id = ?",
    )
    .bind(join_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch managed config by join id")?;
    row.map(managed_record_from_row)
        .transpose()
        .map_err(Into::into)
}

/// 返回设备当前的 join_id；为空时生成 UUID 并落库后返回。
/// 创建设备之外的编辑路径（客户端配置保存、补签发链接）用它补齐。
pub async fn ensure_join_id(network_code: &str, device_id: &str) -> anyhow::Result<String> {
    if let Some(record) = get_managed_config(network_code, device_id).await?
        && !record.join_id.is_empty()
    {
        return Ok(record.join_id);
    }
    let join_id = crate::managed_config::new_join_id();
    let Some(pool) = DB_POOL.get() else {
        return Ok(join_id);
    };
    sqlx::query(
        "UPDATE vnt_device_configs
         SET join_id = CASE WHEN join_id IS NULL OR join_id = '' THEN ? ELSE join_id END
         WHERE network_code = ? AND device_id = ?",
    )
    .bind(&join_id)
    .bind(network_code)
    .bind(device_id)
    .execute(pool)
    .await
    .context("Failed to assign subscription join id")?;
    Ok(join_id)
}

pub async fn list_managed_configs() -> anyhow::Result<Vec<ManagedConfigRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(
        "SELECT c.network_code, c.device_id, c.revision, c.config_toml, c.subscription_server, c.traffic_servers_override, c.credential_key, c.subscription,
                COALESCE(c.join_id, '') AS join_id,
                c.updated_at, d.device_name AS configured_device_name, d.ip AS configured_ip,
                CASE WHEN d.ip_type = 2 THEN d.ip ELSE NULL END AS fixed_ip
         FROM vnt_device_configs c
         JOIN devices d ON d.network_code = c.network_code AND d.device_id = c.device_id",
    )
    .fetch_all(pool)
    .await
    .context("Failed to list managed configs")?;
    rows.into_iter()
        .map(managed_record_from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

pub async fn create_managed_config(record: &ManagedConfigRecord) -> anyhow::Result<()> {
    let pool = DB_POOL
        .get()
        .ok_or_else(|| anyhow::anyhow!("订阅链接配置需要启用 persistence"))?;
    sqlx::query(
        "INSERT INTO vnt_device_configs
         (network_code, device_id, revision, config_toml, subscription_server, traffic_servers_override, credential_key, subscription,
          join_id, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&record.network_code)
    .bind(&record.device_id)
    .bind(record.revision)
    .bind(&record.config_toml)
    .bind(&record.subscription_server)
    .bind(
        record
            .traffic_servers_override
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?,
    )
    .bind(&record.credential_key)
    .bind(&record.subscription)
    .bind(&record.join_id)
    .bind(record.updated_at)
    .execute(pool)
    .await
    .context("Failed to create managed config")?;
    Ok(())
}

pub async fn update_managed_config(
    network_code: &str,
    device_id: &str,
    config_toml: &str,
    join_id: &str,
    updated_at: i64,
) -> anyhow::Result<Option<ManagedConfigRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(None);
    };
    let result = sqlx::query(
        "UPDATE vnt_device_configs
         SET config_toml = ?, revision = revision + 1, updated_at = ?,
             join_id = CASE WHEN join_id IS NULL OR join_id = '' THEN ? ELSE join_id END
         WHERE network_code = ? AND device_id = ?",
    )
    .bind(config_toml)
    .bind(updated_at)
    .bind(join_id)
    .bind(network_code)
    .bind(device_id)
    .execute(pool)
    .await
    .context("Failed to update managed config")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    get_managed_config(network_code, device_id).await
}

pub async fn update_managed_config_with_endpoints(
    network_code: &str,
    device_id: &str,
    config_toml: &str,
    subscription_server: &str,
    traffic_servers_override: Option<&[String]>,
    join_id: &str,
    updated_at: i64,
) -> anyhow::Result<Option<ManagedConfigRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(None);
    };
    let encoded = traffic_servers_override
        .map(serde_json::to_string)
        .transpose()?;
    let result = sqlx::query(
        "UPDATE vnt_device_configs
         SET config_toml = ?, subscription_server = ?, traffic_servers_override = ?, revision = revision + 1, updated_at = ?,
             join_id = CASE WHEN join_id IS NULL OR join_id = '' THEN ? ELSE join_id END
         WHERE network_code = ? AND device_id = ?",
    )
    .bind(config_toml)
    .bind(subscription_server)
    .bind(encoded)
    .bind(updated_at)
    .bind(join_id)
    .bind(network_code)
    .bind(device_id)
    .execute(pool)
    .await
    .context("Failed to update managed config endpoints")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    get_managed_config(network_code, device_id).await
}

/// Atomically advances every device which inherits the global traffic-server
/// list. The caller pushes the returned committed records afterwards.
pub async fn update_inherited_traffic_servers(
    traffic_servers: &[String],
    fallback_subscription_server: &str,
    updated_at: i64,
) -> anyhow::Result<Vec<ManagedConfigRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(Vec::new());
    };
    let effective = if traffic_servers.is_empty() {
        vec![fallback_subscription_server.to_string()]
    } else {
        traffic_servers.to_vec()
    };
    let rows = sqlx::query(
        "SELECT network_code, device_id, config_toml FROM vnt_device_configs
         WHERE traffic_servers_override IS NULL",
    )
    .fetch_all(pool)
    .await?;
    let mut transaction = pool.begin().await?;
    for row in rows {
        let network_code: String = row.try_get("network_code")?;
        let device_id: String = row.try_get("device_id")?;
        let source: String = row.try_get("config_toml")?;
        let mut table: toml::Table = toml::from_str(&source)?;
        table.insert(
            "server".to_string(),
            toml::Value::Array(effective.iter().cloned().map(toml::Value::String).collect()),
        );
        let rendered = toml::to_string_pretty(&table)?;
        sqlx::query(
            "UPDATE vnt_device_configs
             SET config_toml = ?, revision = revision + 1, updated_at = ?
             WHERE network_code = ? AND device_id = ? AND traffic_servers_override IS NULL",
        )
        .bind(rendered)
        .bind(updated_at)
        .bind(network_code)
        .bind(device_id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(list_managed_configs()
        .await?
        .into_iter()
        .filter(|record| record.traffic_servers_override.is_none())
        .collect())
}

/// Rewrites the persisted representation without changing its semantic revision.
///
/// This is used when legacy or user supplied TOML only differs by comments,
/// formatting, or fields that are never part of the managed payload.
pub async fn rewrite_managed_config(
    network_code: &str,
    device_id: &str,
    config_toml: &str,
    join_id: &str,
    updated_at: i64,
) -> anyhow::Result<Option<ManagedConfigRecord>> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(None);
    };
    let result = sqlx::query(
        "UPDATE vnt_device_configs
         SET config_toml = ?, updated_at = ?,
             join_id = CASE WHEN join_id IS NULL OR join_id = '' THEN ? ELSE join_id END
         WHERE network_code = ? AND device_id = ?",
    )
    .bind(config_toml)
    .bind(updated_at)
    .bind(join_id)
    .bind(network_code)
    .bind(device_id)
    .execute(pool)
    .await
    .context("Failed to rewrite managed config")?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    get_managed_config(network_code, device_id).await
}

pub async fn rotate_subscription_credentials(
    network_code: &str,
    device_id: &str,
    credential_key: &str,
    subscription: &str,
    join_id: &str,
    updated_at: i64,
) -> anyhow::Result<bool> {
    let Some(pool) = DB_POOL.get() else {
        return Ok(false);
    };
    let result = sqlx::query(
        "UPDATE vnt_device_configs
         SET credential_key = ?, subscription = ?, updated_at = ?,
             join_id = CASE WHEN join_id IS NULL OR join_id = '' THEN ? ELSE join_id END
         WHERE network_code = ? AND device_id = ?",
    )
    .bind(credential_key)
    .bind(subscription)
    .bind(updated_at)
    .bind(join_id)
    .bind(network_code)
    .bind(device_id)
    .execute(pool)
    .await
    .context("Failed to rotate managed token")?;
    Ok(result.rows_affected() > 0)
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

#[cfg(test)]
mod tests {
    use super::migrate_managed_config_schema;
    use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};

    #[tokio::test]
    async fn release_device_ip_keeps_managed_device_address() {
        let pool: SqlitePool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE devices (
                network_code TEXT NOT NULL,
                device_id TEXT NOT NULL,
                ip TEXT,
                PRIMARY KEY(network_code, device_id)
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE vnt_device_configs (
                network_code TEXT NOT NULL,
                device_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                config_toml TEXT NOT NULL,
                PRIMARY KEY(network_code, device_id)
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        for (device_id, ip) in [("dynamic", "10.0.0.2"), ("managed", "10.0.0.3")] {
            sqlx::query("INSERT INTO devices (network_code, device_id, ip) VALUES ('net', ?, ?)")
                .bind(device_id)
                .bind(ip)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT INTO vnt_device_configs (network_code, device_id, revision, config_toml)
             VALUES ('net', 'managed', 1, '')",
        )
        .execute(&pool)
        .await
        .unwrap();

        super::release_device_ip_on(&pool, "net", "dynamic")
            .await
            .unwrap();
        super::release_device_ip_on(&pool, "net", "managed")
            .await
            .unwrap();

        let dynamic_ip: Option<String> = sqlx::query(
            "SELECT ip FROM devices WHERE network_code = 'net' AND device_id = 'dynamic'",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("ip");
        let managed_ip: Option<String> = sqlx::query(
            "SELECT ip FROM devices WHERE network_code = 'net' AND device_id = 'managed'",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("ip");

        assert!(dynamic_ip.is_none());
        assert_eq!(managed_ip.as_deref(), Some("10.0.0.3"));
    }

    #[tokio::test]
    async fn legacy_managed_config_schema_is_upgraded_before_reads() {
        let pool: SqlitePool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE vnt_device_configs (
                network_code TEXT NOT NULL,
                device_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                config_toml TEXT NOT NULL,
                PRIMARY KEY(network_code, device_id)
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO vnt_device_configs (network_code, device_id, revision, config_toml)
             VALUES ('net', 'device', 1, '')",
        )
        .execute(&pool)
        .await
        .unwrap();

        migrate_managed_config_schema(&pool).await.unwrap();
        migrate_managed_config_schema(&pool).await.unwrap();

        let row = sqlx::query(
            "SELECT credential_key, subscription, updated_at
             FROM vnt_device_configs WHERE network_code = 'net' AND device_id = 'device'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.get::<i64, _>("updated_at"), 0);
        assert!(row.get::<Option<String>, _>("credential_key").is_none());
        assert!(row.get::<Option<String>, _>("subscription").is_none());
    }
}
