export interface ApiResponse<T> {
  code: number
  msg: string
  data: T | null
}

export interface LoginResult {
  token: string
}

export type NetworkSource = 'Config' | 'Manual' | 'DeviceRegister' | string
export type NetworkType = 'Public' | 'Private'
export type DeviceIpType = 'Dynamic' | 'Static' | 'Fixed'
export type ClientType = 'VNT' | 'IKEV2' | 'WIREGUARD'

export interface Ikev2InputRoute {
  subnet: string
  target_ip: string
}

export interface NetworkInfo {
  network_code: string
  gateway: string
  netmask: number
  net: string
  lease_duration: number
  source: NetworkSource
  network_type: NetworkType
  all_count: number
  online_count: number
}

export type DeviceStatus = 'Online' | 'Remote' | string

export interface DeviceInfo {
  device_id: string
  device_name: string
  current_device_name: string | null
  device_version: string
  client_type: ClientType
  ip: string | null
  current_ip: string | null
  ip_type: DeviceIpType | null
  status: DeviceStatus
  last_connect_time: string
  disconnect_time: string | null
  latency_ms: number | null
  server_addr: string | null
  advertised_subnets: string[]
  ikev2_output_subnets: string[]
  ikev2_input_routes: Ikev2InputRoute[]
  wireguard_output_subnets: string[]
  wireguard_input_routes: Ikev2InputRoute[]
  wireguard_dns: string[]
  tx_bytes: number
  rx_bytes: number
  /** 前端基于两次轮询差分计算出的瞬时网速 */
  tx_speed?: number
  rx_speed?: number
  managed: boolean
  /** 中继（流量）会话在线 */
  relay_online: boolean
  /** 订阅控制连接在线 */
  subscription_online: boolean
  subscription_issued: boolean
  subscription_target_revision: number | null
  subscription_applied_revision: number | null
  subscription_status: string | null
  subscription_error: string | null
}

export interface CreateNetworkPayload {
  network_code: string
  gateway: string
  netmask: number
  lease_duration?: number
  network_type?: NetworkType
}

export interface UpdateNetworkPayload {
  gateway: string
  netmask: number
  lease_duration: number
  network_type?: NetworkType
}

export interface CreateDevicePayload {
  network_code: string
  device_id: string
  device_name?: string
  ip: string
  ip_type?: DeviceIpType
  client_type: ClientType
  ikev2_password?: string
  ikev2_output_subnets?: string[]
  ikev2_input_routes?: Ikev2InputRoute[]
  wireguard_output_subnets?: string[]
  wireguard_input_routes?: Ikev2InputRoute[]
  wireguard_dns?: string[]
  wireguard_private_key?: string
}

export interface UpdateDevicePayload {
  network_code: string
  device_name?: string
  ip: string
  ip_type: DeviceIpType
  ikev2_password?: string
  ikev2_output_subnets?: string[]
  ikev2_input_routes?: Ikev2InputRoute[]
  wireguard_output_subnets?: string[]
  wireguard_input_routes?: Ikev2InputRoute[]
  wireguard_dns?: string[]
  wireguard_private_key?: string
}

export interface PeerServerInfo {
  addr: string
  latency_ms: number
  connected: boolean
  is_outbound: boolean
}

export interface PeerServersResponse {
  outbound: PeerServerInfo[]
  inbound: PeerServerInfo[]
}

export interface DeviceIkev2AccessInfo {
  service: Ikev2ServiceInfo
  network_code: string
  network_net: string
  username: string
  password: string
}

export interface Ikev2ServiceInfo {
  configured: boolean
  enabled: boolean
  runtime_active: boolean
  ike_bind: string
  natt_bind: string
  server_address: string
  remote_id: string
  dns: string[]
  cert: string | null
  key: string | null
  certificate_configured: boolean
  certificate_managed: boolean
  certificate_not_after: number | null
  ca_download_available: boolean
  server_certificate_download_available: boolean
  runtime_error: string | null
}

export interface UpdateIkev2ServicePayload {
  enabled: boolean
  ike_bind: string
  natt_bind: string
  server_address: string
  remote_id: string
  dns: string[]
  cert?: string
  key?: string
}

export interface WireGuardServiceInfo {
  configured: boolean
  enabled: boolean
  runtime_active: boolean
  bind: string
  endpoint: string
  persistent_keepalive: number
  public_key: string | null
  runtime_error: string | null
}

export interface UpdateWireGuardServicePayload {
  enabled: boolean
  bind: string
  endpoint: string
  persistent_keepalive: number
}

export interface DeviceWireGuardAccessInfo {
  service: WireGuardServiceInfo
  network_code: string
  network_net: string
  device_id: string
  private_key: string
  public_key: string
  config: string
}

export interface NetworkWhitelistSettings {
  network_codes: string[]
}

export interface ClientAccessSettings {
  subscription_server: string
  traffic_servers: string[]
  listener_ports?: {
    tcp: number | null
    quic: number | null
    wss: number | null
  }
}

export interface ManagedConfig {
  network_code: string
  device_id: string
  revision: number
  config_toml: string
  advanced_config_toml: string
  applied_revision: number
  status: string
  error: string | null
  overridden_fields: string[]
  updated_at: number
  subscription_issued: boolean
  subscription_server: string
  traffic_servers_override: string[] | null
  inherits_traffic_servers: boolean
  effective_traffic_servers: string[]
  client_config: VntClientConfig
}

export interface VntClientConfig {
  current_server: string
  other_servers: string[]
  cert_mode: 'standard' | 'finger'
  password: string
  peer_address: string[]
  turn: string[]
  punch_model: string[]
  device_mode: '' | 'tun' | 'tap' | 'no'
  mtu: number | null
  tun_name: string
  outbound_interface: string
  input: string[]
  output: string[]
  port_mapping: string[]
  subnet_mapping: string[]
  udp_stun: string[]
  tcp_stun: string[]
  tunnel_addr: string[]
  tunnel_port: number | null
  ctrl_port: number | null
  no_punch: boolean | null
  no_broadcast: boolean | null
  allow_ikev2: boolean | null
  allow_wireguard: boolean | null
  compress: boolean | null
  rtx: boolean | null
  fec: boolean | null
  auto_sync_subnet: boolean | null
  no_nat: boolean | null
  allow_mapping: boolean | null
}

export interface ManagedConfigMutation {
  config: ManagedConfig
  push_status: 'queued' | 'not_connected' | 'registering' | 'timeout' | 'closed' | 'unchanged'
  subscription?: string
}

export interface CreateManagedDevicePayload {
  network_code: string
  device_id: string
  device_name: string
  ip: string
  ip_type: DeviceIpType
  config_toml: string
  subscription_server: string
  traffic_servers_override: string[]
  client_type?: 'VNT'
}
