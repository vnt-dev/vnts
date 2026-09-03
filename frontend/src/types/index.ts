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
  device_version: string
  client_type: 'VNT' | 'IKEV2'
  ip: string | null
  current_ip: string | null
  ip_type: DeviceIpType | null
  status: DeviceStatus
  last_connect_time: string
  disconnect_time: string | null
  latency_ms: number | null
  server_addr: string | null
  advertised_subnets: string[]
  tx_bytes: number
  rx_bytes: number
  /** 前端基于两次轮询差分计算出的瞬时网速 */
  tx_speed?: number
  rx_speed?: number
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
  ip: string
  ip_type?: DeviceIpType
}

export interface UpdateDevicePayload {
  network_code: string
  ip: string
  ip_type: DeviceIpType
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

export interface NetworkIkev2Info {
  service: Ikev2ServiceInfo
  network: Ikev2NetworkInfo
  network_code: string
  network_net: string
}

export interface Ikev2ServiceInfo {
  configured: boolean
  enabled: boolean
  runtime_active: boolean
  ike_bind: string
  natt_bind: string
  remote_id: string
  public_ip: string | null
  dns: string[]
  cert: string | null
  key: string | null
  certificate_configured: boolean
  certificate_managed: boolean
  certificate_not_after: number | null
  ca_download_available: boolean
  runtime_error: string | null
}

export interface Ikev2NetworkInfo {
  enabled: boolean
  psk_configured: boolean
  eap_users: string[]
}

export interface Ikev2EapUserUpdate {
  username: string
  password?: string
}

export interface UpdateNetworkIkev2Payload {
  enabled: boolean
  psk?: string
  eap_users: Ikev2EapUserUpdate[]
}

export interface UpdateIkev2ServicePayload {
  enabled: boolean
  ike_bind: string
  natt_bind: string
  remote_id: string
  public_ip?: string
  dns: string[]
  cert?: string
  key?: string
}

export interface Ikev2Secrets {
  psk: string | null
  eap_users: Record<string, string>
}

export interface NetworkWhitelistSettings {
  network_codes: string[]
}
