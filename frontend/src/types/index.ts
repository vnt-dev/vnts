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
  ip: string | null
  current_ip: string | null
  ip_type: DeviceIpType | null
  status: DeviceStatus
  last_connect_time: string
  disconnect_time: string | null
  latency_ms: number | null
  server_addr: string | null
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

export interface NetworkWhitelistSettings {
  network_codes: string[]
}
