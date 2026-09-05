import { downloadFile, fetchSilent, request } from './client'
import type {
  CreateNetworkPayload,
  CreateDevicePayload,
  DeviceInfo,
  DeviceIkev2AccessInfo,
  LoginResult,
  NetworkInfo,
  NetworkWhitelistSettings,
  PeerServersResponse,
  Ikev2ServiceInfo,
  UpdateIkev2ServicePayload,
  UpdateNetworkPayload,
  UpdateDevicePayload,
} from '@/types'

export const authApi = {
  login: (username: string, password: string) =>
    request<LoginResult>('/login', { method: 'POST', body: { username, password } }),
}

export const networkApi = {
  codes: () => request<string[]>('/network_codes'),
  list: async () => {
    const networks = await request<NetworkInfo[]>('/networks')
    return networks.map((network) => ({
      ...network,
      network_type: network.network_type ?? 'Public',
    }))
  },
  create: (payload: CreateNetworkPayload) =>
    request<boolean>('/networks', { method: 'POST', body: payload }),
  update: (code: string, payload: UpdateNetworkPayload) =>
    request<boolean>(`/networks/${encodeURIComponent(code)}`, { method: 'PUT', body: payload }),
  remove: (code: string) =>
    request<boolean>(`/networks/${encodeURIComponent(code)}`, { method: 'DELETE' }),
}

export const deviceApi = {
  add: (payload: CreateDevicePayload) =>
    request<boolean>('/devices', { method: 'POST', body: payload }),
  update: (deviceId: string, payload: UpdateDevicePayload) =>
    request<boolean>(`/devices/${encodeURIComponent(deviceId)}`, {
      method: 'PUT',
      body: payload,
    }),
  /** 首次加载（带 loading 与错误提示） */
  load: (code: string) =>
    request<DeviceInfo[]>(`/devices?code=${encodeURIComponent(code)}`),
  /** 轮询刷新（静默） */
  list: (code: string) =>
    fetchSilent<DeviceInfo[]>(`/devices?code=${encodeURIComponent(code)}`),
  remove: (code: string, deviceId: string) =>
    request<boolean>(
      `/devices?code=${encodeURIComponent(code)}&device_id=${encodeURIComponent(deviceId)}`,
      { method: 'DELETE' },
    ),
  getIkev2Access: (code: string, deviceId: string) =>
    request<DeviceIkev2AccessInfo>(
      `/networks/${encodeURIComponent(code)}/devices/${encodeURIComponent(deviceId)}/ikev2-access`,
    ),
}

export const peerServerApi = {
  list: () => request<PeerServersResponse>('/peer_servers'),
  add: (serverAddr: string) =>
    request<boolean>('/peer_servers', { method: 'POST', body: { server_addr: serverAddr } }),
  remove: (serverAddr: string) =>
    request<boolean>(`/peer_servers/${encodeURIComponent(serverAddr)}`, { method: 'DELETE' }),
}

export const settingsApi = {
  getNetworkWhitelist: () =>
    request<NetworkWhitelistSettings>('/settings/network-whitelist'),
  updateNetworkWhitelist: (payload: NetworkWhitelistSettings) =>
    request<NetworkWhitelistSettings>('/settings/network-whitelist', {
      method: 'PUT',
      body: payload,
    }),
  getIkev2: () => request<Ikev2ServiceInfo>('/settings/ikev2'),
  updateIkev2: (payload: UpdateIkev2ServicePayload) =>
    request<Ikev2ServiceInfo>('/settings/ikev2', {
      method: 'PUT',
      body: payload,
    }),
  downloadIkev2Ca: (format: 'der' | 'pem' = 'der') =>
    downloadFile(`/ikev2/ca-certificate?format=${format}`, `vnt-ikev2-ca.${format === 'der' ? 'cer' : 'pem'}`),
  downloadIkev2ServerCertificate: (format: 'der' | 'pem' = 'der') =>
    downloadFile(`/ikev2/server-certificate?format=${format}`, `vnt-ikev2-server.${format === 'der' ? 'cer' : 'pem'}`),
}
