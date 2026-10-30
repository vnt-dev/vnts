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
  DeviceWireGuardAccessInfo,
  WireGuardServiceInfo,
  UpdateWireGuardServicePayload,
  ClientAccessSettings,
  ManagedConfig,
  ManagedConfigMutation,
  CreateManagedDevicePayload,
  DeviceIpType,
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
  getWireGuardAccess: (code: string, deviceId: string) =>
    request<DeviceWireGuardAccessInfo>(
      `/networks/${encodeURIComponent(code)}/devices/${encodeURIComponent(deviceId)}/wireguard-access`,
    ),
}

export const managedDeviceApi = {
  create: (payload: CreateManagedDevicePayload) =>
    request<ManagedConfigMutation>('/devices', { method: 'POST', body: { ...payload, client_type: payload.client_type ?? 'VNT' } }),
  get: (code: string, deviceId: string) =>
    request<ManagedConfig>(`/networks/${encodeURIComponent(code)}/devices/${encodeURIComponent(deviceId)}/client-config`),
  update: (code: string, deviceId: string, configToml: string, subscriptionServer: string, trafficServersOverride: string[], deviceName: string, ip: string, ipType: DeviceIpType, remote = false) =>
    request<ManagedConfigMutation>(`/networks/${encodeURIComponent(code)}/devices/${encodeURIComponent(deviceId)}/client-config`, {
      method: 'PUT', body: { config_toml: configToml, subscription_server: subscriptionServer, traffic_servers_override: trafficServersOverride, device_name: deviceName, ...(remote ? { connection_id: ip } : { ip, ip_type: ipType }) },
    }),
  subscription: (code: string, deviceId: string) =>
    request<{ subscription: string }>(`/networks/${encodeURIComponent(code)}/devices/${encodeURIComponent(deviceId)}/subscription`),
  disconnect: (code: string, deviceId: string) =>
    request<boolean>(`/networks/${encodeURIComponent(code)}/devices/${encodeURIComponent(deviceId)}/disconnect`, { method: 'POST' }),
}

export const peerServerApi = {
  list: () => request<PeerServersResponse>('/peer_servers'),
  add: (serverAddr: string) =>
    request<boolean>('/peer_servers', { method: 'POST', body: { server_addr: serverAddr } }),
  remove: (serverAddr: string) =>
    request<boolean>(`/peer_servers/${encodeURIComponent(serverAddr)}`, { method: 'DELETE' }),
}

export const settingsApi = {
  getClientAccess: () => request<ClientAccessSettings>('/settings/client-access'),
  updateClientAccess: (payload: ClientAccessSettings) =>
    request<ClientAccessSettings>('/settings/client-access', { method: 'PUT', body: payload }),
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
  getWireGuard: () => request<WireGuardServiceInfo>('/settings/wireguard'),
  updateWireGuard: (payload: UpdateWireGuardServicePayload) =>
    request<WireGuardServiceInfo>('/settings/wireguard', {
      method: 'PUT',
      body: payload,
    }),
  downloadIkev2Ca: (format: 'der' | 'pem' = 'der') =>
    downloadFile(`/ikev2/ca-certificate?format=${format}`, `vnt-ikev2-ca.${format === 'der' ? 'cer' : 'pem'}`),
  downloadIkev2ServerCertificate: (format: 'der' | 'pem' = 'der') =>
    downloadFile(`/ikev2/server-certificate?format=${format}`, `vnt-ikev2-server.${format === 'der' ? 'cer' : 'pem'}`),
}
