import { fetchSilent, request } from './client'
import type {
  CreateNetworkPayload,
  DeviceInfo,
  LoginResult,
  NetworkInfo,
  PeerServersResponse,
  UpdateNetworkPayload,
} from '@/types'

export const authApi = {
  login: (username: string, password: string) =>
    request<LoginResult>('/login', { method: 'POST', body: { username, password } }),
}

export const networkApi = {
  list: () => request<NetworkInfo[]>('/networks'),
  create: (payload: CreateNetworkPayload) =>
    request<boolean>('/networks', { method: 'POST', body: payload }),
  update: (code: string, payload: UpdateNetworkPayload) =>
    request<boolean>(`/networks/${encodeURIComponent(code)}`, { method: 'PUT', body: payload }),
  remove: (code: string) =>
    request<boolean>(`/networks/${encodeURIComponent(code)}`, { method: 'DELETE' }),
}

export const deviceApi = {
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
}

export const peerServerApi = {
  list: () => request<PeerServersResponse>('/peer_servers'),
  add: (serverAddr: string) =>
    request<boolean>('/peer_servers', { method: 'POST', body: { server_addr: serverAddr } }),
  remove: (serverAddr: string) =>
    request<boolean>(`/peer_servers/${encodeURIComponent(serverAddr)}`, { method: 'DELETE' }),
}