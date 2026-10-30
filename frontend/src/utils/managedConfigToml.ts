import { parse, type TomlTable, type TomlValue } from 'smol-toml'
import type { VntClientConfig } from '@/types'

const baseFields = new Set(['server', 'cert_mode', 'network_code', 'device_id', 'device_name', 'ip'])
const forbiddenFields = new Set(['subscription', 'event_script', 'no_tun', 'config_name'])
const arrayFields = ['peer_address', 'turn', 'punch_model', 'input', 'output', 'subnet_mapping', 'port_mapping', 'udp_stun', 'tcp_stun', 'tunnel_addr'] as const
const booleanFields = ['no_punch', 'no_broadcast', 'allow_ikev2', 'allow_wireguard', 'rtx', 'compress', 'fec', 'auto_sync_subnet', 'no_nat', 'allow_mapping'] as const
const stringFields = ['password', 'device_mode', 'tun_name', 'outbound_interface'] as const
const numberFields = ['mtu', 'ctrl_port', 'tunnel_port'] as const
const knownAdvancedFields = new Set<string>([...arrayFields, ...booleanFields, ...stringFields, ...numberFields])
const MIN_MTU = 576
const MAX_MTU = 1500

export function emptyVntClientConfig(): VntClientConfig {
  return {
    current_server: '', other_servers: [], cert_mode: 'finger', password: '', device_mode: '', mtu: null,
    peer_address: [], turn: [], punch_model: [], tun_name: '', outbound_interface: '',
    input: [], output: [], subnet_mapping: [], port_mapping: [], udp_stun: [], tcp_stun: [],
    tunnel_addr: [], tunnel_port: null, ctrl_port: null,
    no_punch: null, no_broadcast: null, allow_ikev2: null, allow_wireguard: null,
    compress: null, rtx: null, fec: null, auto_sync_subnet: null, no_nat: null,
    allow_mapping: null,
  }
}

export const ADVANCED_CONFIG_TEMPLATE = `# 以下字段按需取消注释；未设置时使用客户端默认值
# peer_address = ["tcp://192.168.1.10:29873"]
# turn = ["10.26.0.0/24,10.26.0.2"]
# punch_model = ["10.26.0.0/24,IPv4Tcp,IPv4Udp"]
# no_punch = false
# no_broadcast = false
# allow_ikev2 = false
# allow_wireguard = false
# rtx = false
# compress = false
# fec = false
# mtu = 1400 # 范围：576-1500
# input = ["192.168.10.0/24,10.26.0.2"]
# output = ["192.168.20.0/24"]
# subnet_mapping = ["192.168.30.0/24,192.168.20.0/24"]
# auto_sync_subnet = false
# no_nat = false
# port_mapping = ["tcp://127.0.0.1:8080-10.26.0.2-127.0.0.1:80"]
# allow_mapping = false
# device_mode = "no" # 可选：tun / tap / no
# tun_name = ""
# outbound_interface = ""
# ctrl_port = 11233
# tunnel_addr = ["0.0.0.0:29873", "[::]:29873"]
# tunnel_port = 29873 # 与 tunnel_addr 二选一
# udp_stun = ["stun.example.com:3478"]
# tcp_stun = ["stun.example.com:3478"]
# password = ""
`

function expectStringArray(table: TomlTable, key: string): string[] {
  const value = table[key]
  if (value === undefined) return []
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new Error(`${key} 必须是字符串数组`)
  }
  return value as string[]
}

function expectBoolean(table: TomlTable, key: string): boolean | null {
  const value = table[key]
  if (value === undefined) return null
  if (typeof value !== 'boolean') throw new Error(`${key} 必须是布尔值`)
  return value
}

function expectString(table: TomlTable, key: string): string {
  const value = table[key]
  if (value === undefined) return ''
  if (typeof value !== 'string') throw new Error(`${key} 必须是字符串`)
  return value
}

function expectPort(table: TomlTable, key: string): number | null {
  const value = table[key]
  if (value === undefined) return null
  const number = Number(value)
  if (!Number.isInteger(number) || number < 0 || number > 65_535) {
    throw new Error(`${key} 必须是 0 到 65535 的整数`)
  }
  return number
}

function expectMtu(table: TomlTable): number | null {
  const value = table.mtu
  if (value === undefined) return null
  const number = Number(value)
  if (!Number.isInteger(number) || number < MIN_MTU || number > MAX_MTU) {
    throw new Error(`mtu 必须是 ${MIN_MTU} 到 ${MAX_MTU} 的整数`)
  }
  return number
}

export interface ParsedAdvancedConfig {
  form: VntClientConfig
  extras: TomlTable
}

export function parseAdvancedToml(source: string, base = emptyVntClientConfig()): ParsedAdvancedConfig {
  let table: TomlTable
  try {
    table = parse(source) as TomlTable
  } catch (error) {
    throw new Error(error instanceof Error ? error.message : 'TOML 格式错误')
  }
  for (const key of Object.keys(table)) {
    if (baseFields.has(key)) throw new Error(`${key} 由设备基础配置管理，不能写入高级配置`)
    if (forbiddenFields.has(key)) throw new Error(`${key} 不支持服务端下发`)
  }
  const form = { ...base }
  for (const key of arrayFields) form[key] = expectStringArray(table, key)
  for (const key of booleanFields) form[key] = expectBoolean(table, key)
  for (const key of stringFields) form[key] = expectString(table, key) as never
  form.mtu = expectMtu(table)
  for (const key of ['ctrl_port', 'tunnel_port'] as const) form[key] = expectPort(table, key)
  if (form.device_mode && !['tun', 'tap', 'no'].includes(form.device_mode)) {
    throw new Error('device_mode 只能是 "tun"、"tap" 或 "no"')
  }
  if (form.tunnel_addr.length && form.tunnel_port !== null) {
    throw new Error('tunnel_addr 和 tunnel_port 不能同时配置')
  }
  const extras: TomlTable = {}
  for (const [key, value] of Object.entries(table)) {
    if (!knownAdvancedFields.has(key)) extras[key] = value as TomlValue
  }
  return { form, extras }
}

export const REMOTE_ADVANCED_CONFIG_TEMPLATE = `# 仅配置中继、打洞及通信参数；按需取消注释
# peer_address = ["tcp://192.168.1.10:29873"]
# turn = ["001,0001"]
# punch_model = ["001,IPv4Tcp,IPv4Udp"]
# no_punch = false
# compress = false
# udp_stun = ["stun.example.com:3478"]
# tcp_stun = ["stun.example.com:3478"]
# tunnel_port = 29873
# outbound_interface = ""
# password = ""
`
const remoteFields = new Set(['password', 'peer_address', 'turn', 'punch_model', 'outbound_interface', 'udp_stun', 'tcp_stun', 'tunnel_addr', 'tunnel_port', 'no_punch', 'compress', 'rtx', 'fec'])
export function validateAdvancedToml(source: string, remote = false): void {
  if (remote) {
    const table = parse(source)
    for (const key of Object.keys(table)) if (!remoteFields.has(key)) throw new Error(`远程连接组不支持配置 ${key}`)
    for (const key of ['turn', 'punch_model']) {
      for (const rule of expectStringArray(table, key)) {
        const parts = rule.split(',').map(part => part.trim())
        if (!/^[0-9]{1,9}$/.test(parts[0] ?? '') || parts.length < 2) throw new Error(`${key} 的目标必须为连接 ID`)
        if (key === 'turn' && (parts.length !== 2 || !/^[0-9]{1,9}$/.test(parts[1] ?? ''))) throw new Error('turn 格式为目标连接ID,中继连接ID')
      }
    }
  }
  parseAdvancedToml(source, emptyVntClientConfig())
}
