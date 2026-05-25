# hsxa-ai

基于 Go 的 mDNS/DNS-SD 网络测绘 CLI 工具。输入 IP 网段和端口范围，通过单播 mDNS 协议主动探测目标资产，深度识别服务 banner 并结构化输出。

## 安装

**从源码编译（需要 Go 1.21+）**

```bash
git clone https://github.com/xiaoyu0803/hsxa-ai.git
cd hsxa-ai
go build -o hsxa-ai .
```

## 用法

```
hsxa-ai -i <IP> -p <端口> [选项]
```

### 参数

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| `--ips` | `-i` | 必填 | 目标 IP，支持单 IP / CIDR / 连字符范围 / 逗号列表 |
| `--ports` | `-p` | `5353` | 端口，支持单端口 / 范围 / 逗号列表 |
| `--output` | `-o` | `text` | 输出格式：`text` / `json` / `yaml` |
| `--file` | `-f` | — | 输出到文件（默认 stdout） |
| `--timeout` | — | `5s` | 单目标超时，如 `2s`、`10s` |
| `--concur` | — | `200` | 最大并发探测数 |
| `--verbose` | `-v` | — | 详细日志 |

### IP 输入格式

```bash
-i 192.168.1.1              # 单 IP
-i 192.168.1.0/24           # CIDR
-i 192.168.1.1-192.168.1.50 # 连字符范围
-i 192.168.1.1,10.0.0.1     # 逗号列表
```

### 端口输入格式

```bash
-p 5353             # 单端口
-p 5353,9,445,548   # 逗号列表
-p 8000-8080        # 范围
-p 80,443,8000-8010 # 混合
```

## 示例

**探测本机 mDNS 服务**

```bash
./hsxa-ai -i 127.0.0.1 -p 5353
```

```
[127.0.0.1]
services:
  7000/tcp airplay:
    Name=MyMacBook Pro
    IPv4=127.0.0.1
    IPv6=::1
    Hostname=MyMacBook.local
    TTL=10
    model=Mac17,2,srcvers=950.7.1,features=0x4A7FCFD5,0x38174FDE
  7000/tcp raop:
    Name=CEA65E148865@MyMacBook Pro
    IPv4=127.0.0.1
    Hostname=MyMacBook.local
    TTL=10
    cn=0,1,2,3,tp=UDP,vs=950.7.1
answers:
  PTR:
    _airplay._tcp.local
    _raop._tcp.local
    _companion-link._tcp.local
```

**扫描局域网 /24 网段**

```bash
./hsxa-ai -i 192.168.1.0/24 -p 5353 --timeout 5s --concur 100
```

**扫描多端口（NAS 设备）**

```bash
./hsxa-ai -i 192.168.1.100 -p 5353,9,5000,445,548
```

**JSON 输出，适合脚本解析**

```bash
./hsxa-ai -i 192.168.1.0/24 -p 5353 -o json | jq '.hosts[].services[].service_type'
```

**YAML 输出**

```bash
./hsxa-ai -i 192.168.1.1 -p 5353 -o yaml
```

**输出到文件**

```bash
./hsxa-ai -i 192.168.1.0/24 -p 5353 -o json -f result.json
```

**快速超时扫描大网段**

```bash
./hsxa-ai -i 10.0.0.0/16 -p 5353 --timeout 2s --concur 500
```

## 识别能力

工具自动探测以下 mDNS 服务类型并深度解析 banner：

| 服务类型 | 典型设备 | 关键 banner 字段 |
|---------|---------|----------------|
| `_workstation._tcp` | Linux/macOS 主机 | Name、Hostname、MAC |
| `_http._tcp` | Web 服务 | path |
| `_smb._tcp` | Windows/NAS | 共享名称 |
| `_afpovertcp._tcp` | macOS/NAS | AFP 服务信息 |
| `_qdiscover._tcp` | QNAP NAS | model、fwVer、fwBuildNum、accessType、accessPort |
| `_device-info._tcp` | Apple 设备 | model（如 Mac17,2、Xserve） |
| `_airplay._tcp` | Apple TV/Mac | features、model、srcvers |
| `_raop._tcp` | AirPlay 音频 | 编解码参数 |
| `_homekit._tcp` | HomeKit 设备 | 配对信息 |
| `_googlecast._tcp` | Chromecast | 设备型号 |

## 输出格式说明

### text（默认）

```
[IP地址]
services:
  <port>/tcp <service>:
    Name=<实例名> [MAC地址]
    IPv4=<地址>
    IPv6=<地址>
    Hostname=<主机名>
    TTL=<秒>
    <TXT键值对>
device-info:
  Name=<设备名>
  model=<型号>
answers:
  PTR:
    <服务类型列表>
```

### json

每个 IP 对应一个 JSON 对象，包含 `services`、`device_info`、`ptr_answers` 等字段。

### yaml

与 JSON 结构一致，使用 YAML 缩进格式。

## 注意事项

- mDNS 使用 UDP 单播向目标 IP 的 5353 端口发包，无需 root 权限
- 仅支持 IPv4 目标地址
- 扫描进度和统计信息输出到 stderr，不影响 stdout 管道
- 无 mDNS 响应的目标不产生任何 stdout 输出
