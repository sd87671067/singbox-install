#!/bin/bash

# Sing-Box 一键安装配置脚本 v2.5
# 作者: sd87671067
# 博客: dlmn.lol
# 更新时间: 2025-11-10 06:50 UTC

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

AUTHOR_BLOG="dlmn.lol"
CONFIG_FILE="/etc/sing-box/config.json"
INSTALL_DIR="/usr/local/bin"
CERT_DIR="/etc/sing-box/certs"

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

show_banner() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   Sing-Box 一键安装配置+中转脚本 v2.5               ║${NC}"
    echo -e "${CYAN}║   作者: sd87671067 | 博客:   dlmn.lol              ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════╝${NC}"
    echo ""
}

detect_system() {
    [[ -f /etc/os-release ]] && . /etc/os-release || { print_error "无法检测系统"; exit 1; }
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) print_error "不支持的架构: $ARCH"; exit 1 ;;
    esac
}

install_singbox() {
    print_info "检查依赖和 sing-box..."
    
    if ! command -v jq &>/dev/null || ! command -v openssl &>/dev/null; then
        print_info "安装依赖包..."
        apt-get update -qq && apt-get install -y curl wget jq openssl uuid-runtime qrencode >/dev/null 2>&1
    fi
    
    if command -v sing-box &>/dev/null; then
        local version=$(sing-box version 2>&1 | grep -oP 'sing-box version \K[0-9.]+' || echo "unknown")
        print_success "sing-box 已安装 (版本: ${version})"
        return 0
    fi
    
    print_info "下载并安装 sing-box..."
    LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    [[ -z "$LATEST" ]] && LATEST="1.12.0"
    
    print_info "目标版本: ${LATEST}"
    
    wget -q --show-progress -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz" 2>&1
    
    tar -xzf /tmp/sb.tar.gz -C /tmp
    install -Dm755 /tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box ${INSTALL_DIR}/sing-box
    rm -rf /tmp/sb.tar.gz /tmp/sing-box-*
    
    cat > /etc/systemd/system/sing-box.service << EOFSVC
[Unit]
Description=sing-box service
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/sing-box run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOFSVC
    
    systemctl daemon-reload
    systemctl enable sing-box >/dev/null 2>&1
    
    print_success "sing-box 安装完成 (版本: ${LATEST})"
}

gen_cert() {
    mkdir -p ${CERT_DIR}
    openssl genrsa -out ${CERT_DIR}/private.key 2048 2>/dev/null
    openssl req -new -x509 -days 36500 -key ${CERT_DIR}/private.key -out ${CERT_DIR}/cert.pem \
        -subj "/C=US/ST=California/L=Cupertino/O=Apple Inc./CN=itunes.apple.com" 2>/dev/null
    print_success "证书生成完成（itunes.apple.com，有效期100年）"
}

gen_keys() {
    print_info "生成密钥和 UUID..."
    KEYS=$(${INSTALL_DIR}/sing-box generate reality-keypair 2>/dev/null)
    REALITY_PRIVATE=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
    REALITY_PUBLIC=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
    UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
    SHORT_ID=$(openssl rand -hex 8)
    HY2_PASSWORD=$(openssl rand -base64 16)
    SS_PASSWORD=$(openssl rand -base64 32)
    SHADOWTLS_PASSWORD=$(openssl rand -hex 16)
    ANYTLS_PASSWORD=$(openssl rand -base64 16)
    SOCKS_USER="user_$(openssl rand -hex 4)"
    SOCKS_PASS=$(openssl rand -base64 12)
    print_success "密钥生成完成"
}

get_ip() {
    print_info "获取服务器 IP..."
    SERVER_IP=$(curl -s4m5 ifconfig.me || curl -s4m5 api.ipify.org || curl -s4m5 ip.sb)
    [[ -z "$SERVER_IP" ]] && { print_error "无法获取IP"; exit 1; }
    print_success "服务器 IP: ${SERVER_IP}"
}

setup_reality() {
    echo ""
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    read -p "伪装域名 [itunes.apple.com]: " SNI
    SNI=${SNI:-itunes.apple.com}
    
    print_info "生成配置文件..."
    
    INBOUND_JSON='{
  "type": "vless",
  "tag": "vless-in",
  "listen": "::",
  "listen_port": '${PORT}',
  "users": [{"uuid": "'${UUID}'", "flow": "xtls-rprx-vision"}],
  "tls": {
    "enabled": true,
    "server_name": "'${SNI}'",
    "reality": {
      "enabled": true,
      "handshake": {"server": "'${SNI}'", "server_port": 443},
      "private_key": "'${REALITY_PRIVATE}'",
      "short_id": ["'${SHORT_ID}'"]
    }
  }
}'
    
    LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#${AUTHOR_BLOG}"
    
    # Loon配置格式
    LINK_LOON="${AUTHOR_BLOG} = VLESS,${SERVER_IP},${PORT},\"${UUID}\",transport=tcp,flow=xtls-rprx-vision,public-key=\"${REALITY_PUBLIC}\",short-id=${SHORT_ID},udp=true,block-quic=true,over-tls=true,sni=${SNI},ip-mode=prefer-v4"
    
    PROTO="Reality"
    EXTRA_INFO="UUID: ${UUID}\nPublic Key: ${REALITY_PUBLIC}\nShort ID: ${SHORT_ID}\nSNI: ${SNI}"
    print_success "Reality 配置完成"
}

setup_hysteria2() {
    echo ""
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    
    print_info "生成自签证书..."
    gen_cert
    
    print_info "生成配置文件..."
    
    INBOUND_JSON='{
  "type": "hysteria2",
  "tag": "hy2-in",
  "listen": "::",
  "listen_port": '${PORT}',
  "users": [{"password": "'${HY2_PASSWORD}'"}],
  "tls": {
    "enabled": true,
    "alpn": ["h3"],
    "certificate_path": "'${CERT_DIR}'/cert.pem",
    "key_path": "'${CERT_DIR}'/private.key"
  }
}'
    
    LINK="hysteria2://${HY2_PASSWORD}@${SERVER_IP}:${PORT}?insecure=1&sni=itunes.apple.com#${AUTHOR_BLOG}"
    PROTO="Hysteria2"
    EXTRA_INFO="密码: ${HY2_PASSWORD}\n证书: 自签证书(itunes.apple.com)"
    print_success "Hysteria2 配置完成"
}

setup_socks5() {
    echo ""
    read -p "监听端口 [1080]: " PORT
    PORT=${PORT:-1080}
    read -p "是否启用认证? [Y/n]: " ENABLE_AUTH
    ENABLE_AUTH=${ENABLE_AUTH:-Y}
    
    print_info "生成配置文件..."
    
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        INBOUND_JSON='{
  "type": "socks",
  "tag": "socks-in",
  "listen": "::",
  "listen_port": '${PORT}',
  "users": [{"username": "'${SOCKS_USER}'", "password": "'${SOCKS_PASS}'"}],
  "udp": true
}'
        LINK="socks5://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${PORT}#${AUTHOR_BLOG}"
        EXTRA_INFO="用户名: ${SOCKS_USER}\n密码: ${SOCKS_PASS}"
    else
        INBOUND_JSON='{
  "type": "socks",
  "tag": "socks-in",
  "listen": "::",
  "listen_port": '${PORT}',
  "udp": true
}'
        LINK="socks5://${SERVER_IP}:${PORT}#${AUTHOR_BLOG}"
        EXTRA_INFO="无认证"
    fi
    
    PROTO="SOCKS5"
    print_success "SOCKS5 配置完成"
}

setup_shadowtls() {
    echo ""
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    read -p "伪装域名 [www.bing.com]: " SNI
    SNI=${SNI:-www.bing.com}
    
    print_info "生成配置文件..."
    print_warning "ShadowTLS 通过伪装真实域名的TLS握手工作"
    
    INBOUND_JSON='{
  "type": "shadowtls",
  "tag": "shadowtls-in",
  "listen": "::",
  "listen_port": '${PORT}',
  "version": 3,
  "users": [{"password": "'${SHADOWTLS_PASSWORD}'"}],
  "handshake": {
    "server": "'${SNI}'",
    "server_port": 443
  },
  "strict_mode": true,
  "detour": "shadowsocks-in"
},
{
  "type": "shadowsocks",
  "tag": "shadowsocks-in",
  "listen": "127.0.0.1",
  "method": "2022-blake3-aes-128-gcm",
  "password": "'${SS_PASSWORD}'"
}'
    
    local ss_userinfo=$(echo -n "2022-blake3-aes-128-gcm:${SS_PASSWORD}" | base64 -w0)
    local plugin_json="{\"version\":\"3\",\"host\":\"${SNI}\",\"password\":\"${SHADOWTLS_PASSWORD}\"}"
    local plugin_base64=$(echo -n "$plugin_json" | base64 -w0)
    
    LINK="ss://${ss_userinfo}@${SERVER_IP}:${PORT}?shadow-tls=${plugin_base64}#${AUTHOR_BLOG}"
    
    PROTO="ShadowTLS v3"
    EXTRA_INFO="Shadowsocks方法: 2022-blake3-aes-128-gcm\nShadowsocks密码: ${SS_PASSWORD}\nShadowTLS密码: ${SHADOWTLS_PASSWORD}\n伪装域名: ${SNI}\n\n说明: 可直接复制链接导入 Shadowrocket"
    print_success "ShadowTLS v3 配置完成"
}

setup_https() {
    echo ""
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    
    print_info "生成自签证书..."
    gen_cert
    
    print_info "生成配置文件..."
    
    INBOUND_JSON='{
  "type": "vless",
  "tag": "vless-tls-in",
  "listen": "::",
  "listen_port": '${PORT}',
  "users": [{"uuid": "'${UUID}'"}],
  "tls": {
    "enabled": true,
    "server_name": "itunes.apple.com",
    "certificate_path": "'${CERT_DIR}'/cert.pem",
    "key_path": "'${CERT_DIR}'/private.key"
  }
}'
    
    LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&security=tls&sni=itunes.apple.com&type=tcp&allowInsecure=1#${AUTHOR_BLOG}"
    PROTO="HTTPS"
    EXTRA_INFO="UUID: ${UUID}\n证书: 自签证书(itunes.apple.com)"
    print_success "HTTPS 配置完成"
}

setup_anytls() {
    echo ""
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    
    print_info "生成自签证书..."
    gen_cert
    
    print_info "生成证书指纹..."
    CERT_SHA256=$(openssl x509 -fingerprint -noout -sha256 -in ${CERT_DIR}/cert.pem | awk -F '=' '{print $NF}')
    
    print_info "生成配置文件..."
    
    INBOUND_JSON='{
  "type": "anytls",
  "tag": "anytls-in",
  "listen": "::",
  "listen_port": '${PORT}',
  "users": [{"password": "'${ANYTLS_PASSWORD}'"}],
  "padding_scheme": [],
  "tls": {
    "enabled": true,
    "certificate_path": "'${CERT_DIR}'/cert.pem",
    "key_path": "'${CERT_DIR}'/private.key"
  }
}'
    
    LINK_SHADOWROCKET="anytls://${ANYTLS_PASSWORD}@${SERVER_IP}:${PORT}?udp=1&hpkp=${CERT_SHA256}#${AUTHOR_BLOG}"
    LINK_V2RAYN="anytls://${ANYTLS_PASSWORD}@${SERVER_IP}:${PORT}?security=tls&fp=firefox&insecure=1&type=tcp#${AUTHOR_BLOG}"
    
    LINK="${LINK_SHADOWROCKET}"
    PROTO="AnyTLS"
    
    EXTRA_INFO="密码: ${ANYTLS_PASSWORD}\n证书: 自签证书(itunes.apple.com)\n证书指纹(SHA256): ${CERT_SHA256}\n\n✨ 支持的客户端:\n  • Shadowrocket / V2rayN - 直接导入链接"
    
    print_success "AnyTLS 配置完成（已生成Shadowrocket和V2rayN格式）"
}

parse_socks_link() {
    local link="$1"
    
    # 检查是否是 base64 编码格式 (socks://base64)
    if [[ "$link" =~ ^socks://([A-Za-z0-9+/=]+) ]]; then
        print_info "检测到 base64 编码的 SOCKS 链接，正在解码..."
        local base64_part="${BASH_REMATCH[1]}"
        # 解码 base64
        local decoded=$(echo "$base64_part" | base64 -d 2>/dev/null)
        if [[ -z "$decoded" ]]; then
            print_error "base64 解码失败"
            RELAY_JSON=''
            OUTBOUND_TAG="direct"
            return
        fi
        # 解码后格式: username:password@server:port
        link="socks5://${decoded}"
    fi
    
    # 移除 socks:// 或 socks5:// 前缀
    local data=$(echo "$link" | sed 's|socks5\?://||')
    # 移除 URL 参数
    data=$(echo "$data" | cut -d'?' -f1)
    
    if [[ "$data" =~ @ ]]; then
        local userpass=$(echo "$data" | cut -d'@' -f1)
        local username=$(echo "$userpass" | cut -d':' -f1)
        local password=$(echo "$userpass" | cut -d':' -f2)
        local server_port=$(echo "$data" | cut -d'@' -f2)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2 | cut -d'#' -f1 | cut -d'?' -f1)
        
        RELAY_JSON='{
  "type": "socks",
  "tag": "relay",
  "server": "'${server}'",
  "server_port": '${port}',
  "version": "5",
  "username": "'${username}'",
  "password": "'${password}'"
}'
    else
        local server=$(echo "$data" | cut -d':' -f1)
        local port=$(echo "$data" | cut -d':' -f2 | cut -d'#' -f1 | cut -d'?' -f1)
        
        RELAY_JSON='{
  "type": "socks",
  "tag": "relay",
  "server": "'${server}'",
  "server_port": '${port}',
  "version": "5"
}'
    fi
    
    OUTBOUND_TAG="relay"
    print_success "SOCKS5 中转配置解析完成"
}

parse_http_link() {
    local link="$1"
    local protocol=$(echo "$link" | cut -d':' -f1)
    local data=$(echo "$link" | sed 's|https\?://||')
    
    local tls="false"
    [[ "$protocol" == "https" ]] && tls="true"
    
    if [[ "$data" =~ @ ]]; then
        local userpass=$(echo "$data" | cut -d'@' -f1)
        local username=$(echo "$userpass" | cut -d':' -f1)
        local password=$(echo "$userpass" | cut -d':' -f2)
        local server_port=$(echo "$data" | cut -d'@' -f2)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2 | cut -d'/' -f1 | cut -d'#' -f1 | cut -d'?' -f1)
        
        RELAY_JSON='{
  "type": "http",
  "tag": "relay",
  "server": "'${server}'",
  "server_port": '${port}',
  "username": "'${username}'",
  "password": "'${password}'",
  "tls": {"enabled": '${tls}'}
}'
    else
        local server=$(echo "$data" | cut -d':' -f1)
        local port=$(echo "$data" | cut -d':' -f2 | cut -d'/' -f1 | cut -d'#' -f1 | cut -d'?' -f1)
        
        RELAY_JSON='{
  "type": "http",
  "tag": "relay",
  "server": "'${server}'",
  "server_port": '${port}',
  "tls": {"enabled": '${tls}'}
}'
    fi
    
    OUTBOUND_TAG="relay"
    print_success "HTTP(S) 中转配置解析完成"
}

setup_relay() {
    echo ""
    echo -e "${YELLOW}是否配置中转? [y/N]:${NC}"
    read -p "> " USE_RELAY
    USE_RELAY=${USE_RELAY:-N}
    
    if [[ ! "$USE_RELAY" =~ ^[Yy]$ ]]; then
        RELAY_JSON=''
        OUTBOUND_TAG="direct"
        print_info "不使用中转，直连模式"
        return
    fi
    
    echo ""
    echo -e "${CYAN}支持的中转格式:${NC}"
    echo -e "  ${GREEN}SOCKS5:${NC}"
    echo -e "    socks5://user:pass@server:port"
    echo -e "    socks5://server:port"
    echo -e "    socks://base64编码"
    echo ""
    echo -e "  ${GREEN}HTTP/HTTPS:${NC}"
    echo -e "    http://user:pass@server:port"
    echo -e "    https://server:port"
    echo ""
    read -p "粘贴中转链接: " RELAY_LINK
    
    if [[ -z "$RELAY_LINK" ]]; then
        RELAY_JSON=''
        OUTBOUND_TAG="direct"
        print_warning "未提供链接，使用直连"
        return
    fi
    
    if [[ "$RELAY_LINK" =~ ^socks ]]; then
        parse_socks_link "$RELAY_LINK"
    elif [[ "$RELAY_LINK" =~ ^https? ]]; then
        parse_http_link "$RELAY_LINK"
    else
        print_error "不支持的链接格式"
        RELAY_JSON=''
        OUTBOUND_TAG="direct"
        return
    fi
}

show_menu() {
    show_banner
    echo -e "${YELLOW}请选择协议:${NC}"
    echo ""
    echo -e "${GREEN}[1]${NC} VlessReality ${YELLOW}(⭐ 强烈推荐)${NC}"
    echo -e "    ${CYAN}→ 抗审查最强，伪装真实TLS，无需证书${NC}"
    echo ""
    echo -e "${GREEN}[2]${NC} Hysteria2"
    echo -e "    ${CYAN}→ 基于QUIC，速度快，垃圾线路专用，适合高延迟网络${NC}"
    echo ""
    echo -e "${GREEN}[3]${NC} SOCKS5"
    echo -e "    ${CYAN}→ 适合中转的代理协议，只能在落地机上用${NC}"
    echo ""
    echo -e "${GREEN}[4]${NC} ShadowTLS v3"
    echo -e "    ${CYAN}→ TLS流量伪装，支持 Shadowrocket${NC}"
    echo ""
    echo -e "${GREEN}[5]${NC} HTTPS"
    echo -e "    ${CYAN}→ 标准HTTPS，可过CDN${NC}"
    echo ""
    echo -e "${GREEN}[6]${NC} AnyTLS ${YELLOW}"
    echo -e "    ${CYAN}→ 通用TLS协议，支持多客户端自动配置${NC}"
    echo ""
    read -p "选择 [1-6]: " choice
    
    case $choice in
        1) setup_reality ;;
        2) setup_hysteria2 ;;
        3) setup_socks5 ;;
        4) setup_shadowtls ;;
        5) setup_https ;;
        6) setup_anytls ;;
        *) print_error "无效选项"; exit 1 ;;
    esac
}

generate_config() {
    print_info "生成最终配置文件..."
    
    local outbounds='[{"type": "direct", "tag": "direct"}]'
    
    if [[ -n "$RELAY_JSON" ]]; then
        outbounds='['${RELAY_JSON}', {"type": "direct", "tag": "direct"}]'
    fi
    
    cat > ${CONFIG_FILE} << EOFCONFIG
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [${INBOUND_JSON}],
  "outbounds": ${outbounds},
  "route": {
    "final": "${OUTBOUND_TAG}"
  }
}
EOFCONFIG
    
    print_success "配置文件生成完成"
}

start_svc() {
    print_info "验证配置文件..."
    
    if ! ${INSTALL_DIR}/sing-box check -c ${CONFIG_FILE} 2>&1; then
        print_error "配置验证失败"
        cat ${CONFIG_FILE}
        exit 1
    fi
    
    print_info "启动 sing-box 服务..."
    systemctl restart sing-box
    sleep 2
    
    if systemctl is-active --quiet sing-box; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败，查看日志："
        journalctl -u sing-box -n 10 --no-pager
        exit 1
    fi
}

show_result() {
    clear
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                       ║${NC}"
    echo -e "${CYAN}║               ${GREEN}🎉 配置完成！${CYAN}                          ║${NC}"
    echo -e "${CYAN}║                                                       ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}服务器信息:${NC}"
    echo -e "  协议: ${GREEN}${PROTO}${NC}"
    echo -e "  IP: ${GREEN}${SERVER_IP}${NC}"
    echo -e "  端口: ${GREEN}${PORT}${NC}"
    echo -e "  出站: ${GREEN}${OUTBOUND_TAG}${NC}"
    echo ""
    
    if [[ -n "$EXTRA_INFO" ]]; then
        echo -e "${YELLOW}协议详情:${NC}"
        echo -e "$EXTRA_INFO" | sed 's/^/  /'
        echo ""
    fi
    
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
    
    if [[ "$PROTO" == "AnyTLS" ]]; then
        echo -e "${GREEN}📋 Shadowrocket 剪贴板链接:${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo ""
        echo -e "${YELLOW}${LINK}${NC}"
        echo ""
        
        if command -v qrencode &>/dev/null; then
            echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
            echo -e "${GREEN}📱 二维码 (Shadowrocket):${NC}"
            echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
            echo ""
            qrencode -t ANSIUTF8 -s 1 -m 1 "${LINK}"
            echo ""
        fi
        
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo -e "${GREEN}📋 V2rayN 专用链接:${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo ""
        echo -e "${YELLOW}${LINK_V2RAYN}${NC}"
        echo ""
    
    elif [[ "$PROTO" == "Reality" ]]; then
        echo -e "${GREEN}📋 剪贴板链接:${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo ""
        echo -e "${YELLOW}${LINK}${NC}"
        echo ""
        
        if command -v qrencode &>/dev/null; then
            echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
            echo -e "${GREEN}📱 二维码:${NC}"
            echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
            echo ""
            qrencode -t ANSIUTF8 -s 1 -m 1 "${LINK}"
            echo ""
        fi
        
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo -e "${GREEN}📋 Loon iOS 配置:${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo ""
        echo -e "${YELLOW}${LINK_LOON}${NC}"
        echo ""
    else
        echo -e "${GREEN}📋 剪贴板链接:${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo ""
        echo -e "${YELLOW}${LINK}${NC}"
        echo ""
        
        if command -v qrencode &>/dev/null; then
            echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
            echo -e "${GREEN}📱 二维码:${NC}"
            echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
            echo ""
            qrencode -t ANSIUTF8 -s 1 -m 1 "${LINK}"
            echo ""
        fi
    fi
    
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${YELLOW}📱 使用方法:${NC}"
    if [[ "$PROTO" == "AnyTLS" ]]; then
        echo -e "  ${GREEN}Shadowrocket / V2rayN:${NC}"
        echo -e "    1. 复制对应客户端的链接"
        echo -e "    2. 打开客户端，从剪贴板导入"
    elif [[ "$PROTO" == "Reality" ]]; then
        echo -e "  ${GREEN}通用客户端:${NC}"
        echo -e "    1. 复制链接或扫描二维码"
        echo -e "    2. 打开客户端导入配置"
        echo ""
        echo -e "  ${GREEN}Loon (iOS):${NC}"
        echo -e "    1. 复制上方 Loon 配置"
        echo -e "    2. 粘贴到 Loon配置文件中 的 [Proxy] 部分"
        echo -e "    3. 或者从vless开始复制，然后添加节点，从剪贴板导入"
    else
        echo -e "  1. 复制上面的链接或扫描二维码"
        echo -e "  2. 打开客户端导入配置"
    fi
    echo ""
    echo -e "${YELLOW}⚙️  服务管理:${NC}"
    echo -e "  查看状态: ${CYAN}systemctl status sing-box${NC}"
    echo -e "  查看日志: ${CYAN}journalctl -u sing-box -f${NC}"
    echo -e "  重启服务: ${CYAN}systemctl restart sing-box${NC}"
    echo -e "  停止服务: ${CYAN}systemctl stop sing-box${NC}"
    echo ""
    echo -e "${GREEN}💡 博客教程: ${YELLOW}https://${AUTHOR_BLOG}${NC}"
    echo -e "${GREEN}📧 脚本作者: ${YELLOW}sd87671067${NC}"
    echo ""
}

main() {
    [[ $EUID -ne 0 ]] && { print_error "需要 root 权限"; exit 1; }
    
    detect_system
    print_success "系统: ${OS} (${ARCH})"
    
    install_singbox
    mkdir -p /etc/sing-box
    gen_keys
    get_ip
    
    show_menu
    setup_relay
    generate_config
    start_svc
    show_result
}

main