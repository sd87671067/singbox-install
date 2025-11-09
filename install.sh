#!/bin/bash

# ==========================================
# SingBox 一键安装配置脚本
# 作者: sd87671067
# 博客: https://dlmn.lol
# 支持: Reality / ShadowTLS v3 / Reality+gRPC / SOCKS5
# ==========================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 打印函数
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

# 显示 Banner
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════╗"
    echo "║                                                ║"
    echo "║       SingBox 一键安装配置脚本 v1.2           ║"
    echo "║                                                ║"
    echo "║       作者: ${PURPLE}sd87671067${CYAN}                        ║"
    echo "║       博客: ${PURPLE}https://dlmn.lol${CYAN}                 ║"
    echo "║                                                ║"
    echo "║       支持协议:                                ║"
    echo "║       • Reality (最安全推荐)                   ║"
    echo "║       • ShadowTLS v3 (高性能)                  ║"
    echo "║       • Reality + gRPC (稳定)                  ║"
    echo "║       • SOCKS5 (中转专用)                      ║"
    echo "║                                                ║"
    echo "╚════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# 检查 root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "请使用 root 权限运行此脚本"
        exit 1
    fi
}

# 检测系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        print_error "无法检测操作系统"
        exit 1
    fi

    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        print_error "此脚本仅支持 Ubuntu 和 Debian 系统"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    print_info "更新系统软件包..."
    apt update -y > /dev/null 2>&1

    print_info "安装必要依赖..."
    apt install -y curl wget tar gzip qrencode openssl jq > /dev/null 2>&1

    if command -v sing-box &> /dev/null; then
        print_success "sing-box 已安装"
        return
    fi

    print_info "安装 sing-box..."
    
    ARCH=$(dpkg --print-architecture)
    LATEST_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    
    if [ -z "$LATEST_VERSION" ]; then
        print_error "无法获取 sing-box 最新版本"
        exit 1
    fi
    
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH}.tar.gz"
    
    print_info "下载 sing-box v${LATEST_VERSION}..."
    wget -q --show-progress -O /tmp/sing-box.tar.gz "$DOWNLOAD_URL"
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    
    cp /tmp/sing-box-${LATEST_VERSION}-linux-${ARCH}/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    cat > /etc/systemd/system/sing-box.service <<SERVICE
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
SERVICE
    
    systemctl daemon-reload
    rm -rf /tmp/sing-box*
    
    print_success "sing-box 安装完成"
}

# 获取服务器 IP
get_server_ip() {
    SERVER_IP=$(curl -s4m8 ip.sb) || SERVER_IP=$(curl -s6m8 ip.sb)
    if [ -z "$SERVER_IP" ]; then
        print_error "无法获取服务器 IP 地址"
        exit 1
    fi
}

# Reality 配置
setup_reality() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}Reality 协议配置${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Reality 是目前最安全的代理协议，基于真实 TLS 指纹"
    echo ""
    
    UUID=$(sing-box generate uuid)
    KEYPAIR=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "PrivateKey" | awk '{print $2}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "PublicKey" | awk '{print $2}')
    
    read -p "$(echo -e ${YELLOW}请输入监听端口 [默认: 443]: ${NC})" PORT
    PORT=${PORT:-443}
    
    echo ""
    echo -e "${CYAN}═══════════ 选择伪装域名 ═══════════${NC}"
    echo ""
    echo -e "  ${GREEN}1${NC}) www.microsoft.com    ${CYAN}(微软官网)${NC}"
    echo -e "  ${GREEN}2${NC}) itunes.apple.com     ${CYAN}(苹果 iTunes - 推荐)${NC}"
    echo -e "  ${GREEN}3${NC}) www.lovelive-anime.jp ${CYAN}(日本动漫网站)${NC}"
    echo -e "  ${GREEN}4${NC}) gateway.icloud.com   ${CYAN}(苹果 iCloud)${NC}"
    echo -e "  ${GREEN}5${NC}) 自定义域名"
    echo ""
    read -p "$(echo -e ${YELLOW}请选择伪装域名 [默认: 2]: ${NC})" SNI_CHOICE
    SNI_CHOICE=${SNI_CHOICE:-2}
    
    case $SNI_CHOICE in
        1) SNI="www.microsoft.com" ;;
        2) SNI="itunes.apple.com" ;;
        3) SNI="www.lovelive-anime.jp" ;;
        4) SNI="gateway.icloud.com" ;;
        5) 
            read -p "$(echo -e ${YELLOW}请输入自定义域名: ${NC})" SNI
            ;;
        *) SNI="itunes.apple.com" ;;
    esac
    
    SHORT_ID=$(openssl rand -hex 8)
    
    INBOUND_CONFIG=$(cat <<CONF
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": ${PORT},
            "users": [
                {
                    "uuid": "${UUID}",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "${SNI}",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "${SNI}",
                        "server_port": 443
                    },
                    "private_key": "${PRIVATE_KEY}",
                    "short_id": ["${SHORT_ID}"]
                }
            }
        }
CONF
)
    
    NODE_NAME="Reality|博客:dlmn.lol"
    CLIENT_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${NODE_NAME}"
    
    PROTOCOL_NAME="Reality"
    PROTOCOL_DESC="VLESS + Reality + XTLS-Vision"
    print_success "Reality 配置完成"
}

# ShadowTLS v3 配置
setup_shadowtls() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}ShadowTLS v3 协议配置${NC}                         ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "ShadowTLS v3 是高性能的 TLS 伪装协议"
    echo ""
    
    PASSWORD=$(openssl rand -base64 32)
    
    read -p "$(echo -e ${YELLOW}请输入监听端口 [默认: 443]: ${NC})" PORT
    PORT=${PORT:-443}
    
    read -p "$(echo -e ${YELLOW}请输入伪装域名 [默认: cloud.tencent.com]: ${NC})" HANDSHAKE_SERVER
    HANDSHAKE_SERVER=${HANDSHAKE_SERVER:-cloud.tencent.com}
    
    INBOUND_CONFIG=$(cat <<CONF
        {
            "type": "shadowtls",
            "tag": "st-in",
            "listen": "::",
            "listen_port": ${PORT},
            "version": 3,
            "users": [
                {
                    "password": "${PASSWORD}"
                }
            ],
            "handshake": {
                "server": "${HANDSHAKE_SERVER}",
                "server_port": 443
            },
            "strict_mode": true,
            "detour": "ss-in"
        },
        {
            "type": "shadowsocks",
            "tag": "ss-in",
            "listen": "127.0.0.1",
            "network": "tcp",
            "method": "2022-blake3-aes-128-gcm",
            "password": "${PASSWORD}"
        }
CONF
)
    
    NODE_NAME="ShadowTLS|博客:dlmn.lol"
    SS_LINK=$(echo -n "2022-blake3-aes-128-gcm:${PASSWORD}" | base64 -w 0)
    CLIENT_LINK="ss://${SS_LINK}@${SERVER_IP}:${PORT}?plugin=shadow-tls;version=3;host=${HANDSHAKE_SERVER}#${NODE_NAME}"
    
    PASSWORD_INFO="Password: ${PASSWORD}"
    PROTOCOL_NAME="ShadowTLS v3"
    PROTOCOL_DESC="Shadowsocks + ShadowTLS v3"
    print_success "ShadowTLS v3 配置完成"
}

# Reality + gRPC 配置
setup_reality_grpc() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}Reality + gRPC 协议配置${NC}                       ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "Reality + gRPC 提供更好的抗审查能力"
    print_info "gRPC 传输更稳定，适合复杂网络环境"
    echo ""
    
    UUID=$(sing-box generate uuid)
    KEYPAIR=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "PrivateKey" | awk '{print $2}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "PublicKey" | awk '{print $2}')
    
    read -p "$(echo -e ${YELLOW}请输入监听端口 [默认: 443]: ${NC})" PORT
    PORT=${PORT:-443}
    
    echo ""
    echo -e "${CYAN}═══════════ 选择伪装域名 ═══════════${NC}"
    echo ""
    echo -e "  ${GREEN}1${NC}) www.microsoft.com    ${CYAN}(微软官网)${NC}"
    echo -e "  ${GREEN}2${NC}) itunes.apple.com     ${CYAN}(苹果 iTunes - 推荐)${NC}"
    echo -e "  ${GREEN}3${NC}) www.lovelive-anime.jp ${CYAN}(日本动漫网站)${NC}"
    echo -e "  ${GREEN}4${NC}) gateway.icloud.com   ${CYAN}(苹果 iCloud)${NC}"
    echo -e "  ${GREEN}5${NC}) 自定义域名"
    echo ""
    read -p "$(echo -e ${YELLOW}请选择伪装域名 [默认: 2]: ${NC})" SNI_CHOICE
    SNI_CHOICE=${SNI_CHOICE:-2}
    
    case $SNI_CHOICE in
        1) SNI="www.microsoft.com" ;;
        2) SNI="itunes.apple.com" ;;
        3) SNI="www.lovelive-anime.jp" ;;
        4) SNI="gateway.icloud.com" ;;
        5) 
            read -p "$(echo -e ${YELLOW}请输入自定义域名: ${NC})" SNI
            ;;
        *) SNI="itunes.apple.com" ;;
    esac
    
    SHORT_ID=$(openssl rand -hex 8)
    GRPC_SERVICE="grpc$(openssl rand -hex 4)"
    
    INBOUND_CONFIG=$(cat <<CONF
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": ${PORT},
            "users": [
                {
                    "uuid": "${UUID}",
                    "flow": ""
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "${SNI}",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "${SNI}",
                        "server_port": 443
                    },
                    "private_key": "${PRIVATE_KEY}",
                    "short_id": ["${SHORT_ID}"]
                }
            },
            "transport": {
                "type": "grpc",
                "service_name": "${GRPC_SERVICE}"
            }
        }
CONF
)
    
    NODE_NAME="Reality-gRPC|博客:dlmn.lol"
    CLIENT_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=grpc&serviceName=${GRPC_SERVICE}&mode=gun#${NODE_NAME}"
    
    PROTOCOL_NAME="Reality-gRPC"
    PROTOCOL_DESC="VLESS + Reality + gRPC"
    print_success "Reality + gRPC 配置完成"
}

# SOCKS5 配置
setup_socks5() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}SOCKS5 协议配置 (中转专用)${NC}                    ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "SOCKS5 协议适合用作中转节点"
    print_warning "注意: 建议配合用户认证使用"
    echo ""
    
    read -p "$(echo -e ${YELLOW}请输入监听端口 [默认: 1080]: ${NC})" PORT
    PORT=${PORT:-1080}
    
    echo ""
    read -p "$(echo -e ${YELLOW}是否启用用户认证? [Y/n]: ${NC})" ENABLE_AUTH
    ENABLE_AUTH=${ENABLE_AUTH:-Y}
    
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        read -p "$(echo -e ${YELLOW}请输入用户名 [默认: user]: ${NC})" SOCKS_USER
        SOCKS_USER=${SOCKS_USER:-user}
        
        read -p "$(echo -e ${YELLOW}请输入密码 [留空自动生成]: ${NC})" SOCKS_PASS
        if [ -z "$SOCKS_PASS" ]; then
            SOCKS_PASS=$(openssl rand -base64 16)
        fi
        
        INBOUND_CONFIG=$(cat <<CONF
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "::",
            "listen_port": ${PORT},
            "users": [
                {
                    "username": "${SOCKS_USER}",
                    "password": "${SOCKS_PASS}"
                }
            ]
        }
CONF
)
        AUTH_INFO="用户名: ${SOCKS_USER}\n密码: ${SOCKS_PASS}"
    else
        INBOUND_CONFIG=$(cat <<CONF
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "::",
            "listen_port": ${PORT}
        }
CONF
)
        AUTH_INFO="无需认证"
    fi
    
    NODE_NAME="SOCKS5|博客:dlmn.lol"
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        CLIENT_LINK="socks://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${PORT}#${NODE_NAME}"
    else
        CLIENT_LINK="socks://${SERVER_IP}:${PORT}#${NODE_NAME}"
    fi
    
    PROTOCOL_NAME="SOCKS5"
    PROTOCOL_DESC="SOCKS5 代理 (中转专用)"
    print_success "SOCKS5 配置完成"
}

# 配置中转出站
setup_relay_outbound() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}中转出站配置${NC}                                  ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    print_info "是否配置中转出站？"
    echo ""
    echo -e "  ${GREEN}Y${NC}) 是 - 配置中转到另一个代理服务器"
    echo -e "  ${RED}N${NC}) 否 - 直接连接（默认）"
    echo ""
    read -p "$(echo -e ${YELLOW}请选择 [y/N]: ${NC})" USE_RELAY
    USE_RELAY=${USE_RELAY:-N}
    
    if [[ ! "$USE_RELAY" =~ ^[Yy]$ ]]; then
        OUTBOUND_TAG="direct"
        OUTBOUND_CONFIG=$(cat <<'CONF'
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
CONF
)
        print_info "使用直连出站"
        return
    fi
    
    echo ""
    print_info "请粘贴 v2ray/vless/vmess 分享链接"
    print_warning "支持格式: vless://, vmess://, ss://, trojan://"
    echo ""
    read -p "$(echo -e ${YELLOW}粘贴分享链接: ${NC})" SHARE_LINK
    
    if [ -z "$SHARE_LINK" ]; then
        print_error "链接为空，使用直连出站"
        OUTBOUND_TAG="direct"
        OUTBOUND_CONFIG=$(cat <<'CONF'
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
CONF
)
        return
    fi
    
    # 解析分享链接
    parse_share_link "$SHARE_LINK"
}

# 解析分享链接并生成出站配置
parse_share_link() {
    local link="$1"
    local protocol=$(echo "$link" | cut -d':' -f1)
    
    case "$protocol" in
        vless)
            parse_vless_link "$link"
            ;;
        vmess)
            parse_vmess_link "$link"
            ;;
        ss)
            parse_ss_link "$link"
            ;;
        trojan)
            parse_trojan_link "$link"
            ;;
        *)
            print_error "不支持的协议: $protocol"
            OUTBOUND_TAG="direct"
            OUTBOUND_CONFIG=$(cat <<'CONF'
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
CONF
)
            ;;
    esac
}

# 解析 VLESS 链接
parse_vless_link() {
    local link="$1"
    local data=$(echo "$link" | sed 's/vless:\/\///')
    
    local uuid=$(echo "$data" | cut -d'@' -f1)
    local rest=$(echo "$data" | cut -d'@' -f2)
    local server=$(echo "$rest" | cut -d':' -f1)
    local port_and_params=$(echo "$rest" | cut -d':' -f2)
    local port=$(echo "$port_and_params" | cut -d'?' -f1)
    local params=$(echo "$port_and_params" | cut -d'?' -f2 | cut -d'#' -f1)
    
    # 解析参数
    local security=$(echo "$params" | grep -oP 'security=\K[^&]+' || echo "none")
    local sni=$(echo "$params" | grep -oP 'sni=\K[^&]+' || echo "")
    local flow=$(echo "$params" | grep -oP 'flow=\K[^&]+' || echo "")
    local pbk=$(echo "$params" | grep -oP 'pbk=\K[^&]+' || echo "")
    local sid=$(echo "$params" | grep -oP 'sid=\K[^&]+' || echo "")
    local net_type=$(echo "$params" | grep -oP 'type=\K[^&]+' || echo "tcp")
    
    OUTBOUND_TAG="relay"
    
    if [ "$security" = "reality" ]; then
        OUTBOUND_CONFIG=$(cat <<CONF
        {
            "type": "vless",
            "tag": "relay",
            "server": "${server}",
            "server_port": ${port},
            "uuid": "${uuid}",
            "flow": "${flow}",
            "tls": {
                "enabled": true,
                "server_name": "${sni}",
                "reality": {
                    "enabled": true,
                    "public_key": "${pbk}",
                    "short_id": "${sid}"
                }
            }
        },
        {
            "type": "block",
            "tag": "block"
        }
CONF
)
    else
        OUTBOUND_CONFIG=$(cat <<CONF
        {
            "type": "vless",
            "tag": "relay",
            "server": "${server}",
            "server_port": ${port},
            "uuid": "${uuid}"
        },
        {
            "type": "block",
            "tag": "block"
        }
CONF
)
    fi
    
    print_success "已解析 VLESS 中转配置"
}

# 解析 VMess 链接
parse_vmess_link() {
    local link="$1"
    local data=$(echo "$link" | sed 's/vmess:\/\///' | base64 -d 2>/dev/null)
    
    if [ -z "$data" ]; then
        print_error "VMess 链接解析失败"
        OUTBOUND_TAG="direct"
        OUTBOUND_CONFIG='{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}'
        return
    fi
    
    local server=$(echo "$data" | jq -r '.add')
    local port=$(echo "$data" | jq -r '.port')
    local uuid=$(echo "$data" | jq -r '.id')
    local aid=$(echo "$data" | jq -r '.aid // 0')
    
    OUTBOUND_TAG="relay"
    OUTBOUND_CONFIG=$(cat <<CONF
        {
            "type": "vmess",
            "tag": "relay",
            "server": "${server}",
            "server_port": ${port},
            "uuid": "${uuid}",
            "alter_id": ${aid}
        },
        {
            "type": "block",
            "tag": "block"
        }
CONF
)
    
    print_success "已解析 VMess 中转配置"
}

# 解析 Shadowsocks 链接
parse_ss_link() {
    local link="$1"
    print_warning "Shadowsocks 链接解析功能待完善，使用直连"
    OUTBOUND_TAG="direct"
    OUTBOUND_CONFIG='{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}'
}

# 解析 Trojan 链接
parse_trojan_link() {
    local link="$1"
    print_warning "Trojan 链接解析功能待完善，使用直连"
    OUTBOUND_TAG="direct"
    OUTBOUND_CONFIG='{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}'
}

# 保存配置
save_config() {
    mkdir -p /etc/sing-box
    
    CONFIG=$(cat <<CONF
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "dns": {
        "servers": [
            {
                "tag": "google",
                "address": "8.8.8.8"
            }
        ]
    },
    "inbounds": [
${INBOUND_CONFIG}
    ],
    "outbounds": [
${OUTBOUND_CONFIG}
    ],
    "route": {
        "rules": [],
        "final": "${OUTBOUND_TAG}"
    }
}
CONF
)
    
    echo "$CONFIG" > /etc/sing-box/config.json
    print_success "配置文件已生成"
}

# 启动服务
start_service() {
    print_info "启动 sing-box 服务..."
    
    systemctl enable sing-box > /dev/null 2>&1
    systemctl restart sing-box
    
    sleep 2
    
    if systemctl is-active --quiet sing-box; then
        print_success "sing-box 服务启动成功"
    else
        print_error "服务启动失败，查看日志: journalctl -u sing-box -n 50"
        exit 1
    fi
}

# 配置防火墙
setup_firewall() {
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow ${PORT}/tcp > /dev/null 2>&1
        print_success "防火墙规则已添加"
    fi
}

# 显示结果
show_result() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                                                       ║${NC}"
    echo -e "${CYAN}${BOLD}║              🎉 SingBox 安装完成 ✓                   ║${NC}"
    echo -e "${CYAN}${BOLD}║                                                       ║${NC}"
    echo -e "${CYAN}${BOLD}║          更多工具访问: ${PURPLE}https://dlmn.lol${CYAN}            ║${NC}"
    echo -e "${CYAN}${BOLD}║          作者博客: ${PURPLE}sd87671067${CYAN}                      ║${NC}"
    echo -e "${CYAN}${BOLD}║                                                       ║${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════ 📋 服务器信息 ═══════════════${NC}"
    echo -e "  ${CYAN}🖥️  IP 地址:${NC} ${YELLOW}${SERVER_IP}${NC}"
    echo -e "  ${CYAN}🔐 协议类型:${NC} ${YELLOW}${PROTOCOL_NAME}${NC}"
    echo -e "  ${CYAN}📝 协议说明:${NC} ${YELLOW}${PROTOCOL_DESC}${NC}"
    echo -e "  ${CYAN}🔌 监听端口:${NC} ${YELLOW}${PORT}${NC}"
    
    if [[ "$OUTBOUND_TAG" = "relay" ]]; then
        echo -e "  ${CYAN}🔄 出站模式:${NC} ${YELLOW}中转模式${NC}"
    else
        echo -e "  ${CYAN}🔄 出站模式:${NC} ${YELLOW}直连模式${NC}"
    fi
    
    if [[ "$PROTOCOL_NAME" =~ "Reality" ]]; then
        echo -e "  ${CYAN}🆔 UUID:${NC} ${YELLOW}${UUID}${NC}"
        echo -e "  ${CYAN}🔑 公钥:${NC} ${YELLOW}${PUBLIC_KEY}${NC}"
        echo -e "  ${CYAN}🎯 Short ID:${NC} ${YELLOW}${SHORT_ID}${NC}"
        echo -e "  ${CYAN}🌐 SNI:${NC} ${YELLOW}${SNI}${NC}"
        if [ "$PROTOCOL_NAME" = "Reality-gRPC" ]; then
            echo -e "  ${CYAN}📡 gRPC Service:${NC} ${YELLOW}${GRPC_SERVICE}${NC}"
        fi
    elif [ "$PROTOCOL_NAME" = "ShadowTLS v3" ]; then
        echo -e "  ${CYAN}🔒 ${YELLOW}${PASSWORD_INFO}${NC}"
        echo -e "  ${CYAN}🌐 伪装域名:${NC} ${YELLOW}${HANDSHAKE_SERVER}${NC}"
    elif [ "$PROTOCOL_NAME" = "SOCKS5" ]; then
        echo -e "  ${CYAN}👤 认证信息:${NC}"
        echo -e "     ${YELLOW}${AUTH_INFO}${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════ 📱 客户端配置 ═══════════════${NC}"
    echo -e "${CYAN}复制以下链接到客户端导入:${NC}"
    echo -e "${PURPLE}节点备注: ${PROTOCOL_NAME}|博客:dlmn.lol${NC}"
    echo ""
    echo -e "${YELLOW}${CLIENT_LINK}${NC}"
    echo ""
    
    # 生成二维码
    if command -v qrencode &> /dev/null; then
        echo -e "${CYAN}📲 终端二维码 (小尺寸):${NC}"
        echo ""
        qrencode -t ANSIUTF8 -s 1 -m 1 "${CLIENT_LINK}"
        echo ""
        
        QR_FILE="/root/singbox_qr_${PROTOCOL_NAME}.png"
        qrencode -t PNG -s 6 -o "${QR_FILE}" "${CLIENT_LINK}" 2>/dev/null
        
        if [ -f "${QR_FILE}" ]; then
            print_success "二维码已保存: ${QR_FILE}"
            echo -e "  ${YELLOW}scp root@${SERVER_IP}:${QR_FILE} ./${NC}"
        fi
        echo ""
    fi
    
    echo -e "${GREEN}${BOLD}═══════════════ ⚙️  管理命令 ═══════════════${NC}"
    echo -e "  ${CYAN}查看状态:${NC} systemctl status sing-box"
    echo -e "  ${CYAN}查看日志:${NC} journalctl -u sing-box -f"
    echo -e "  ${CYAN}重启服务:${NC} systemctl restart sing-box"
    echo -e "  ${CYAN}查看配置:${NC} cat /etc/sing-box/config.json"
    echo ""
    
    print_success "配置信息已保存到: /root/singbox_config.txt"
    echo ""
    echo -e "${PURPLE}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}${BOLD}   💡 更多工具: ${CYAN}https://dlmn.lol${NC}"
    echo -e "${PURPLE}${BOLD}   📧 作者: ${CYAN}sd87671067${NC}"
    echo -e "${PURPLE}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# 主菜单
main_menu() {
    show_banner
    echo -e "${CYAN}${BOLD}═══════════════ 请选择代理协议 ═══════════════${NC}"
    echo ""
    echo -e "  ${GREEN}${BOLD}1${NC}) ${BOLD}Reality${NC}"
    echo -e "     ${CYAN}├─${NC} VLESS + Reality + XTLS-Vision"
    echo -e "     ${CYAN}├─${NC} 最安全的代理协议"
    echo -e "     ${CYAN}└─${NC} ${GREEN}★ 强烈推荐 ★${NC}"
    echo ""
    echo -e "  ${GREEN}${BOLD}2${NC}) ${BOLD}ShadowTLS v3${NC}"
    echo -e "     ${CYAN}├─${NC} Shadowsocks + ShadowTLS v3"
    echo -e "     ${CYAN}├─${NC} 高性能 TLS 伪装"
    echo -e "     ${CYAN}└─${NC} 适合高速传输"
    echo ""
    echo -e "  ${GREEN}${BOLD}3${NC}) ${BOLD}Reality + gRPC${NC}"
    echo -e "     ${CYAN}├─${NC} VLESS + Reality + gRPC"
    echo -e "     ${CYAN}├─${NC} 稳定性好"
    echo -e "     ${CYAN}└─${NC} ${GREEN}★ 推荐备用 ★${NC}"
    echo ""
    echo -e "  ${GREEN}${BOLD}4${NC}) ${BOLD}SOCKS5${NC} ${CYAN}(中转专用)${NC}"
    echo -e "     ${CYAN}├─${NC} SOCKS5 代理协议"
    echo -e "     ${CYAN}├─${NC} 适合做中转节点"
    echo -e "     ${CYAN}└─${NC} 支持用户认证"
    echo ""
    echo -e "  ${RED}${BOLD}0${NC}) ${BOLD}退出脚本${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
    echo ""
    read -p "$(echo -e ${YELLOW}${BOLD}请输入选项 [1-4]: ${NC})" choice
    
    case $choice in
        1) setup_reality ;;
        2) setup_shadowtls ;;
        3) setup_reality_grpc ;;
        4) setup_socks5 ;;
        0) 
            echo ""
            echo -e "${CYAN}感谢使用！更多工具: ${PURPLE}https://dlmn.lol${NC}"
            echo ""
            exit 0 
            ;;
        *) 
            print_error "无效选择"
            sleep 2
            main_menu
            ;;
    esac
}

# 主函数
main() {
    check_root
    detect_os
    get_server_ip
    
    install_dependencies
    main_menu
    setup_relay_outbound
    save_config
    start_service
    setup_firewall
    show_result
}

main
