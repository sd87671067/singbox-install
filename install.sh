#!/bin/bash

# SingBox 一键安装配置脚本
# 支持 Reality / ShadowTLS v3 / AnyTLS
# 作者: sd87671067
# 网站: dlmn.lol
# 日期: 2025-11-09

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 打印函数
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 显示 Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════╗"
    echo "║     SingBox 一键安装配置脚本           ║"
    echo "║     作者: sd87671067                   ║"
    echo "║     网站: ${PURPLE}dlmn.lol${CYAN}                      ║"
    echo "║     支持: Reality/ShadowTLS/AnyTLS     ║"
    echo "╚════════════════════════════════════════╝"
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
    apt install -y curl wget tar gzip qrencode > /dev/null 2>&1

    # 检查 sing-box 是否已安装
    if command -v sing-box &> /dev/null; then
        print_success "sing-box 已安装"
        return
    fi

    # 安装 sing-box
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
    
    # 创建 systemd 服务
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
    print_info "配置 Reality 协议..."
    
    UUID=$(sing-box generate uuid)
    KEYPAIR=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$KEYPAIR" | grep "PrivateKey" | awk '{print $2}')
    PUBLIC_KEY=$(echo "$KEYPAIR" | grep "PublicKey" | awk '{print $2}')
    
    read -p "请输入监听端口 (默认: 443): " PORT
    PORT=${PORT:-443}
    
    echo ""
    echo "请选择伪装域名:"
    echo "1) www.microsoft.com"
    echo "2) itunes.apple.com"
    echo "3) www.lovelive-anime.jp"
    echo "4) gateway.icloud.com"
    echo "5) 自定义"
    read -p "请选择 (默认: 2): " SNI_CHOICE
    SNI_CHOICE=${SNI_CHOICE:-2}
    
    case $SNI_CHOICE in
        1) SNI="www.microsoft.com" ;;
        2) SNI="itunes.apple.com" ;;
        3) SNI="www.lovelive-anime.jp" ;;
        4) SNI="gateway.icloud.com" ;;
        5) read -p "请输入域名: " SNI ;;
        *) SNI="itunes.apple.com" ;;
    esac
    
    SHORT_ID=$(openssl rand -hex 8)
    
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
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "route": {
        "rules": [],
        "final": "direct"
    }
}
CONF
)
    
    NODE_NAME="Reality-${SERVER_IP}|dlmn.lol"
    CLIENT_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${NODE_NAME}"
    
    PROTOCOL_NAME="Reality"
}

# ShadowTLS v3 配置
setup_shadowtls() {
    print_info "配置 ShadowTLS v3 协议..."
    
    PASSWORD=$(openssl rand -base64 32)
    
    read -p "请输入监听端口 (默认: 443): " PORT
    PORT=${PORT:-443}
    
    read -p "请输入伪装域名 (默认: cloud.tencent.com): " HANDSHAKE_SERVER
    HANDSHAKE_SERVER=${HANDSHAKE_SERVER:-cloud.tencent.com}
    
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
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "route": {
        "rules": [],
        "final": "direct"
    }
}
CONF
)
    
    NODE_NAME="ShadowTLS-${SERVER_IP}|dlmn.lol"
    SS_LINK=$(echo -n "2022-blake3-aes-128-gcm:${PASSWORD}" | base64 -w 0)
    CLIENT_LINK="ss://${SS_LINK}@${SERVER_IP}:${PORT}?plugin=shadow-tls;version=3;host=${HANDSHAKE_SERVER}#${NODE_NAME}"
    
    PASSWORD_INFO="Password: ${PASSWORD}"
    PROTOCOL_NAME="ShadowTLS v3"
}

# AnyTLS 配置
setup_anytls() {
    print_info "配置 AnyTLS 协议..."
    print_warning "注意: AnyTLS 是实验性功能"
    
    UUID=$(sing-box generate uuid)
    
    read -p "请输入监听端口 (默认: 443): " PORT
    PORT=${PORT:-443}
    
    read -p "请输入伪装域名 (默认: www.bing.com): " TLS_SERVER
    TLS_SERVER=${TLS_SERVER:-www.bing.com}
    
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
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": ${PORT},
            "users": [
                {
                    "uuid": "${UUID}"
                }
            ],
            "transport": {
                "type": "http",
                "host": ["${TLS_SERVER}"],
                "path": "/"
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "route": {
        "rules": [],
        "final": "direct"
    }
}
CONF
)
    
    NODE_NAME="AnyTLS-${SERVER_IP}|dlmn.lol"
    CLIENT_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&type=http&host=${TLS_SERVER}&path=%2F#${NODE_NAME}"
    
    PROTOCOL_NAME="AnyTLS"
}

# 保存配置
save_config() {
    mkdir -p /etc/sing-box
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
    echo -e "${CYAN}╔════════════════════════════════════════╗"
    echo -e "║         SingBox 安装完成 ✓             ║"
    echo -e "║       更多工具访问: ${PURPLE}dlmn.lol${CYAN}          ║"
    echo -e "╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}═══════════════ 服务器信息 ═══════════════${NC}"
    echo -e "  🖥️  IP 地址: ${YELLOW}${SERVER_IP}${NC}"
    echo -e "  🔐 协议类型: ${YELLOW}${PROTOCOL_NAME}${NC}"
    echo -e "  🔌 监听端口: ${YELLOW}${PORT}${NC}"
    
    if [ "$PROTOCOL_NAME" = "Reality" ]; then
        echo -e "  🆔 UUID: ${YELLOW}${UUID}${NC}"
        echo -e "  🔑 公钥: ${YELLOW}${PUBLIC_KEY}${NC}"
        echo -e "  🎯 Short ID: ${YELLOW}${SHORT_ID}${NC}"
        echo -e "  🌐 SNI: ${YELLOW}${SNI}${NC}"
    elif [ "$PROTOCOL_NAME" = "ShadowTLS v3" ]; then
        echo -e "  🔒 ${YELLOW}${PASSWORD_INFO}${NC}"
        echo -e "  🌐 伪装域名: ${YELLOW}${HANDSHAKE_SERVER}${NC}"
    elif [ "$PROTOCOL_NAME" = "AnyTLS" ]; then
        echo -e "  🆔 UUID: ${YELLOW}${UUID}${NC}"
        echo -e "  🌐 伪装域名: ${YELLOW}${TLS_SERVER}${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}═══════════════ 客户端配置 ═══════════════${NC}"
    echo -e "${CYAN}📱 复制以下链接到 v2rayN 导入:${NC}"
    echo ""
    echo -e "${YELLOW}${CLIENT_LINK}${NC}"
    echo ""
    
    if command -v qrencode &> /dev/null; then
        echo -e "${CYAN}📲 扫描二维码导入:${NC}"
        qrencode -t ANSIUTF8 "${CLIENT_LINK}"
        echo ""
    fi
    
    echo -e "${GREEN}═══════════════ 管理命令 ═══════════════${NC}"
    echo -e "  查看状态: ${CYAN}systemctl status sing-box${NC}"
    echo -e "  查看日志: ${CYAN}journalctl -u sing-box -f${NC}"
    echo -e "  重启服务: ${CYAN}systemctl restart sing-box${NC}"
    echo -e "  停止服务: ${CYAN}systemctl stop sing-box${NC}"
    echo ""
    
    cat > /root/singbox_config.txt <<INFO
════════════════════════════════════════════════════
         SingBox 配置信息
         脚本作者: sd87671067
         官方网站: dlmn.lol
         生成时间: $(date)
════════════════════════════════════════════════════

【服务器信息】
服务器 IP: ${SERVER_IP}
协议类型: ${PROTOCOL_NAME}
监听端口: ${PORT}

$(if [ "$PROTOCOL_NAME" = "Reality" ]; then
    echo "【Reality 配置】"
    echo "UUID: ${UUID}"
    echo "私钥: ${PRIVATE_KEY}"
    echo "公钥: ${PUBLIC_KEY}"
    echo "Short ID: ${SHORT_ID}"
    echo "SNI: ${SNI}"
elif [ "$PROTOCOL_NAME" = "ShadowTLS v3" ]; then
    echo "【ShadowTLS 配置】"
    echo "${PASSWORD_INFO}"
    echo "伪装域名: ${HANDSHAKE_SERVER}"
elif [ "$PROTOCOL_NAME" = "AnyTLS" ]; then
    echo "【AnyTLS 配置】"
    echo "UUID: ${UUID}"
    echo "伪装域名: ${TLS_SERVER}"
fi)

【客户端链接】
${CLIENT_LINK}

【配置文件位置】
/etc/sing-box/config.json

【常用命令】
查看状态: systemctl status sing-box
查看日志: journalctl -u sing-box -f
启动服务: systemctl start sing-box
停止服务: systemctl stop sing-box
重启服务: systemctl restart sing-box

════════════════════════════════════════════════════
更多代理工具和教程，请访问: https://dlmn.lol
════════════════════════════════════════════════════
INFO
    
    print_success "配置信息已保存到: /root/singbox_config.txt"
    echo ""
    echo -e "${PURPLE}════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}   💡 更多工具和教程，请访问: ${CYAN}https://dlmn.lol${NC}"
    echo -e "${PURPLE}════════════════════════════════════════════════════${NC}"
    echo ""
}

# 主菜单
main_menu() {
    show_banner
    echo "请选择要安装的协议:"
    echo ""
    echo "  ${GREEN}1)${NC} Reality ${CYAN}(推荐 - 最安全)${NC}"
    echo "  ${GREEN}2)${NC} ShadowTLS v3 ${CYAN}(高性能)${NC}"
    echo "  ${GREEN}3)${NC} AnyTLS ${YELLOW}(实验性)${NC}"
    echo "  ${RED}0)${NC} 退出脚本"
    echo ""
    read -p "请输入选项 [1-3]: " choice
    
    case $choice in
        1) setup_reality ;;
        2) setup_shadowtls ;;
        3) setup_anytls ;;
        0) 
            echo -e "${CYAN}感谢使用！访问 dlmn.lol 获取更多工具${NC}"
            exit 0 
            ;;
        *) 
            print_error "无效选择"
            exit 1
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
    save_config
    start_service
    setup_firewall
    show_result
}

main
