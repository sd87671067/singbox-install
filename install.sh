#!/bin/bash

# ==========================================
# SingBox 一键安装配置脚本
# 作者: sd87671067
# 博客: https://dlmn.lol
# 支持: Reality / ShadowTLS v3 / AnyTLS
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
    echo "║       SingBox 一键安装配置脚本 v1.0           ║"
    echo "║                                                ║"
    echo "║       作者: ${PURPLE}sd87671067${CYAN}                        ║"
    echo "║       博客: ${PURPLE}https://dlmn.lol${CYAN}                 ║"
    echo "║                                                ║"
    echo "║       支持协议:                                ║"
    echo "║       • Reality (最安全推荐)                   ║"
    echo "║       • ShadowTLS v3 (高性能)                  ║"
    echo "║       • AnyTLS (实验性)                        ║"
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
    apt install -y curl wget tar gzip qrencode > /dev/null 2>&1

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
    
    NODE_NAME="Reality|博客:dlmn.lol"
    CLIENT_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${NODE_NAME}"
    
    PROTOCOL_NAME="Reality"
    PROTOCOL_DESC="VLESS + Reality"
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
    
    NODE_NAME="ShadowTLS|博客:dlmn.lol"
    SS_LINK=$(echo -n "2022-blake3-aes-128-gcm:${PASSWORD}" | base64 -w 0)
    CLIENT_LINK="ss://${SS_LINK}@${SERVER_IP}:${PORT}?plugin=shadow-tls;version=3;host=${HANDSHAKE_SERVER}#${NODE_NAME}"
    
    PASSWORD_INFO="Password: ${PASSWORD}"
    PROTOCOL_NAME="ShadowTLS v3"
    PROTOCOL_DESC="Shadowsocks + ShadowTLS v3"
    print_success "ShadowTLS v3 配置完成"
}

# AnyTLS 配置
setup_anytls() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}AnyTLS 协议配置 (实验性)${NC}                      ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    print_warning "AnyTLS 是实验性功能，可能不稳定"
    print_info "AnyTLS 基于 VLESS + HTTP 传输"
    echo ""
    
    UUID=$(sing-box generate uuid)
    
    read -p "$(echo -e ${YELLOW}请输入监听端口 [默认: 443]: ${NC})" PORT
    PORT=${PORT:-443}
    
    read -p "$(echo -e ${YELLOW}请输入伪装域名 [默认: www.bing.com]: ${NC})" TLS_SERVER
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
    
    NODE_NAME="AnyTLS|博客:dlmn.lol"
    # AnyTLS 使用 VLESS + HTTP 传输
    CLIENT_LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&type=http&host=${TLS_SERVER}&path=%2F&security=none#${NODE_NAME}"
    
    PROTOCOL_NAME="AnyTLS"
    PROTOCOL_DESC="VLESS + HTTP 传输 (实验性)"
    print_success "AnyTLS 配置完成"
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
    
    if [ "$PROTOCOL_NAME" = "Reality" ]; then
        echo -e "  ${CYAN}🆔 UUID:${NC} ${YELLOW}${UUID}${NC}"
        echo -e "  ${CYAN}🔑 公钥:${NC} ${YELLOW}${PUBLIC_KEY}${NC}"
        echo -e "  ${CYAN}🎯 Short ID:${NC} ${YELLOW}${SHORT_ID}${NC}"
        echo -e "  ${CYAN}🌐 SNI:${NC} ${YELLOW}${SNI}${NC}"
    elif [ "$PROTOCOL_NAME" = "ShadowTLS v3" ]; then
        echo -e "  ${CYAN}🔒 ${YELLOW}${PASSWORD_INFO}${NC}"
        echo -e "  ${CYAN}🌐 伪装域名:${NC} ${YELLOW}${HANDSHAKE_SERVER}${NC}"
    elif [ "$PROTOCOL_NAME" = "AnyTLS" ]; then
        echo -e "  ${CYAN}🆔 UUID:${NC} ${YELLOW}${UUID}${NC}"
        echo -e "  ${CYAN}🌐 伪装域名:${NC} ${YELLOW}${TLS_SERVER}${NC}"
        echo -e "  ${YELLOW}⚠️  注意: 链接协议显示为 vless 是正常的${NC}"
        echo -e "  ${YELLOW}   (AnyTLS = VLESS + HTTP传输)${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════ 📱 客户端配置 ═══════════════${NC}"
    echo -e "${CYAN}复制以下链接到 v2rayN 导入:${NC}"
    echo -e "${PURPLE}节点备注: ${PROTOCOL_NAME}|博客:dlmn.lol${NC}"
    echo ""
    echo -e "${YELLOW}${CLIENT_LINK}${NC}"
    echo ""
    
    # 生成二维码
    if command -v qrencode &> /dev/null; then
        echo -e "${CYAN}📲 终端二维码 (小尺寸，适合手机扫描):${NC}"
        echo ""
        qrencode -t ANSIUTF8 -s 1 -m 1 "${CLIENT_LINK}"
        echo ""
        
        QR_FILE="/root/singbox_qr_${PROTOCOL_NAME}.png"
        qrencode -t PNG -s 6 -o "${QR_FILE}" "${CLIENT_LINK}" 2>/dev/null
        
        if [ -f "${QR_FILE}" ]; then
            print_success "二维码图片已保存: ${QR_FILE}"
            echo -e "  ${CYAN}提示: 可以使用 scp 下载到本地扫描${NC}"
            echo -e "  ${YELLOW}scp root@${SERVER_IP}:${QR_FILE} ./${NC}"
        fi
        echo ""
    fi
    
    echo -e "${GREEN}${BOLD}═══════════════ ⚙️  管理命令 ═══════════════${NC}"
    echo -e "  ${CYAN}查看状态:${NC} systemctl status sing-box"
    echo -e "  ${CYAN}查看日志:${NC} journalctl -u sing-box -f"
    echo -e "  ${CYAN}重启服务:${NC} systemctl restart sing-box"
    echo -e "  ${CYAN}停止服务:${NC} systemctl stop sing-box"
    echo -e "  ${CYAN}查看配置:${NC} cat /root/singbox_config.txt"
    echo ""
    
    cat > /root/singbox_config.txt <<INFO
════════════════════════════════════════════════════
         SingBox 配置信息
         
         脚本作者: sd87671067
         作者博客: https://dlmn.lol
         生成时间: $(date)
════════════════════════════════════════════════════

【服务器信息】
服务器 IP: ${SERVER_IP}
协议类型: ${PROTOCOL_NAME}
协议说明: ${PROTOCOL_DESC}
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
    echo ""
    echo "注意: AnyTLS 基于 VLESS + HTTP 传输"
    echo "客户端链接显示 vless:// 是正常的"
fi)

【客户端链接】
${CLIENT_LINK}

【节点备注】
格式: ${PROTOCOL_NAME}|博客:dlmn.lol
说明: 导入v2rayN后，节点名称会显示此备注

【二维码文件】
终端查看: 已显示在安装完成界面
PNG 文件: ${QR_FILE}
下载命令: scp root@${SERVER_IP}:${QR_FILE} ./

【配置文件位置】
/etc/sing-box/config.json

【常用命令】
查看状态: systemctl status sing-box
查看日志: journalctl -u sing-box -f
启动服务: systemctl start sing-box
停止服务: systemctl stop sing-box
重启服务: systemctl restart sing-box

════════════════════════════════════════════════════
更多代理工具和教程，请访问作者博客:
👉 https://dlmn.lol
════════════════════════════════════════════════════
INFO
    
    print_success "配置信息已保存到: /root/singbox_config.txt"
    echo ""
    echo -e "${PURPLE}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}${BOLD}   💡 更多工具和教程，请访问作者博客: ${CYAN}https://dlmn.lol${NC}"
    echo -e "${PURPLE}${BOLD}   📧 作者: sd87671067${NC}"
    echo -e "${PURPLE}${BOLD}══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# 主菜单
main_menu() {
    show_banner
    echo -e "${CYAN}${BOLD}═══════════════ 请选择代理协议 ═══════════════${NC}"
    echo ""
    echo -e "  ${GREEN}${BOLD}1${NC}) ${BOLD}Reality${NC}"
    echo -e "     ${CYAN}├─${NC} 最新、最安全的代理协议"
    echo -e "     ${CYAN}├─${NC} 基于真实 TLS 指纹伪装"
    echo -e "     ${CYAN}├─${NC} 抗审查能力极强"
    echo -e "     ${CYAN}└─${NC} ${GREEN}★ 强烈推荐 ★${NC}"
    echo ""
    echo -e "  ${GREEN}${BOLD}2${NC}) ${BOLD}ShadowTLS v3${NC}"
    echo -e "     ${CYAN}├─${NC} 高性能 TLS 伪装协议"
    echo -e "     ${CYAN}├─${NC} 伪装成正常 HTTPS 流量"
    echo -e "     ${CYAN}└─${NC} 适合高速传输场景"
    echo ""
    echo -e "  ${GREEN}${BOLD}3${NC}) ${BOLD}AnyTLS${NC} ${YELLOW}(实验性)${NC}"
    echo -e "     ${CYAN}├─${NC} 基于 VLESS + HTTP 传输"
    echo -e "     ${CYAN}├─${NC} 灵活的传输方式"
    echo -e "     ${CYAN}└─${NC} ${YELLOW}可能不稳定${NC}"
    echo ""
    echo -e "  ${RED}${BOLD}0${NC}) ${BOLD}退出脚本${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
    echo ""
    read -p "$(echo -e ${YELLOW}${BOLD}请输入选项 [1-3]: ${NC})" choice
    
    case $choice in
        1) 
            PROTOCOL_TYPE="Reality"
            setup_reality 
            ;;
        2) 
            PROTOCOL_TYPE="ShadowTLS v3"
            setup_shadowtls 
            ;;
        3) 
            PROTOCOL_TYPE="AnyTLS"
            setup_anytls 
            ;;
        0) 
            echo ""
            echo -e "${CYAN}感谢使用！"
            echo -e "更多工具请访问: ${PURPLE}https://dlmn.lol${NC}"
            echo -e "作者: ${PURPLE}sd87671067${NC}"
            echo ""
            exit 0 
            ;;
        *) 
            print_error "无效选择，请输入 1-3"
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
    save_config
    start_service
    setup_firewall
    show_result
}

main
