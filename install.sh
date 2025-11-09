#!/bin/bash

# Sing-Box 一键安装配置脚本 v2.1
# 作者: sd87671067
# 博客: dlmn.lol
# 更新时间: 2025-11-09 07:46 UTC

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

AUTHOR_BLOG="dlmn.lol"
CONFIG_FILE="/etc/sing-box/config.json"
INSTALL_DIR="/usr/local/bin"
CERT_DIR="/etc/sing-box/certs"

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

show_banner() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   Sing-Box 一键安装脚本 v2.1         ║${NC}"
    echo -e "${CYAN}║   作者: sd87671067 | dlmn.lol        ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
    echo ""
}

# 检测系统
detect_system() {
    [[ -f /etc/os-release ]] && . /etc/os-release || { print_error "无法检测系统"; exit 1; }
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) print_error "不支持的架构: $ARCH"; exit 1 ;;
    esac
}

# 安装依赖和 sing-box
install_singbox() {
    print_info "检查依赖和 sing-box..."
    
    # 检查并安装依赖
    if ! command -v jq &>/dev/null || ! command -v openssl &>/dev/null; then
        print_info "安装依赖包..."
        apt-get update -qq && apt-get install -y curl wget jq openssl uuid-runtime >/dev/null 2>&1
    fi
    
    # 检查 sing-box
    if command -v sing-box &>/dev/null; then
        local version=$(sing-box version 2>&1 | grep -oP 'sing-box version \K[0-9.]+' || echo "unknown")
        print_success "sing-box 已安装 (版本: ${version})"
        return 0
    fi
    
    # 安装 sing-box
    print_info "下载并安装 sing-box..."
    LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    [[ -z "$LATEST" ]] && LATEST="1.12.0"
    
    print_info "目标版本: ${LATEST}"
    
    wget -q --show-progress -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz" 2>&1 | grep -oP '\d+%' | tail -1
    
    tar -xzf /tmp/sb.tar.gz -C /tmp
    install -Dm755 /tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box ${INSTALL_DIR}/sing-box
    rm -rf /tmp/sb.tar.gz /tmp/sing-box-*
    
    # 创建 systemd 服务
    cat > /etc/systemd/system/sing-box.service << EOF
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
EOF
    
    systemctl daemon-reload
    systemctl enable sing-box >/dev/null 2>&1
    
    print_success "sing-box 安装完成 (版本: ${LATEST})"
}

# 生成证书
gen_cert() {
    mkdir -p ${CERT_DIR}
    openssl genrsa -out ${CERT_DIR}/private.key 2048 2>/dev/null
    openssl req -new -x509 -days 36500 -key ${CERT_DIR}/private.key -out ${CERT_DIR}/cert.pem \
        -subj "/CN=bing.com" 2>/dev/null
    print_success "证书生成完成（有效期100年）"
}

# 生成密钥
gen_keys() {
    print_info "生成密钥和 UUID..."
    KEYS=$(${INSTALL_DIR}/sing-box generate reality-keypair 2>/dev/null)
    REALITY_PRIVATE=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
    REALITY_PUBLIC=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
    UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
    SHORT_ID=$(openssl rand -hex 8)
    PASSWORD=$(openssl rand -base64 16)
    print_success "密钥生成完成"
}

# 获取IP
get_ip() {
    print_info "获取服务器 IP..."
    SERVER_IP=$(curl -s4m5 ifconfig.me || curl -s4m5 api.ipify.org)
    [[ -z "$SERVER_IP" ]] && { print_error "无法获取IP"; exit 1; }
    print_success "服务器 IP: ${SERVER_IP}"
}

# Reality配置
setup_reality() {
    echo ""
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    read -p "伪装域名 [itunes.apple.com]: " SNI
    SNI=${SNI:-itunes.apple.com}
    
    print_info "生成配置文件..."
    
    cat > ${CONFIG_FILE} << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
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
          "private_key": "${REALITY_PRIVATE}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
EOF
    
    LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#Reality|${AUTHOR_BLOG}"
    PROTO="Reality"
    print_success "Reality 配置完成"
}

# AnyTLS配置
setup_anytls() {
    echo ""
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    
    print_info "生成自签证书..."
    gen_cert
    
    print_info "生成配置文件..."
    
    cat > ${CONFIG_FILE} << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "anytls",
      "listen": "::",
      "listen_port": ${PORT},
      "users": [
        {
          "password": "${UUID}"
        }
      ],
      "padding_scheme": [],
      "tls": {
        "enabled": true,
        "certificate_path": "${CERT_DIR}/cert.pem",
        "key_path": "${CERT_DIR}/private.key"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
EOF
    
    LINK="anytls://${UUID}@${SERVER_IP}:${PORT}?security=tls&fp=firefox&insecure=1&type=tcp#AnyTLS|${AUTHOR_BLOG}"
    PROTO="AnyTLS"
    print_success "AnyTLS 配置完成"
}

# 显示菜单
show_menu() {
    show_banner
    echo -e "${YELLOW}请选择协议:${NC}"
    echo ""
    echo -e "${GREEN}[1]${NC} Reality ${YELLOW}(⭐ 强烈推荐)${NC}"
    echo -e "    ${CYAN}→ 抗审查能力最强，伪装真实TLS流量${NC}"
    echo ""
    echo -e "${GREEN}[2]${NC} AnyTLS"
    echo -e "    ${CYAN}→ 通用TLS协议，兼容性好${NC}"
    echo ""
    read -p "选择 [1-2]: " choice
    
    case $choice in
        1) setup_reality ;;
        2) setup_anytls ;;
        *) print_error "无效选项"; exit 1 ;;
    esac
}

# 启动服务
start_svc() {
    print_info "验证配置文件..."
    
    if ! ${INSTALL_DIR}/sing-box check -c ${CONFIG_FILE} 2>&1; then
        print_error "配置验证失败"
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

# 显示结果
show_result() {
    clear
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                           ║${NC}"
    echo -e "${CYAN}║               ${GREEN}🎉 配置完成！${CYAN}                              ║${NC}"
    echo -e "${CYAN}║                                                           ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}服务器信息:${NC}"
    echo -e "  协议: ${GREEN}${PROTO}${NC}"
    echo -e "  IP: ${GREEN}${SERVER_IP}${NC}"
    echo -e "  端口: ${GREEN}${PORT}${NC}"
    echo -e "  UUID: ${GREEN}${UUID}${NC}"
    echo ""
    echo -e "${CYAN}─────────────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}📋 v2rayN/V2RayNG 剪贴板链接:${NC}"
    echo -e "${CYAN}─────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${YELLOW}${LINK}${NC}"
    echo ""
    echo -e "${CYAN}─────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${YELLOW}📱 使用方法:${NC}"
    echo -e "  1. 复制上面的完整链接"
    echo -e "  2. 打开 v2rayN 或 V2RayNG 客户端"
    echo -e "  3. 点击 '从剪贴板导入'"
    echo ""
    echo -e "${YELLOW}⚙️  服务管理:${NC}"
    echo -e "  启动: ${CYAN}systemctl start sing-box${NC}"
    echo -e "  停止: ${CYAN}systemctl stop sing-box${NC}"
    echo -e "  重启: ${CYAN}systemctl restart sing-box${NC}"
    echo -e "  状态: ${CYAN}systemctl status sing-box${NC}"
    echo -e "  日志: ${CYAN}journalctl -u sing-box -f${NC}"
    echo ""
    echo -e "${GREEN}💡 更多教程: ${YELLOW}https://${AUTHOR_BLOG}${NC}"
    echo -e "${GREEN}📧 作者: ${YELLOW}sd87671067${NC}"
    echo ""
}

# 主函数
main() {
    # Root 权限检查
    [[ $EUID -ne 0 ]] && { print_error "需要 root 权限运行"; exit 1; }
    
    # 系统检测
    detect_system
    print_success "系统检测: ${OS} (${ARCH})"
    
    # 安装 sing-box
    install_singbox
    
    # 创建配置目录
    mkdir -p /etc/sing-box
    
    # 生成密钥
    gen_keys
    
    # 获取 IP
    get_ip
    
    # 显示菜单并配置
    show_menu
    
    # 启动服务
    start_svc
    
    # 显示结果
    show_result
}

main
