#!/bin/bash

# Sing-Box 一键安装配置脚本 v2.1
# 作者: sd87671067
# 博客: dlmn.lol
# 更新时间: 2025-11-09

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
    print_info "安装依赖和 sing-box..."
    apt-get update -qq && apt-get install -y curl wget jq openssl uuid-runtime >/dev/null 2>&1
    
    if command -v sing-box &>/dev/null; then
        print_success "sing-box 已安装"
        return 0
    fi
    
    LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    [[ -z "$LATEST" ]] && LATEST="1.12.0"
    
    wget -q -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz"
    tar -xzf /tmp/sb.tar.gz -C /tmp
    install -Dm755 /tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box ${INSTALL_DIR}/sing-box
    rm -rf /tmp/sb.tar.gz /tmp/sing-box-*
    
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/sing-box run -c ${CONFIG_FILE}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable sing-box >/dev/null 2>&1
    print_success "sing-box 安装完成"
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
    KEYS=$(sing-box generate reality-keypair 2>/dev/null)
    REALITY_PRIVATE=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
    REALITY_PUBLIC=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
    UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
    SHORT_ID=$(openssl rand -hex 8)
    PASSWORD=$(openssl rand -base64 16)
}

# 获取IP
get_ip() {
    SERVER_IP=$(curl -s4m5 ifconfig.me || curl -s4m5 api.ipify.org)
    [[ -z "$SERVER_IP" ]] && { print_error "无法获取IP"; exit 1; }
}

# Reality配置
setup_reality() {
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    read -p "伪装域名 [itunes.apple.com]: " SNI
    SNI=${SNI:-itunes.apple.com}
    
    cat > ${CONFIG_FILE} << EOF
{"log":{"level":"info"},"inbounds":[{"type":"vless","listen":"::","listen_port":${PORT},"users":[{"uuid":"${UUID}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${SNI}","reality":{"enabled":true,"handshake":{"server":"${SNI}","server_port":443},"private_key":"${REALITY_PRIVATE}","short_id":["${SHORT_ID}"]}}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
    
    LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#Reality|${AUTHOR_BLOG}"
    PROTO="Reality"
}

# AnyTLS配置
setup_anytls() {
    read -p "监听端口 [443]: " PORT
    PORT=${PORT:-443}
    gen_cert
    
    cat > ${CONFIG_FILE} << EOF
{"log":{"level":"info"},"inbounds":[{"type":"anytls","listen":"::","listen_port":${PORT},"users":[{"password":"${UUID}"}],"padding_scheme":[],"tls":{"enabled":true,"certificate_path":"${CERT_DIR}/cert.pem","key_path":"${CERT_DIR}/private.key"}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
    
    LINK="anytls://${UUID}@${SERVER_IP}:${PORT}?security=tls&fp=firefox&insecure=1&type=tcp#AnyTLS|${AUTHOR_BLOG}"
    PROTO="AnyTLS"
}

# 显示菜单
show_menu() {
    show_banner
    echo -e "${YELLOW}请选择协议:${NC}"
    echo -e "${GREEN}[1]${NC} Reality (强烈推荐)"
    echo -e "${GREEN}[2]${NC} AnyTLS"
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
    sing-box check -c ${CONFIG_FILE} || { print_error "配置验证失败"; exit 1; }
    systemctl restart sing-box
    sleep 2
    systemctl is-active --quiet sing-box && print_success "服务启动成功" || { print_error "服务启动失败"; exit 1; }
}

# 显示结果
show_result() {
    clear
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}🎉 配置完成！${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}协议:${NC} ${PROTO}"
    echo -e "${YELLOW}IP:${NC} ${SERVER_IP}"
    echo -e "${YELLOW}端口:${NC} ${PORT}"
    echo -e "${YELLOW}UUID:${NC} ${UUID}"
    echo ""
    echo -e "${GREEN}v2rayN 剪贴板链接:${NC}"
    echo -e "${CYAN}${LINK}${NC}"
    echo ""
    echo -e "${YELLOW}更多教程: https://${AUTHOR_BLOG}${NC}"
    echo ""
}

# 主函数
main() {
    [[ $EUID -ne 0 ]] && { print_error "需要root权限"; exit 1; }
    detect_system
    install_singbox
    mkdir -p /etc/sing-box
    gen_keys
    get_ip
    show_menu
    start_svc
    show_result
}

main
