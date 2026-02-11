#!/bin/bash
source /etc/hysteria/core/scripts/utils.sh
define_colors

APISERVER_ENV_FILE="/etc/hysteria/core/scripts/apiserver/.env"
WEBPANEL_ENV_FILE="/etc/hysteria/core/scripts/webpanel/.env"
CADDY_CONFIG_FILE="/etc/hysteria/core/scripts/webpanel/Caddyfile"
APISERVER_LISTEN_ADDRESS="127.0.0.1"
APISERVER_LISTEN_PORT="28261"

install_dependencies() {
    if command -v caddy &> /dev/null; then
        return 0
    fi

    echo -e "${yellow}Installing Caddy...${NC}"
    sudo apt update -y > /dev/null 2>&1
    sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl libnss3-tools > /dev/null 2>&1

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg > /dev/null 2>&1
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null 2>&1
    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod o+r /etc/apt/sources.list.d/caddy-stable.list

    sudo apt update -y > /dev/null 2>&1
    sudo apt install -y caddy
    if [ $? -ne 0 ]; then
        echo -e "${red}Error: Failed to install Caddy.${NC}"
        exit 1
    fi
    systemctl stop caddy > /dev/null 2>&1
    systemctl disable caddy > /dev/null 2>&1
    echo -e "${green}Caddy installed successfully.${NC}"
}

update_env_file() {
    local domain=$1
    local port=$2
    local api_token=$3
    local root_path=$4
    local debug=$5

    if [ -z "$api_token" ]; then
        api_token=$(openssl rand -hex 32)
    fi

    if [ -z "$root_path" ]; then
        root_path=$(openssl rand -hex 16)
    fi

    cat <<EOL > "$APISERVER_ENV_FILE"
DOMAIN=$domain
PORT=$port
ROOT_PATH=$root_path
API_TOKEN=$api_token
DEBUG=$debug
LISTEN_ADDRESS=$APISERVER_LISTEN_ADDRESS
LISTEN_PORT=$APISERVER_LISTEN_PORT
EOL
}

create_apiserver_service_file() {
    cat <<EOL > /etc/systemd/system/hysteria-apiserver.service
[Unit]
Description=Hysteria2 API Server
After=network.target

[Service]
WorkingDirectory=/etc/hysteria/core/scripts/apiserver
EnvironmentFile=$APISERVER_ENV_FILE
ExecStart=/bin/bash -c 'source /etc/hysteria/hysteria2_venv/bin/activate && /etc/hysteria/hysteria2_venv/bin/python /etc/hysteria/core/scripts/apiserver/app.py'
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOL
}

create_caddy_service_file() {
    cat <<EOL > /etc/systemd/system/hysteria-caddy.service
[Unit]
Description=Hysteria2 Caddy
After=network.target

[Service]
WorkingDirectory=/etc/caddy
ExecStart=/usr/bin/caddy run --environ --config $CADDY_CONFIG_FILE
ExecReload=/usr/bin/caddy reload --config $CADDY_CONFIG_FILE --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOL
}

refresh_caddy() {
    if ! bash /etc/hysteria/core/scripts/webpanel/webpanel_shell.sh refresh-caddy; then
        echo -e "${red}Error: Failed to refresh Caddy configuration.${NC}"
        return 1
    fi
}

show_apiserver_url() {
    if [ ! -f "$APISERVER_ENV_FILE" ]; then
        echo -e "${red}Error: API Server .env file not found. Is the API Server configured?${NC}"
        exit 1
    fi

    source "$APISERVER_ENV_FILE"
    local apiserver_url="https://$DOMAIN:$PORT/$ROOT_PATH/"
    echo "$apiserver_url"
}

show_apiserver_api_token() {
    if [ ! -f "$APISERVER_ENV_FILE" ]; then
        echo -e "${red}Error: API Server .env file not found. Is the API Server configured?${NC}"
        exit 1
    fi

    source "$APISERVER_ENV_FILE"
    echo "$API_TOKEN"
}

start_service() {
    local domain=""
    local port=""
    local api_token=""
    local root_path=""
    local debug="false"

    OPTIND=1
    while getopts ":d:p:t:r:g" opt; do
        case $opt in
            d) domain="$OPTARG" ;;
            p) port="$OPTARG" ;;
            t) api_token="$OPTARG" ;;
            r) root_path="$OPTARG" ;;
            g) debug="true" ;;
            \?) echo -e "${red}Invalid option: -$OPTARG${NC}" >&2; exit 1 ;;
            :) echo -e "${red}Option -$OPTARG requires an argument.${NC}" >&2; exit 1 ;;
        esac
    done

    if [ -z "$domain" ] || [ -z "$port" ]; then
        echo -e "${red}Usage: $0 start -d <DOMAIN> -p <PORT> [-t API_TOKEN] [-r ROOT_PATH] [-g]${NC}"
        exit 1
    fi

    install_dependencies

    update_env_file "$domain" "$port" "$api_token" "$root_path" "$debug"

    create_apiserver_service_file

    if [ ! -f /etc/systemd/system/hysteria-caddy.service ]; then
        create_caddy_service_file
    fi

    systemctl daemon-reload
    systemctl enable hysteria-apiserver.service > /dev/null 2>&1
    systemctl start hysteria-apiserver.service > /dev/null 2>&1

    if systemctl is-active --quiet hysteria-apiserver.service; then
        echo -e "${green}Hysteria API Server started successfully.${NC}"
    else
        echo -e "${red}Error: Hysteria API Server service failed to start.${NC}"
        exit 1
    fi

    refresh_caddy || exit 1
    echo -e "${green}API Server URL: $(show_apiserver_url)${NC}"
}

stop_service() {
    systemctl disable hysteria-apiserver.service > /dev/null 2>&1
    systemctl stop hysteria-apiserver.service > /dev/null 2>&1
    rm -f "$APISERVER_ENV_FILE"

    if [ -f "$WEBPANEL_ENV_FILE" ]; then
        refresh_caddy
        return
    fi

    if systemctl is-active --quiet hysteria-caddy.service; then
        systemctl stop hysteria-caddy.service > /dev/null 2>&1
        systemctl disable hysteria-caddy.service > /dev/null 2>&1
    fi

    rm -f "$CADDY_CONFIG_FILE"
}

case "$1" in
    start)
        shift
        start_service "$@"
        ;;
    stop)
        stop_service
        ;;
    url)
        show_apiserver_url
        ;;
    api-token)
        show_apiserver_api_token
        ;;
    *)
        echo -e "${red}Usage: $0 {start|stop|url|api-token} [options]${NC}"
        echo -e "${yellow}start -d <DOMAIN> -p <PORT> [-t API_TOKEN] [-r ROOT_PATH] [-g]${NC}"
        echo -e "${yellow}stop${NC}"
        echo -e "${yellow}url${NC}"
        echo -e "${yellow}api-token${NC}"
        exit 1
        ;;
 esac
