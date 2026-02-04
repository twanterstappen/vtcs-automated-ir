#!/bin/bash
# Setup script for VTCS Project
# Generates SSL certificates and starts services

# Color output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

info() { echo -e "${BLUE}${BOLD}[INFO]${RESET} $*"; }
success() { echo -e "${GREEN}${BOLD}[OK]${RESET} $*"; }
warn() { echo -e "${YELLOW}${BOLD}[WARN]${RESET} $*"; }
err() { echo -e "${RED}${BOLD}[ERROR]${RESET} $*"; }

# Function to generate a random password
generate_password() {
    tr -dc 'A-Za-z0-9!?' </dev/urandom | head -c 16
}

# Function to prompt for password with confirmation or generation
prompt_for_password() {
    local prompt_text=$1
    local var_name=$2
    local allow_generation=$3  # "true" or "false"
    local password=""
    local password_confirm=""
    
    # Keep prompting until the user provides a valid, confirmed password
    while true; do
        if [ "$allow_generation" = "true" ]; then
            echo -ne "${BLUE}${BOLD}$prompt_text${RESET}"$'\n'" (Press Enter to generate, or type your password): "
            read password
            
            if [ -z "$password" ]; then
                # Generate random password
                password=$(generate_password)
                echo ""
                info "Generated password: $password"
                eval "$var_name='$password'"
                return 0
            fi
        else
            echo -ne "${BLUE}${BOLD}$prompt_text${RESET}: "
            read -s password
            echo ""
        fi
        
        if [ -z "$password" ]; then
            err "Password cannot be empty. Please try again."
            continue
        fi
        
        if [ ${#password} -lt 8 ]; then
            warn "Password should be at least 8 characters long (recommended 16+)."
        fi
        
        echo -ne "${BLUE}${BOLD}Confirm password${RESET}: "
        read -s password_confirm
        echo ""
        
        if [ "$password" = "$password_confirm" ]; then
            eval "$var_name='$password'"
            return 0
        else
            err "Passwords do not match. Please try again."
        fi
    done
}

# Function to prompt for Telegram credentials
prompt_for_telegram() {
    info ""
    info "╔════════════════════════════════════════════════════════════╗"
    info "║         TELEGRAM BOT CONFIGURATION SETUP                   ║"
    info "╚════════════════════════════════════════════════════════════╝"
    info ""
    info "Wazuh will send security alerts to your Telegram chat."
    info "You need a Telegram bot token and your chat ID."
    info ""
    
    read -p "Do you want to set up Telegram alerts now? (yes/no) [default: yes]: " setup_telegram
    setup_telegram=${setup_telegram:-yes}
    
    if [[ "$setup_telegram" != "yes" && "$setup_telegram" != "y" ]]; then
        warn "Skipping Telegram setup. You can configure this later."
        TELEGRAM_BOT_TOKEN="CHANGE-ME-BOT-TOKEN"
        TELEGRAM_CHAT_ID="CHANGE-ME-CHAT-ID"
        return 0
    fi
    
    info ""
    info "HOW TO GET YOUR TELEGRAM BOT TOKEN:"
    info "   1. Open Telegram and search for 'BotFather'"
    info "   2. Click /start and then /newbot"
    info "   3. Follow the steps to create a bot"
    info "   4. BotFather will give you a TOKEN (it looks like:"
    info "      123456789:ABCDefGhIjKlMnOpQrStUvWxYz_1234567890)"
    info ""
    info "BEFORE CONTINUING:"
    info "   IMPORTANT: You MUST send a message to your bot first!"
    info "   1. Search for your bot in Telegram"
    info "   2. Click 'Start' button OR send ANY message (e.g., 'hello', 'test')"
    info "   3. Wait a few seconds for the message to be delivered"
    info ""
    
    read -p "Enter your Telegram Bot Token: " TELEGRAM_BOT_TOKEN
    
    # Retry Telegram setup on empty input
    if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
        err "Bot token cannot be empty."
        prompt_for_telegram
        return
    fi
    
    info ""
    info "Retrieving your Chat ID using the Telegram API..."
    
    # Try to retrieve Chat ID using Python script logic
    CHAT_ID_RETRIEVAL=$(python3 << PYTHON_SCRIPT
import requests

bot_token = "$TELEGRAM_BOT_TOKEN"

try:
    url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
    response = requests.get(url, timeout=5)
    
    if response.status_code == 200:
        data = response.json()
        
        if data.get("ok") and data.get("result"):
            chat_id = data["result"][-1]["message"]["chat"]["id"]
            print(str(chat_id))
        else:
            print("")
    else:
        print("")
except:
    print("")
PYTHON_SCRIPT
)
    
    if [ -z "$CHAT_ID_RETRIEVAL" ]; then
        err "Could not retrieve Chat ID from Telegram API."
        info ""
        info "This means:"
        info "   • You haven't sent a message to your bot yet, OR"
        info "   • Your bot token is incorrect, OR"
        info "   • Internet connection issue"
        info ""
        info "What to do:"
        info "   1. Make sure you SENT A MESSAGE to your bot in Telegram"
        info "   2. Check your bot token is copied correctly"
        info "   3. Try setup again"
        echo ""
        prompt_for_telegram
        return
    fi
    
    TELEGRAM_CHAT_ID="$CHAT_ID_RETRIEVAL"
    success "Chat ID retrieved: $TELEGRAM_CHAT_ID"
    info ""
    success "Telegram credentials retrieved successfully!"
}

# Check if .env file exists
if [ ! -f ".env" ]; then
    info ""
    info "FIRST-TIME SETUP - CREATING CONFIGURATION"
    info ""
    
    info "Copying default .env file..."
    if [ -f ".env.example" ]; then
        cp ".env.example" ".env"
        success "Default .env file copied"
    else
        # Create a default .env if no example exists
        cat > ".env" << 'EOF'
# Malware API Configuration
# Generate a strong random key: openssl rand -hex 32
MALWARE_API_KEY=change-me-to-a-secure-key
# LLM / Ollama Configuration
# Service URL inside compose; change if invoking externally.
OLLAMA_URL=http://ollama:11434
# Model to pull and use for explanations.
OLLAMA_MODEL=llama3.2:1b
# Limit on tokens returned per explanation.
OLLAMA_MAX_TOKENS=350
# Wazuh admin / Dashboard credentials
# Set strong passwords; Recommend to use a minimum of 16 characters with a mix of letters, numbers, and special characters.
ADMIN_PASSWORD=change-me-admin
KIBANASERVER_PASSWORD=change-me-kibana
READONLY_USER_PASSWORD=change-me-readonly
# Telegram Bot Configuration for Wazuh Alerts
TELEGRAM_BOT_TOKEN=change-me-to-your-bot-token
TELEGRAM_CHAT_ID=change-me-to-your-chat-id
EOF
        success ".env file created with defaults"
    fi
    
    info ""
    prompt_for_password "Enter Admin Password (minimum 8 characters)" "admin_password" "true"
    
    # Always generate Kibana Server Password
    kibana_password=$(generate_password)
    info "Kibana Server Password generated: $kibana_password"
    
    prompt_for_password "Enter Read-Only User Password (minimum 8 characters)" "readonly_password" "true"
    
    # Setup Telegram
    prompt_for_telegram
    
    # Update .env file with provided values
    info "Updating .env configuration file..."
    
    # Use temporary file for safe replacement
    tmp_env=$(mktemp)
    
    # Update passwords
    sed "s/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=$admin_password/" ".env" > "$tmp_env"
    mv "$tmp_env" ".env"
    
    sed "s/^KIBANASERVER_PASSWORD=.*/KIBANASERVER_PASSWORD=$kibana_password/" ".env" > "$tmp_env"
    mv "$tmp_env" ".env"
    
    sed "s/^READONLY_USER_PASSWORD=.*/READONLY_USER_PASSWORD=$readonly_password/" ".env" > "$tmp_env"
    mv "$tmp_env" ".env"
    
    # Update Telegram credentials
    sed "s/^TELEGRAM_BOT_TOKEN=.*/TELEGRAM_BOT_TOKEN=$TELEGRAM_BOT_TOKEN/" ".env" > "$tmp_env"
    mv "$tmp_env" ".env"
    
    sed "s/^TELEGRAM_CHAT_ID=.*/TELEGRAM_CHAT_ID=$TELEGRAM_CHAT_ID/" ".env" > "$tmp_env"
    mv "$tmp_env" ".env"
    
    success ".env file configured with your settings!"
    info ""
fi

# Verify required fields in .env
info "Verifying .env configuration..."

if ! grep -q "ADMIN_PASSWORD=" ".env"; then
    err "ADMIN_PASSWORD not found in .env. Aborting setup."
    exit 1
fi

if ! grep -q "KIBANASERVER_PASSWORD=" ".env"; then
    err "KIBANASERVER_PASSWORD not found in .env. Aborting setup."
    exit 1
fi

if ! grep -q "TELEGRAM_BOT_TOKEN=" ".env"; then
    err "TELEGRAM_BOT_TOKEN not found in .env. Aborting setup."
    exit 1
fi

if ! grep -q "TELEGRAM_CHAT_ID=" ".env"; then
    err "TELEGRAM_CHAT_ID not found in .env. Aborting setup."
    exit 1
fi

success ".env file verification complete!"
info ""

# Source the .env file to get variables
set -a
source .env
set +a

info "Checking for passwords in .env file..."

example_path="services/wazuh/config/wazuh_indexer/internal_users.yml.example"
target_path="services/wazuh/config/wazuh_indexer/internal_users.yml"

if [ -f "$example_path" ]; then
    cp "$example_path" "$target_path"
    hashed_any=false
    
    # Check for admin password
    if grep -q "ADMIN_PASSWORD=" ".env"; then
        admin_password=$(grep "ADMIN_PASSWORD=" ".env" | cut -d '=' -f2 | tr -d '\r')
        info "Found admin password. Generating password hash..."
        
        # Generate hash using Docker
        admin_hash=$(docker run --rm wazuh/wazuh-indexer:4.14.1 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$admin_password")
        admin_hash=$(echo "$admin_hash" | tr -d '\r\n')
        # Safely replace the placeholder with the generated hash (handles slashes, ampersands, etc.)
        tmpfile=$(mktemp)
        awk -v h="$admin_hash" '{ gsub(/\{ADMIN-PASSWORD-HASH\}/, h); print }' "$target_path" > "$tmpfile" && mv "$tmpfile" "$target_path"
        success "Admin password hash generated successfully!"
        hashed_any=true
    fi
    
    # Check for kibanaserver password
    if grep -q "KIBANASERVER_PASSWORD=" ".env"; then
        kibana_password=$(grep "KIBANASERVER_PASSWORD=" ".env" | cut -d '=' -f2 | tr -d '\r')
        info "Found kibanaserver password. Generating password hash..."
        
        # Generate hash using Docker
        kibana_hash=$(docker run --rm wazuh/wazuh-indexer:4.14.1 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$kibana_password")
        kibana_hash=$(echo "$kibana_hash" | tr -d '\r\n')
        
        tmpfile=$(mktemp)
        awk -v h="$kibana_hash" '{ gsub(/\{KIBANASERVER-PASSWORD-HASH\}/, h); print }' "$target_path" > "$tmpfile" && mv "$tmpfile" "$target_path"
        success "Kibanaserver password hash generated successfully!"
        hashed_any=true
    fi
    
    # Check for readonly_user password
    if grep -q "READONLY_USER_PASSWORD=" ".env"; then
        readonly_password=$(grep "READONLY_USER_PASSWORD=" ".env" | cut -d '=' -f2 | tr -d '\r')
        info "Found readonly_user password. Generating password hash..."
        
        # Generate hash using Docker
        readonly_hash=$(docker run --rm wazuh/wazuh-indexer:4.14.1 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$readonly_password")
        readonly_hash=$(echo "$readonly_hash" | tr -d '\r\n')
        
        tmpfile=$(mktemp)
        awk -v h="$readonly_hash" '{ gsub(/\{READONLY-USER-PASSWORD-HASH\}/, h); print }' "$target_path" > "$tmpfile" && mv "$tmpfile" "$target_path"
        success "Readonly user password hash generated successfully!"
        hashed_any=true
    fi
    
    if [ "$hashed_any" = true ]; then
        success "Created internal_users.yml with password hashes"
    else
        warn "No ADMIN_PASSWORD or KIBANASERVER_PASSWORD found in .env file"
    fi
else
    warn "internal_users.yml.example not found"
fi

info "Generating Wazuh indexer certificates..."

# Ensure certificate output directory exists and is writable by the generator container
cert_dir="services/wazuh/config/wazuh_indexer_ssl_certs"
mkdir -p "$cert_dir"

# Fix ownership so Docker-generated files are accessible on the host
if command -v sudo >/dev/null 2>&1; then
    sudo chown -R "$(id -u)":"$(id -g)" "$cert_dir" 2>/dev/null || true
    sudo chmod -R u+rwX "$cert_dir" 2>/dev/null || true
else
    chown -R "$(id -u)":"$(id -g)" "$cert_dir" 2>/dev/null || true
    chmod -R u+rwX "$cert_dir" 2>/dev/null || true
fi

# Run certificate generator and remove container when done
docker compose -f services/wazuh/generate-indexer-certs.yml run --rm generator

# Fix permissions so generated keys are readable outside the container
if [ -d "$cert_dir" ]; then
    info "Fixing certificate file ownership and permissions..."
    cmd_prefix=()
    if command -v sudo >/dev/null 2>&1; then
        cmd_prefix=(sudo)
    fi

    "${cmd_prefix[@]}" chown -R "$(id -u)":"$(id -g)" "$cert_dir" 2>/dev/null || true
    "${cmd_prefix[@]}" find "$cert_dir" -type f \( -name "*-key.pem" -o -name "*.key" \) -exec chmod 600 {} +
    "${cmd_prefix[@]}" find "$cert_dir" -type f -name "*.pem" -exec chmod 644 {} +
fi

success "Certificate generation complete!"

# Copy roles and roles_mapping files if they don't exist in the target directory
roles_source="services/wazuh/config/wazuh_indexer/roles.yml"
roles_mapping_source="services/wazuh/config/wazuh_indexer/roles_mapping.yml"

if [ -f "$roles_source" ]; then
    info "Roles configuration file found: $roles_source"
else
    warn "Roles configuration file not found at $roles_source"
fi

if [ -f "$roles_mapping_source" ]; then
    info "Roles mapping configuration file found: $roles_mapping_source"
else
    warn "Roles mapping configuration file not found at $roles_mapping_source"
fi

info "Starting services..."

# Start all services
docker compose up -d --build

success "All services started!"

# Wait for indexer to be ready
info "Waiting for indexer to become available..."
indexer_url="https://localhost:9200"
max_indexer_attempts=30
indexer_attempt=0

while [ "$indexer_attempt" -lt "$max_indexer_attempts" ]; do
    indexer_response=$(curl -k -u "admin:$admin_password" -s "$indexer_url/_cluster/health" 2>/dev/null)
    curl_exit_code=$?
    
    if [ "$curl_exit_code" -eq 0 ] && echo "$indexer_response" | grep -qE "yellow|green"; then
        success "Indexer is available."
        break
    fi
    
    indexer_attempt=$((indexer_attempt + 1))
    info "Indexer not ready yet (attempt $indexer_attempt/$max_indexer_attempts). Waiting 5 seconds..."
    sleep 5
done

if [ "$indexer_attempt" -lt "$max_indexer_attempts" ]; then
    # Load custom roles into the indexer
    info "Loading custom security roles..."
    
    roles_result=$(docker compose exec wazuh.indexer bash -c "chmod +x /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh && JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /usr/share/wazuh-indexer/config/custom-security/roles.yml -t roles -icl -nhnv -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -cert /usr/share/wazuh-indexer/config/certs/admin.pem -key /usr/share/wazuh-indexer/config/certs/admin-key.pem -h localhost" 2>&1)
    
    if [ $? -eq 0 ]; then
        success "Custom roles loaded successfully!"
    else
        warn "Could not load custom roles. Error: $roles_result"
    fi
    
    mapping_result=$(docker compose exec wazuh.indexer bash -c "JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /usr/share/wazuh-indexer/config/custom-security/roles_mapping.yml -t rolesmapping -icl -nhnv -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -cert /usr/share/wazuh-indexer/config/certs/admin.pem -key /usr/share/wazuh-indexer/config/certs/admin-key.pem -h localhost" 2>&1)
    
    if [ $? -eq 0 ]; then
        success "Custom roles mapping loaded successfully!"
    else
        warn "Could not load custom roles mapping. Error: $mapping_result"
    fi
else
    warn "Indexer did not become ready in time. Skipping custom role loading."
fi

# Wait for the dashboard to be ready and import custom dashboard
dashboard_url="https://localhost:443"
ndjson_path="$PWD/services/wazuh/config/custom_dashboard/malware_dashboard.ndjson"

info "Waiting for dashboard to become available..."

max_attempts=30
attempt=0

# Poll dashboard status API until it reports available
while [ "$attempt" -lt "$max_attempts" ]; do
    status_response=$(curl -s -k -u "admin:$admin_password" "$dashboard_url/api/status" 2>/dev/null)
    curl_exit_code=$?

    if [ "$curl_exit_code" -eq 0 ] && echo "$status_response" | grep -q "available"; then
        success "Dashboard is available."
        break
    fi

    attempt=$((attempt + 1))
    info "Dashboard not ready yet (attempt $attempt/$max_attempts). Waiting 10 seconds..."
    sleep 10
done

if [ "$attempt" -ge "$max_attempts" ]; then
    warn "Dashboard did not become ready in time. Skipping custom dashboard import."
else
    # Import saved objects (NDJSON) into the dashboard
    empty=$(curl -X POST -s -k -u "admin:$admin_password" \
        "$dashboard_url/api/saved_objects/_import?overwrite=true" \
        -H "osd-xsrf: true" \
        --form "file=@${ndjson_path}")

    success "Custom dashboard imported."
fi

# Display final summary
info ""
info "╔════════════════════════════════════════════════════════════╗"
info "║              SETUP COMPLETE - SUMMARY                      ║"
info "╚════════════════════════════════════════════════════════════╝"
info ""
info "Dashboard Access:"
info "   URL: https://localhost:443"
info "   Username: admin"
info "   Password: $admin_password"
info ""
info "Read-Only User Password: $readonly_password"
info ""
info "Telegram Bot Token: $TELEGRAM_BOT_TOKEN"
info "Telegram Chat ID: $TELEGRAM_CHAT_ID"
info ""
success "All services are now running!"
info ""