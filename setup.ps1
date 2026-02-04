#!/usr/bin/env pwsh
# Setup script for VTCS Project
# Generates SSL certificates and starts services

# Set execution policy for this script only
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Color output helpers
$COLORS = @{
    "Red"    = [ConsoleColor]::Red
    "Green"  = [ConsoleColor]::Green
    "Yellow" = [ConsoleColor]::Yellow
    "Cyan"   = [ConsoleColor]::Cyan
}

function Info { Write-Host "[INFO] $args" -ForegroundColor Cyan }
function Success { Write-Host "[OK] $args" -ForegroundColor Green }
function Warn { Write-Host "[WARN] $args" -ForegroundColor Yellow }
function Err { Write-Host "[ERROR] $args" -ForegroundColor Red }

# Function to generate a random password
function Generate-Password {
    $length = 16
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?'
    
    # Build a random string by selecting random characters from $chars
    $password = -join (1..$length | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return $password
}

# Function to prompt for password with confirmation or generation
function Prompt-ForPassword {
    param(
        [string]$PromptText,
        [bool]$AllowGeneration = $false
    )
    
    # Keep prompting until a valid and confirmed password is provided
    while ($true) {
        if ($AllowGeneration) {
            Write-Host "$PromptText" -ForegroundColor Cyan -NoNewline
            Write-Host "`n(Press Enter to generate, or type your password): " -NoNewline
            $password = Read-Host
            
            if ([string]::IsNullOrEmpty($password)) {
                # Generate random password
                $password = Generate-Password
                Info "Generated password: $password"
                return $password
            }
        } else {
            Write-Host "$PromptText`: " -ForegroundColor Cyan -NoNewline
            $password = Read-Host -AsSecureString

             # Convert SecureString to plain text for validation and file writing
            $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($password))
        }
        
        if ([string]::IsNullOrEmpty($password)) {
            Err "Password cannot be empty. Please try again."
            continue
        }
        
        if ($password.Length -lt 8) {
            Warn "Password should be at least 8 characters long (recommended 16+)."
        }
        
        Write-Host "Confirm password: " -ForegroundColor Cyan -NoNewline
        $passwordConfirm = Read-Host -AsSecureString

        # Convert SecureString confirm input to plain text for comparison
        $passwordConfirm = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($passwordConfirm))
        
        if ($password -eq $passwordConfirm) {
            return $password
        } else {
            Err "Passwords do not match. Please try again."
        }
    }
}

# Function to prompt for Telegram credentials
function Prompt-ForTelegram {
    Info ""
    Info "=================================================="
    Info "    TELEGRAM BOT CONFIGURATION SETUP"
    Info "=================================================="
    Info ""
    Info "Wazuh will send security alerts to your Telegram chat."
    Info "You need a Telegram bot token and your chat ID."
    Info ""
    
    $setupTelegram = Read-Host "Do you want to set up Telegram alerts now? (yes/no) [default: yes]"
    if ([string]::IsNullOrEmpty($setupTelegram)) { $setupTelegram = "yes" }
    
    if ($setupTelegram -ne "yes" -and $setupTelegram -ne "y") {
        Warn "Skipping Telegram setup. You can configure this later."
        return @{
            "BotToken" = "CHANGE-ME-BOT-TOKEN"
            "ChatId" = "CHANGE-ME-CHAT-ID"
        }
    }
    
    Info ""
    Info "HOW TO GET YOUR TELEGRAM BOT TOKEN:"
    Info "   1. Open Telegram and search for 'BotFather'"
    Info "   2. Click /start and then /newbot"
    Info "   3. Follow the steps to create a bot"
    Info "   4. BotFather will give you a TOKEN (it looks like:"
    Info "      123456789:ABCDefGhIjKlMnOpQrStUvWxYz_1234567890)"
    Info ""
    Info "BEFORE CONTINUING:"
    Info "   IMPORTANT: You MUST send a message to your bot first!"
    Info "   1. Search for your bot in Telegram"
    Info "   2. Click 'Start' button OR send ANY message (e.g., 'hello', 'test')"
    Info "   3. Wait a few seconds for the message to be delivered"
    Info ""
    
    $botToken = Read-Host "Enter your Telegram Bot Token"
    
    if ([string]::IsNullOrEmpty($botToken)) {
        Err "Bot token cannot be empty."
        return Prompt-ForTelegram
    }
    
    Info ""
    Info "Retrieving your Chat ID using the Telegram API..."
    
    # Call Telegram getUpdates to read the latest messages sent to the bot
    try {
        $url = "https://api.telegram.org/bot$botToken/getUpdates"
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
        $data = $response.Content | ConvertFrom-Json
        
        # Get chat ID from the most recent message
        if ($data.ok -and $data.result) {
            $chatId = $data.result[-1].message.chat.id
            if ($chatId) {
                Success "Chat ID retrieved: $chatId"
                Info ""
                Success "Telegram credentials retrieved successfully!"
                return @{
                    "BotToken" = $botToken
                    "ChatId" = $chatId
                }
            }
        }
        
        throw "No messages found"
    } catch {
        Err "Could not retrieve Chat ID from Telegram API."
        Info ""
        Info "This means:"
        Info "   * You haven't sent a message to your bot yet, OR"
        Info "   * Your bot token is incorrect, OR"
        Info "   * Internet connection issue"
        Info ""
        Info "What to do:"
        Info "   1. Make sure you SENT A MESSAGE to your bot in Telegram"
        Info "   2. Check your bot token is copied correctly"
        Info "   3. Try setup again"
        Write-Host ""
        return Prompt-ForTelegram
    }
}

# Check if .env file exists
if (-not (Test-Path ".env")) {
    Info ""
    Info "FIRST-TIME SETUP - CREATING CONFIGURATION"
    Info ""
    
    Info "Creating .env file..."
    
    # Create a default .env file
    $envContent = @"
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
"@
    
    Set-Content -Path ".env" -Value $envContent -Encoding UTF8
    Success ".env file created with defaults"
    
    Info ""
    $adminPassword = Prompt-ForPassword "Enter Admin Password (minimum 8 characters)" $true
    
    # Always generate Kibana Server Password
    $kibanaPassword = Generate-Password
    Info "Kibana Server Password generated: $kibanaPassword"
    
    $readonlyPassword = Prompt-ForPassword "Enter Read-Only User Password (minimum 8 characters)" $true
    
    # Setup Telegram
    $telegramCreds = Prompt-ForTelegram
    
    # Update .env file with provided values
    Info "Updating .env configuration file..."
    
    $envContent = Get-Content ".env" -Raw
    $envContent = $envContent -replace '(?m)^ADMIN_PASSWORD=.*', "ADMIN_PASSWORD=$adminPassword"
    $envContent = $envContent -replace '(?m)^KIBANASERVER_PASSWORD=.*', "KIBANASERVER_PASSWORD=$kibanaPassword"
    $envContent = $envContent -replace '(?m)^READONLY_USER_PASSWORD=.*', "READONLY_USER_PASSWORD=$readonlyPassword"
    $envContent = $envContent -replace '(?m)^TELEGRAM_BOT_TOKEN=.*', "TELEGRAM_BOT_TOKEN=$($telegramCreds.BotToken)"
    $envContent = $envContent -replace '(?m)^TELEGRAM_CHAT_ID=.*', "TELEGRAM_CHAT_ID=$($telegramCreds.ChatId)"
    
    Set-Content -Path ".env" -Value $envContent -Encoding UTF8
    Success ".env file configured with your settings!"
    Info ""
} else {
    # Load existing .env file for later use
    $envContent = Get-Content ".env" -Raw
    if ($envContent -match 'ADMIN_PASSWORD=(.+?)$') { $adminPassword = $matches[1].Trim() }
    if ($envContent -match 'KIBANASERVER_PASSWORD=(.+?)$') { $kibanaPassword = $matches[1].Trim() }
    if ($envContent -match 'READONLY_USER_PASSWORD=(.+?)$') { $readonlyPassword = $matches[1].Trim() }
    if ($envContent -match 'TELEGRAM_BOT_TOKEN=(.+?)$') { $telegramBotToken = $matches[1].Trim() }
    if ($envContent -match 'TELEGRAM_CHAT_ID=(.+?)$') { $telegramChatId = $matches[1].Trim() }
}

# Verify required fields in .env
Info "Verifying .env configuration..."

$envContent = Get-Content ".env" -Raw

if (-not ($envContent -match "ADMIN_PASSWORD=")) {
    Err "ADMIN_PASSWORD not found in .env. Aborting setup."
    exit 1
}

if (-not ($envContent -match "KIBANASERVER_PASSWORD=")) {
    Err "KIBANASERVER_PASSWORD not found in .env. Aborting setup."
    exit 1
}

if (-not ($envContent -match "TELEGRAM_BOT_TOKEN=")) {
    Err "TELEGRAM_BOT_TOKEN not found in .env. Aborting setup."
    exit 1
}

if (-not ($envContent -match "TELEGRAM_CHAT_ID=")) {
    Err "TELEGRAM_CHAT_ID not found in .env. Aborting setup."
    exit 1
}

Success ".env file verification complete!"
Info ""

# Extract credentials from .env for use in the script
if ($envContent -match 'ADMIN_PASSWORD=(.+?)(?:\r?\n|$)') { $adminPassword = $matches[1].Trim() }
if ($envContent -match 'KIBANASERVER_PASSWORD=(.+?)(?:\r?\n|$)') { $kibanaPassword = $matches[1].Trim() }
if ($envContent -match 'READONLY_USER_PASSWORD=(.+?)(?:\r?\n|$)') { $readonlyPassword = $matches[1].Trim() }
if ($envContent -match 'TELEGRAM_BOT_TOKEN=(.+?)(?:\r?\n|$)') { $telegramBotToken = $matches[1].Trim() }
if ($envContent -match 'TELEGRAM_CHAT_ID=(.+?)(?:\r?\n|$)') { $telegramChatId = $matches[1].Trim() }

Info "Checking for passwords in .env file..."

$examplePath = "services/wazuh/config/wazuh_indexer/internal_users.yml.example"
$targetPath = "services/wazuh/config/wazuh_indexer/internal_users.yml"

if (Test-Path $examplePath) {
    Copy-Item $examplePath $targetPath -Force
    $hashedAny = $false
    
    # Check for admin password
    if ($adminPassword -and $adminPassword -notmatch "change-me") {
        Info "Found admin password. Generating password hash..."
        
        # Generate hash using Docker
        $adminHash = docker run --rm wazuh/wazuh-indexer:4.14.1 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$adminPassword" | ForEach-Object { $_.Trim() }
        
        $content = Get-Content $targetPath -Raw
        $content = $content -replace '\{ADMIN-PASSWORD-HASH\}', $adminHash
        Set-Content -Path $targetPath -Value $content -Encoding UTF8
        Success "Admin password hash generated successfully!"
        $hashedAny = $true
    }
    
    # Check for kibanaserver password
    if ($kibanaPassword -and $kibanaPassword -notmatch "change-me") {
        Info "Found kibanaserver password. Generating password hash..."
        
        # Generate hash using Docker
        $kibanaHash = docker run --rm wazuh/wazuh-indexer:4.14.1 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$kibanaPassword" | ForEach-Object { $_.Trim() }
        
        $content = Get-Content $targetPath -Raw
        $content = $content -replace '\{KIBANASERVER-PASSWORD-HASH\}', $kibanaHash
        Set-Content -Path $targetPath -Value $content -Encoding UTF8
        Success "Kibanaserver password hash generated successfully!"
        $hashedAny = $true
    }
    
    # Check for readonly_user password
    if ($readonlyPassword -and $readonlyPassword -notmatch "change-me") {
        Info "Found readonly_user password. Generating password hash..."
        
        # Generate hash using Docker
        $readonlyHash = docker run --rm wazuh/wazuh-indexer:4.14.1 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$readonlyPassword" | ForEach-Object { $_.Trim() }
        
        $content = Get-Content $targetPath -Raw
        $content = $content -replace '\{READONLY-USER-PASSWORD-HASH\}', $readonlyHash
        Set-Content -Path $targetPath -Value $content -Encoding UTF8
        Success "Readonly user password hash generated successfully!"
        $hashedAny = $true
    }
    
    if ($hashedAny) {
        Success "Created internal_users.yml with password hashes"
    } else {
        Warn "No ADMIN_PASSWORD or KIBANASERVER_PASSWORD found in .env file"
    }
} else {
    Warn "internal_users.yml.example not found"
}

Info "Generating Wazuh indexer certificates..." -ForegroundColor Cyan

# Run certificate generator and remove container when done
docker compose -f services/wazuh/generate-indexer-certs.yml run --rm generator

Success "Certificate generation complete!"

# Copy roles and roles_mapping files if they don't exist in the target directory
$rolesSource = "services/wazuh/config/wazuh_indexer/roles.yml"
$rolesMappingSource = "services/wazuh/config/wazuh_indexer/roles_mapping.yml"

if (Test-Path $rolesSource) {
    Info "Roles configuration file found: $rolesSource"
} else {
    Warn "Roles configuration file not found at $rolesSource"
}

if (Test-Path $rolesMappingSource) {
    Info "Roles mapping configuration file found: $rolesMappingSource"
} else {
    Warn "Roles mapping configuration file not found at $rolesMappingSource"
}

Info "Starting services..."

# Start all services
docker compose up -d --build

Success "All services started!"

# Wait for indexer to be ready
Info "Waiting for indexer to become available..."
$indexerUrl = "https://localhost:9200"
$maxIndexerAttempts = 30
$indexerAttempt = 0

while ($indexerAttempt -lt $maxIndexerAttempts) {
    try {
        $response = curl.exe -k -u "admin:$adminPassword" -s "$indexerUrl/_cluster/health" 2>$null
        if ($LASTEXITCODE -eq 0 -and $response -match "yellow|green") {
            Success "Indexer is available."
            break
        }
    } catch {
        # Continue waiting
    }
    
    $indexerAttempt++
    Info "Indexer not ready yet (attempt $indexerAttempt/$maxIndexerAttempts). Waiting 5 seconds..."
    Start-Sleep -Seconds 5
}

if ($indexerAttempt -lt $maxIndexerAttempts) {
    # Load custom roles into the indexer
    Info "Loading custom security roles..."
    
    # Run securityadmin.sh inside the running indexer container
    $rolesResult = docker compose exec wazuh.indexer bash -c "chmod +x /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh && JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /usr/share/wazuh-indexer/config/custom-security/roles.yml -t roles -icl -nhnv -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -cert /usr/share/wazuh-indexer/config/certs/admin.pem -key /usr/share/wazuh-indexer/config/certs/admin-key.pem -h localhost" 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Success "Custom roles loaded successfully!"
    } else {
        Warn "Could not load custom roles. Error: $rolesResult"
    }
    
    $mappingResult = docker compose exec wazuh.indexer bash -c "JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /usr/share/wazuh-indexer/config/custom-security/roles_mapping.yml -t rolesmapping -icl -nhnv -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -cert /usr/share/wazuh-indexer/config/certs/admin.pem -key /usr/share/wazuh-indexer/config/certs/admin-key.pem -h localhost" 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Success "Custom roles mapping loaded successfully!"
    } else {
        Warn "Could not load custom roles mapping. Error: $mappingResult"
    }
} else {
    Warn "Indexer did not become ready in time. Skipping custom role loading."
}

# Wait for dashboard to be ready and import custom dashboard
$dashboardUrl = "https://localhost:443"
$ndjsonPath = Join-Path $PSScriptRoot "services/wazuh/config/custom_dashboard/malware_dashboard.ndjson"

Info "Waiting for dashboard to become available..."

$maxAttempts = 30
$attempt = 0

# Poll dashboard status endpoint until it reports available
while ($attempt -lt $maxAttempts) {
    $statusResponse = curl.exe -s -k -u "admin:$adminPassword" "$dashboardUrl/api/status" 2>$null

    if ($LASTEXITCODE -eq 0 -and $statusResponse -match "available") {
        Success "Dashboard is available."
        break
    }

    $attempt++
    Info "Dashboard not ready yet (attempt $attempt/$maxAttempts). Waiting 10 seconds..."
    Start-Sleep -Seconds 10
}

if ($attempt -ge $maxAttempts) {
    Warn "Dashboard did not become ready in time. Skipping custom dashboard import."
} else {
    # Import the NDJSON saved objects file into the dashboard 
    $empty = curl.exe -X POST -s -k -u "admin:$adminPassword" `
        "$dashboardUrl/api/saved_objects/_import?overwrite=true" `
        -H "osd-xsrf: true" `
        --form "file=@$ndjsonPath"

    Success "Custom dashboard imported."
}

# Display final summary
Info ""
Info "=================================================="
Info "         SETUP COMPLETE - SUMMARY"
Info "=================================================="
Info ""
Info "Dashboard Access:"
Info "   URL: https://localhost:443"
Info "   Username: admin"
Info "   Password: $adminPassword"
Info ""
Info "Read-Only User Password: $readonlyPassword"
Info ""
Info "Telegram Bot Token: $telegramBotToken"
Info "Telegram Chat ID: $telegramChatId"
Info ""
Success "All services are now running!"
Info ""
