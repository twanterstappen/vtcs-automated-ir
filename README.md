# VTCS Project 25-26

A ready-to-run stack that ships:
- Wazuh manager, indexer, and dashboard (security monitoring)
- Malware API service (FastAPI)
- Ollama LLM service

This guide is written for non-technical users. Follow the steps in order and copy/paste the commands as shown.

## Architecture
```mermaid
flowchart TB
  A[Endpoint] --> B[Wazuh Agent]
  B --> C[Wazuh Manager]
  C --> D[Wazuh Indexer]
  D --> E[Wazuh Dashboard]

  C --> F{File hash}
  F -->|Ja| G[Malware API]
  G <--> H[Lokale Malware Database]
  G --> I{Malware bevestigd}

  I -->|Nee| D

  I -->|Ja| J[Ollama LLM]
  J --> K[Verrijkte uitleg]
  K --> D

  K --> L[Active Response remove threat]
  L --> M[File verwijderen of quarantaine]
  M --> D

  K --> N[Telegram alert]
  N --> O[Beheerder ontvangt melding]
  O --> D
```

## What you need
- Docker and Docker Compose installed
- Internet connection (images will be pulled on first run)
- At least 15 GB free disk space for images and data
- At least 8 GB RAM (absolute minimum 4 GB) and 2 CPU cores; more memory gives a smoother Wazuh dashboard
- Docker will start 5 containers: Wazuh manager, Wazuh indexer, Wazuh dashboard, malware-api, and ollama

## 1) Prepare the settings
1. Copy the environment example file:
   - Windows (PowerShell): `Copy-Item .env.example .env`
   - macOS/Linux (bash): `cp .env.example .env`
2. Open `.env` and set the passwords:
  - `ADMIN_PASSWORD` - used by Wazuh indexer/admin
  - `KIBANASERVER_PASSWORD` - used by the Wazuh dashboard
  - `READONLY_USER_PASSWORD` - used for normal users that are only allowed to use Wazuh.
  - Optionally change `MALWARE_API_KEY` and Ollama settings.
  - Pick strong, memorable passwords and do not commit `.env` to source control. keep it private and secure.

## 2) Run the setup (one time)
Run the script that matches your system from the project root:
- Windows (PowerShell): `./setup.ps1`
  - If you get an error about execution policy, first allow scripts to run (one time):
    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    ```
    Then run `./setup.ps1` again.
- macOS/Linux: `./setup.sh`

What the setup does for you:
- Generates SSL certificates for Wazuh indexer
- Creates `internal_users.yml` with hashed passwords from your `.env`
- Starts all containers with Docker Compose
- Reloads Wazuh security so the new passwords are active

If required passwords are missing in `.env`, the script stops and tells you what to add.

## 3) Using the services
- Wazuh Dashboard: https://localhost (use `kibanaserver` / your `KIBANASERVER_PASSWORD`)
- Malware API: http://localhost:8000 (API key from `.env`)


## Common actions
- Stop all: `docker compose down`
- Start again: `docker compose up -d`
- View container status: `docker compose ps`
- View dashboard logs: `docker logs vtcs-project-25-26-wazuh.dashboard-1 --tail 50`
- View indexer logs: `docker logs vtcs-project-25-26-wazuh.indexer-1 --tail 50`

## Troubleshooting
- Login fails on dashboard: ensure `.env` has correct `KIBANASERVER_PASSWORD`, re-run setup, then restart dashboard: `docker compose restart wazuh.dashboard`
- Admin auth fails: check `ADMIN_PASSWORD` in `.env`, re-run setup, try to reload security:
  `docker exec vtcs-project-25-26-wazuh.indexer-1 bash -c "JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/config/opensearch-security -icl -key /usr/share/wazuh-indexer/config/certs/admin-key.pem -cert /usr/share/wazuh-indexer/config/certs/admin.pem -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -h wazuh.indexer"`
- Ports in use: stop any service occupying 443, 8000, 9200, 11434, or 1514/1515.

## Where data lives
Docker volumes keep your data between runs (malware API DB, Wazuh data, dashboard config). Removing volumes will reset stored data.






## How to deploy the agent
This is a step-by-step guide to install the agent.

- Step 1. Extract the `install-wazuh-agent-gui-windows.zip` directory.
- Step 2. Run `install-wazuh-agent-gui.exe` and confirm the User Account Control prompt when it appears.
- Step 3. In the 'Wazuh manager IP' field, enter the Wazuh manager's IP address (usually the network gateway, e.g. x.x.x.1). It's advised to enter a descriptive agent name so you can identify it later. Click 'Install' to proceed. You will receive a notification that the Wazuh agent was installed successfully. We recommend clearing the log after installation by clicking 'Clear log'.
- Step 4. To verify the installation, navigate to 'ossec-agent' → 'active-response' → 'bin' where you'll find files including `remove-threat.exe`. (This is described later in this README.)

## How does the notification work
If a user accidentally opens malware on Windows or Linux, Wazuh can detect and delete the file. This behavior is implemented by the `remove-threat.exe` active response (mentioned above).

Warning: the `remove-threat.exe` active response may permanently delete files. Test this in a safe environment and ensure you have backups before enabling it on production systems.

- Step 1. Go to 'Summary' (first option under 'Agents management').
- Step 2. Click the host where the user opened the malware.
- Step 3. In the rule description you can see that the malware was detected and whether it was deleted or quarantined, including the file location.