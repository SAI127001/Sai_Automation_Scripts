#!/bin/bash
# =============================================================================
# Script Name:     code_database_backupgenerator.sh
# Author:          Terukula Sai (DevOps Engineer)
# Created On:      Oct 6, 2025
# Last Modified:   Oct 9, 2025
# Version:         v1.0
# Email:           codesai127.0.0.1@gmail.com
# Usage:           ./code_database_backupgenerator.sh
# =============================================================================
# Description:
# -----------------------------------------------------------------------------
# This automation script dynamically generates backup scripts for either:
#   1. Source Code Backups (Project directories)
#   2. Database Backups (MySQL, PostgreSQL, MongoDB, SQLite, MSSQL)
#
# Based on the user's input, it interactively creates a fully functional,
# standalone backup script in the current working directory with proper
# logging, folder management, and optional cloud integration.
#
# -----------------------------------------------------------------------------
# Key Features:
# -----------------------------------------------------------------------------
# ✅ Interactive CLI:
#     - Asks the user whether to generate a *Code Backup* or *Database Backup*.
#     - Prompts for necessary inputs such as source path, destination path,
#       database type, and credentials.
#
# ✅ Supported Databases:
#     - MySQL / MariaDB
#     - PostgreSQL
#     - MongoDB
#     - SQLite
#     - Microsoft SQL Server
#
# ✅ Cloud Upload Integration:
#     - Optional integration with AWS S3, Azure Blob Storage, or Google Cloud Storage.
#     - If selected, automatically appends respective upload commands to the
#       generated backup script.
#
# ✅ Backup Storage Logic:
#     - Backups are organized by weekday (Monday, Tuesday, …) to maintain a
#       7-day rotation structure.
#     - Logs are stored alongside backups for easy monitoring.
#
# ✅ Credentials Guidance:
#     - Prints a sample credentials file template (.my.cnf, .pgpass, etc.)
#       on the terminal for manual setup.
#     - Credentials are *not* stored by the generator to ensure security.
#
# ✅ Safe & Reliable:
#     - Uses `set -euo pipefail` for error handling.
#     - Verifies required utilities (mysqldump, zip, aws, etc.) before use.
#     - Adds colored, readable CLI outputs.
#
# -----------------------------------------------------------------------------
# Output:
# -----------------------------------------------------------------------------
# - Generates executable backup scripts such as:
#       backup_code_<project>.sh
#       backup_mysql_<db>.sh
#       backup_postgres_<db>.sh
#
# - Each generated script:
#       → Creates date-based backup folders
#       → Logs operations with timestamps
#       → Optionally uploads backup to cloud
#
# -----------------------------------------------------------------------------
# Example Usages:
# -----------------------------------------------------------------------------
#   1️⃣ Generate Code Backup Script:
#       $ ./code_database_backupgenerator.sh
#       > Do you want to create a Code backup or Database backup? (code/db): code
#       > Enter source path of code: /var/www/project
#       > Enter destination path: /home/ubuntu/backups/code
#       → Output: backup_code_project.sh
#
#   2️⃣ Generate Database Backup Script:
#       $ ./code_database_backupgenerator.sh
#       > Do you want to create a Code backup or Database backup? (code/db): db
#       > Enter database type: mysql
#       > Enter database name: myapp_prod
#       > Enter destination path: /home/ubuntu/backups/db
#       → Output: backup_mysql_myapp_prod.sh
#
# -----------------------------------------------------------------------------
# Notes:
# -----------------------------------------------------------------------------
# - Ensure the credentials files (~/.my.cnf, ~/.pgpass, etc.) exist and have
#   correct permissions (chmod 600).
# - Requires AWS CLI, Azure CLI, or GCloud SDK if cloud integration is enabled.
# - Compatible with all major Linux distributions (Ubuntu, CentOS, Debian).
#
# =============================================================================

set -euo pipefail

# ==== COLORS ====
GREEN="\e[32m"
CYAN="\e[36m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"

# ==== FUNCTIONS ====
banner() {
  echo -e "${CYAN}\n============================================"
  echo -e "     🔄 Universal Backup Script Generator"
  echo -e "============================================${RESET}\n"
}

prompt() {
  local message="$1"
  read -rp "$(echo -e "${YELLOW}$message${RESET}") " REPLY
  echo "$REPLY"
}

# ==== MULTI-CLOUD UPLOAD LOGIC ====
generate_cloud_upload_logic() {
  local SCRIPT_FILE="$1"
  local INCLUDE_CLOUD
  INCLUDE_CLOUD=$(prompt "Do you want to integrate cloud upload? (yes/no): ")

  if [[ "$INCLUDE_CLOUD" =~ ^(yes|y)$ ]]; then
    local CLOUD_PROVIDER
    CLOUD_PROVIDER=$(prompt "Choose cloud provider (aws/azure/gcp): ")

    if [[ "$CLOUD_PROVIDER" =~ ^(aws)$ ]]; then
      local S3_BUCKET
      S3_BUCKET=$(prompt "Enter S3 bucket name: ")
      local S3_PATH
      S3_PATH=$(prompt "Enter S3 path (e.g. prod/db_backups): ")
      cat <<EOF >> "$SCRIPT_FILE"

if ! command -v aws >/dev/null 2>&1; then
  log "ERROR: aws CLI not found!"
  exit 1
fi

if aws s3 cp "\$BACKUP_FILE" "s3://$S3_BUCKET/$S3_PATH/\$DAY_OF_WEEK/\$(basename \$BACKUP_FILE)" 2>>"\$LOG_FILE"; then
  log "S3 upload successful: s3://$S3_BUCKET/$S3_PATH/\$DAY_OF_WEEK/\$(basename \$BACKUP_FILE)"
else
  log "ERROR: S3 upload failed!"
  exit 1
fi
EOF

    elif [[ "$CLOUD_PROVIDER" =~ ^(azure)$ ]]; then
      local AZURE_CONTAINER
      AZURE_CONTAINER=$(prompt "Enter Azure container name: ")
      local AZURE_PATH
      AZURE_PATH=$(prompt "Enter Azure path (e.g. dev/backups): ")
      cat <<EOF >> "$SCRIPT_FILE"

if ! command -v az >/dev/null 2>&1; then
  log "ERROR: Azure CLI not found!"
  exit 1
fi

if az storage blob upload --account-name yourAccountName --container-name $AZURE_CONTAINER --file "\$BACKUP_FILE" --name "$AZURE_PATH/\$DAY_OF_WEEK/\$(basename \$BACKUP_FILE)" --overwrite 2>>"\$LOG_FILE"; then
  log "Azure upload successful: $AZURE_PATH/\$DAY_OF_WEEK/\$(basename \$BACKUP_FILE)"
else
  log "ERROR: Azure upload failed!"
  exit 1
fi
EOF

    elif [[ "$CLOUD_PROVIDER" =~ ^(gcp|google)$ ]]; then
      local GCS_BUCKET
      GCS_BUCKET=$(prompt "Enter GCS bucket name: ")
      local GCS_PATH
      GCS_PATH=$(prompt "Enter GCS path (e.g. backups/db): ")
      cat <<EOF >> "$SCRIPT_FILE"

if ! command -v gsutil >/dev/null 2>&1; then
  log "ERROR: gsutil not found!"
  exit 1
fi

if gsutil cp "\$BACKUP_FILE" "gs://$GCS_BUCKET/$GCS_PATH/\$DAY_OF_WEEK/\$(basename \$BACKUP_FILE)" 2>>"\$LOG_FILE"; then
  log "GCS upload successful: gs://$GCS_BUCKET/$GCS_PATH/\$DAY_OF_WEEK/\$(basename \$BACKUP_FILE)"
else
  log "ERROR: GCS upload failed!"
  exit 1
fi
EOF
    fi
  fi
}

# ==== DATABASE BACKUP SCRIPT GENERATOR ====
generate_db_script() {
  echo -e "${CYAN}\nCreating Database Backup Script...${RESET}\n"
  local DB_TYPE
  DB_TYPE=$(prompt "Enter database type (mysql/postgres/mongodb/sqlite/mssql): ")
  local DB_NAME
  DB_NAME=$(prompt "Enter database name: ")
  local DEST_PATH
  DEST_PATH=$(prompt "Enter destination backup path (e.g. /home/ubuntu/backups): ")

  echo -e "${YELLOW}\n--- CREDENTIAL FILE SETUP ---${RESET}"

  case "$DB_TYPE" in
    mysql)
      echo -e "${YELLOW}\nCopy and create the following as ${CYAN}~/.my.cnf${RESET}\n"
      cat <<EOF
[client]
user=backup_user
password=YourPasswordHere
host=localhost
EOF
      ;;
    postgres)
      echo -e "${YELLOW}\nCopy and create the following as ${CYAN}~/.pgpass${RESET}\n"
      cat <<EOF
localhost:5432:$DB_NAME:backup_user:YourPasswordHere
EOF
      ;;
    mongodb)
      echo -e "${YELLOW}\nMongoDB doesn’t require a special file, store credentials in environment or prompt later.${RESET}\n"
      ;;
    sqlite)
      echo -e "${YELLOW}\nSQLite doesn’t require credentials. Backup will be direct file copy.${RESET}\n"
      ;;
    mssql)
      echo -e "${YELLOW}\nCopy and create the following as ${CYAN}~/.mssql.cnf${RESET}\n"
      cat <<EOF
[client]
user=sa
password=YourPasswordHere
host=localhost
EOF
      ;;
    *)
      echo -e "${RED}Invalid database type.${RESET}"
      exit 1
      ;;
  esac

  echo -e "\n${GREEN}⚙️ Save credentials and ensure chmod 600 on the file.${RESET}\n"

  local CURRENT_DIR
  CURRENT_DIR=$(pwd)
  local SCRIPT_FILE="$CURRENT_DIR/backup_${DB_TYPE}_${DB_NAME}.sh"

  echo -e "${CYAN}Generating script: ${SCRIPT_FILE}${RESET}"

  cat <<EOF > "$SCRIPT_FILE"
#!/bin/bash
set -euo pipefail

DB_NAME="$DB_NAME"
DB_TYPE="$DB_TYPE"
BACKUP_BASE_DIR="$DEST_PATH/\$DB_NAME"
DAY_OF_WEEK=\$(date +"%A")
BACKUP_DIR="\$BACKUP_BASE_DIR/\$DAY_OF_WEEK"
LOG_FILE="$DEST_PATH/${DB_TYPE}_backup_log_\$DAY_OF_WEEK.log"
mkdir -p "\$BACKUP_DIR"

log() {
  echo "[\$(date)] \$1" | tee -a "\$LOG_FILE"
}

case "\$DB_TYPE" in
  mysql)
    BACKUP_FILE="\$BACKUP_DIR/\${DB_NAME}.sql"
    log "Starting MySQL backup..."
    mysqldump --defaults-extra-file="\$HOME/.my.cnf" --no-tablespaces "\$DB_NAME" > "\$BACKUP_FILE" 2>>"\$LOG_FILE"
    ;;
  postgres)
    BACKUP_FILE="\$BACKUP_DIR/\${DB_NAME}.sql"
    log "Starting PostgreSQL backup..."
    PGPASSFILE="\$HOME/.pgpass" pg_dump -U backup_user -h localhost "\$DB_NAME" > "\$BACKUP_FILE" 2>>"\$LOG_FILE"
    ;;
  mongodb)
    BACKUP_FILE="\$BACKUP_DIR/\${DB_NAME}.gz"
    log "Starting MongoDB backup..."
    mongodump --db "\$DB_NAME" --archive="\$BACKUP_FILE" --gzip 2>>"\$LOG_FILE"
    ;;
  sqlite)
    BACKUP_FILE="\$BACKUP_DIR/\${DB_NAME}.db"
    log "Starting SQLite backup..."
    cp "\$DB_NAME" "\$BACKUP_FILE"
    ;;
  mssql)
    BACKUP_FILE="\$BACKUP_DIR/\${DB_NAME}.bak"
    log "Starting MSSQL backup..."
    sqlcmd -S localhost -U sa -P 'YourPasswordHere' -Q "BACKUP DATABASE [\$DB_NAME] TO DISK='\$BACKUP_FILE'" 2>>"\$LOG_FILE"
    ;;
esac

if [ -s "\$BACKUP_FILE" ]; then
  log "Backup successful: \$BACKUP_FILE"
else
  log "ERROR: Backup failed or empty file."
  exit 1
fi
EOF

  generate_cloud_upload_logic "$SCRIPT_FILE"
  echo 'log "Backup process completed successfully."' >> "$SCRIPT_FILE"
  chmod +x "$SCRIPT_FILE"

  echo -e "\n${GREEN}✅ Database backup script created successfully: $SCRIPT_FILE${RESET}\n"
}

# ==== CODE BACKUP SCRIPT ====
generate_code_script() {
  echo -e "${CYAN}\nCreating Code Backup Script...${RESET}\n"
  local SOURCE_PATH
  SOURCE_PATH=$(prompt "Enter source path of code (e.g. /var/www/project): ")
  local DEST_PATH
  DEST_PATH=$(prompt "Enter destination backup path (e.g. /home/ubuntu/backups/code): ")
  local PROJECT_NAME
  PROJECT_NAME=$(basename "$SOURCE_PATH")
  local CURRENT_DIR
  CURRENT_DIR=$(pwd)
  local SCRIPT_FILE="$CURRENT_DIR/backup_code_${PROJECT_NAME}.sh"

  echo -e "${CYAN}Generating script in current directory: ${SCRIPT_FILE}${RESET}"

  cat <<EOF > "$SCRIPT_FILE"
#!/bin/bash
set -euo pipefail

PROJECT_NAME="$PROJECT_NAME"
SOURCE_DIR="$SOURCE_PATH"
BACKUP_BASE_DIR="$DEST_PATH/\$PROJECT_NAME"
DAY_OF_WEEK=\$(date +"%A")
BACKUP_DIR="\$BACKUP_BASE_DIR/\$DAY_OF_WEEK"
BACKUP_FILE="\$BACKUP_DIR/\${PROJECT_NAME}.zip"
LOG_FILE="$DEST_PATH/code_backup_log_\$DAY_OF_WEEK.log"

mkdir -p "\$BACKUP_DIR"

log() {
  echo "[\$(date)] \$1" | tee -a "\$LOG_FILE"
}

if ! command -v zip >/dev/null 2>&1; then
  log "ERROR: zip not found!"
  exit 1
fi

log "Starting code backup..."
zip -r -q "\$BACKUP_FILE" "\$SOURCE_DIR" 2>>"\$LOG_FILE"

if [ -s "\$BACKUP_FILE" ]; then
  log "Code backup successful: \$BACKUP_FILE"
else
  log "ERROR: Code backup failed or empty file."
  exit 1
fi
EOF

  generate_cloud_upload_logic "$SCRIPT_FILE"
  echo 'log "Code backup process completed successfully."' >> "$SCRIPT_FILE"
  chmod +x "$SCRIPT_FILE"

  echo -e "\n${GREEN}✅ Code backup script created successfully: $SCRIPT_FILE${RESET}\n"
}

# ==== MAIN ====
banner
CHOICE=$(prompt "Do you want to create a Code backup or Database backup? (code/db): ")

if [[ "$CHOICE" =~ ^(db|database)$ ]]; then
  generate_db_script
elif [[ "$CHOICE" =~ ^(code)$ ]]; then
  generate_code_script
else
  echo -e "${RED}Invalid choice. Please run again with 'code' or 'db'.${RESET}"
  exit 1
fi

echo -e "${GREEN}🎯 Backup script generation complete.${RESET}\n"
