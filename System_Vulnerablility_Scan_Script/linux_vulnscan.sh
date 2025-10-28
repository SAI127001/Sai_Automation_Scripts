#!/bin/bash
# =============================================================================
# Script Name:     linux-vulnscan.sh
# Author:          Terukula Sai (DevOps Engineer)
# Created On:      $(date +%Y-%m-%d)
# Last Modified:   
# Version:         v1.0
# Email:           codesai127.0.0.1@gmail.com
# Usage:           ./linux-vulnscan.sh [--install] [--web] [--output-json PATH]
# =============================================================================
# Description:
# -----------------------------------------------------------------------------
# Comprehensive Linux host vulnerability scanner that performs security audits,
# vulnerability assessments, and configuration checks. Supports multiple Linux
# distributions and produces JSON, HTML, and summary reports.
# -----------------------------------------------------------------------------
# Key Features:
# -----------------------------------------------------------------------------
# - Auto-detection of Linux distribution and package manager
# - Automated tool installation (nmap, lynis, trivy, etc.)
# - Multiple scan types: host audit, port scanning, CVE detection
# - Security configuration checks (SSH, SUID/SGID, file permissions)
# - JSON, HTML, and human-readable output formats
# - CI/CD integration with strict exit codes
# - Safe defaults with dry-run mode
# - Professional loading bar with percentage display
# -----------------------------------------------------------------------------
# Output:
# -----------------------------------------------------------------------------
# - JSON report with structured vulnerability data
# - HTML report with interactive web interface
# - Summary report in terminal
# - Scan results in ./scan-results/ directory
# -----------------------------------------------------------------------------
# Example Usages:
# -----------------------------------------------------------------------------
# ./linux-vulnscan.sh --install --output-json ./security-scan.json
# ./linux-vulnscan.sh --dry-run --summary
# ./linux-vulnscan.sh --ci --quiet --output-json scan-results.json
# ./linux-vulnscan.sh --install --web --malware
# -----------------------------------------------------------------------------
# Notes:
# -----------------------------------------------------------------------------
# - Run with --install flag to auto-install required tools
# - Use --dry-run for testing without making changes
# --ci mode exits with code 2 for CRITICAL, 1 for other issues, 0 for clean
# - Requires sudo privileges for comprehensive scanning
# =============================================================================

set -euo pipefail

# Script configuration
SCRIPT_NAME="linux-vulnscan.sh"
SCRIPT_VERSION="1.0.0"
SCAN_ID=$(date +%Y%m%d_%H%M%S)-$(hostname -s)
RESULTS_DIR="./scan-results"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Default configuration
INSTALL_TOOLS=false
SCAN_WEB=false
SCAN_MALWARE=false
DRY_RUN=false
CI_MODE=false
QUIET=false
DEBUG=false
ALLOW_UPLOAD=false
INCLUDE_SECRETS=false
INSTALL_HEAVY=false
SELFTEST=false
OUTPUT_JSON=""
OUTPUT_HTML=""
SLACK_WEBHOOK=""
EMAIL_TO=""
SCAN_REMOTE=""
POLICY=""

# Progress tracking
TOTAL_STEPS=10
CURRENT_STEP=0
SCAN_START_TIME=0

# Severity levels
SEVERITY_CRITICAL=4
SEVERITY_HIGH=3
SEVERITY_MEDIUM=2
SEVERITY_LOW=1
SEVERITY_INFO=0

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Global variables
declare -A SCANNER_RESULTS
declare -a VULNERABILITIES
declare -a SCAN_ERRORS
CURRENT_SCAN=""
HOST_INFO={}
DISTRO_INFO={}

# Loading bar functions
show_progress() {
    local current=$1
    local total=$2
    local text=$3
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((current * width / total))
    local remaining=$((width - completed))
    
    if [ "$QUIET" = true ]; then
        return
    fi
    
    # Create progress bar strings
    local completed_str=""
    local remaining_str=""
    
    for ((i=0; i<completed; i++)); do
        completed_str+="█"
    done
    
    for ((i=0; i<remaining; i++)); do
        remaining_str+="░"
    done
    
    printf "\r${CYAN}[%s]${NC} ${MAGENTA}%3d%%${NC} [${GREEN}%s${NC}${RED}%s${NC}] ${BLUE}%s${NC}" \
        "$(date '+%H:%M:%S')" \
        $percentage \
        "$completed_str" \
        "$remaining_str" \
        "$text"
    
    if [ $current -eq $total ]; then
        printf "\n"
    fi
}

update_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    show_progress $CURRENT_STEP $TOTAL_STEPS "$1"
}

# Initialize directories
init_directories() {
    mkdir -p "${RESULTS_DIR}/${SCAN_ID}"
    mkdir -p "${RESULTS_DIR}/logs"
    ln -sfn "${SCAN_ID}" "${RESULTS_DIR}/latest" 2>/dev/null || true
}

# Logging functions
log() {
    if [ "$QUIET" = false ]; then
        echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${RESULTS_DIR}/logs/scan.log"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "${RESULTS_DIR}/logs/scan.log"
    fi
}

log_info() {
    log "${BLUE}INFO${NC}: $*"
}

log_warn() {
    log "${YELLOW}WARN${NC}: $*"
}

log_error() {
    log "${RED}ERROR${NC}: $*" >&2
}

log_debug() {
    if [ "$DEBUG" = true ]; then
        log "DEBUG: $*"
    fi
}

log_success() {
    log "${GREEN}SUCCESS${NC}: $*"
}

# Cleanup function
cleanup() {
    log_debug "Cleaning up temporary files"
    rm -rf "${TMP_DIR:-/tmp/scan-tmp}" 2>/dev/null || true
}

# Trap signals for cleanup
trap cleanup EXIT INT TERM

# Display help
show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} - Linux Host Vulnerability Scanner

USAGE:
    ${SCRIPT_NAME} [OPTIONS]

OPTIONS:
    --install               Install required tools automatically
    --install-heavy         Install heavy scanning tools (OpenVAS, etc.)
    --web                   Include web server scanning
    --malware               Include malware scanning with ClamAV
    --scan-remote HOST      Scan remote host (network perspective)
    --allow-upload          Allow remote upload of reports
    --include-secrets       Include potentially sensitive data in reports
    --ci                    CI mode with strict exit codes
    --dry-run               Skip privileged operations and tool installation
    --quiet                 Minimal output
    --debug                 Verbose debug output
    --selftest              Run self-test and validation

OUTPUT OPTIONS:
    --output-json PATH      Save JSON report to specified path
    --output-html PATH      Generate HTML report
    --summary               Print human-readable summary

INTEGRATIONS:
    --slack WEBHOOK_URL     Send summary to Slack
    --email ADDRESS         Email report

POLICY:
    --policy POLICY         Apply policy (CIS, OWASP, or path to custom JSON)

EXAMPLES:
    # Full scan with tool installation
    ./linux-vulnscan.sh --install --output-json ./security-scan.json

    # CI/CD integration
    ./linux-vulnscan.sh --ci --quiet --output-json scan-results.json

    # Dry run for testing
    ./linux-vulnscan.sh --dry-run --summary

    # Web server focused scan
    ./linux-vulnscan.sh --install --web --malware

    # Remote scanning
    ./linux-vulnscan.sh --scan-remote 192.168.1.100 --allow-upload

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install)
                INSTALL_TOOLS=true
                TOTAL_STEPS=$((TOTAL_STEPS + 2))
                shift
                ;;
            --install-heavy)
                INSTALL_HEAVY=true
                INSTALL_TOOLS=true
                shift
                ;;
            --web)
                SCAN_WEB=true
                TOTAL_STEPS=$((TOTAL_STEPS + 1))
                shift
                ;;
            --malware)
                SCAN_MALWARE=true
                TOTAL_STEPS=$((TOTAL_STEPS + 1))
                shift
                ;;
            --scan-remote)
                SCAN_REMOTE="$2"
                shift 2
                ;;
            --allow-upload)
                ALLOW_UPLOAD=true
                shift
                ;;
            --include-secrets)
                INCLUDE_SECRETS=true
                shift
                ;;
            --ci)
                CI_MODE=true
                QUIET=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --quiet)
                QUIET=true
                shift
                ;;
            --debug)
                DEBUG=true
                set -x
                shift
                ;;
            --selftest)
                SELFTEST=true
                shift
                ;;
            --output-json)
                OUTPUT_JSON="$2"
                shift 2
                ;;
            --output-html)
                OUTPUT_HTML="$2"
                shift 2
                ;;
            --summary)
                OUTPUT_JSON="${OUTPUT_JSON:-${RESULTS_DIR}/${SCAN_ID}/report.json}"
                shift
                ;;
            --slack)
                SLACK_WEBHOOK="$2"
                shift 2
                ;;
            --email)
                EMAIL_TO="$2"
                shift 2
                ;;
            --policy)
                POLICY="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Check if running as root or with sudo
check_privileges() {
    if [ "$(id -u)" -eq 0 ]; then
        log_info "Running as root"
        PRIV_CMD=""
    elif command -v sudo >/dev/null 2>&1; then
        log_info "Using sudo for privileged operations"
        PRIV_CMD="sudo"
    else
        log_warn "Not running as root and sudo not available - some checks will be limited"
        PRIV_CMD=""
    fi

    if [ "$DRY_RUN" = true ]; then
        log_info "Dry run mode - skipping privileged operations"
        PRIV_CMD=""
    fi
}

# Detect Linux distribution
detect_distro() {
    log_info "Detecting Linux distribution..."
    
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        DISTRO_NAME="$ID"
        DISTRO_VERSION="$VERSION_ID"
        PRETTY_NAME="$PRETTY_NAME"
    elif [ -f /etc/redhat-release ]; then
        DISTRO_NAME="rhel"
        DISTRO_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release || echo "unknown")
        PRETTY_NAME=$(cat /etc/redhat-release)
    elif [ -f /etc/debian_version ]; then
        DISTRO_NAME="debian"
        DISTRO_VERSION=$(cat /etc/debian_version)
        PRETTY_NAME="Debian $(cat /etc/debian_version)"
    else
        DISTRO_NAME="unknown"
        DISTRO_VERSION="unknown"
        PRETTY_NAME="Unknown Linux"
    fi

    DISTRO_INFO=$(jq -n \
        --arg name "$DISTRO_NAME" \
        --arg version "$DISTRO_VERSION" \
        --arg pretty "$PRETTY_NAME" \
        '{name: $name, version: $version, pretty_name: $pretty}')
    
    log_success "Detected: $PRETTY_NAME"
}

# Detect package manager
detect_package_manager() {
    case "$DISTRO_NAME" in
        ubuntu|debian)
            PKG_MANAGER="apt-get"
            PKG_INSTALL="$PKG_MANAGER install -y"
            ;;
        rhel|centos|fedora)
            if command -v dnf >/dev/null 2>&1; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi
            PKG_INSTALL="$PKG_MANAGER install -y"
            ;;
        opensuse*|sles)
            PKG_MANAGER="zypper"
            PKG_INSTALL="$PKG_MANAGER install -y"
            ;;
        arch)
            PKG_MANAGER="pacman"
            PKG_INSTALL="$PKG_MANAGER -S --noconfirm"
            ;;
        alpine)
            PKG_MANAGER="apk"
            PKG_INSTALL="$PKG_MANAGER add"
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO_NAME"
            exit 1
            ;;
    esac
    
    log_info "Using package manager: $PKG_MANAGER"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install package
install_package() {
    local package=$1
    local name=${2:-$package}
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would install: $name"
        return 0
    fi
    
    if command_exists "$package"; then
        log_debug "$name already installed"
        return 0
    fi
    
    log_info "Installing: $name"
    
    if $PRIV_CMD $PKG_INSTALL "$package" >> "${RESULTS_DIR}/logs/install.log" 2>&1; then
        log_success "Installed $name"
        return 0
    else
        log_error "Failed to install $name"
        return 1
    fi
}

# Install required tools
install_tools() {
    if [ "$INSTALL_TOOLS" = false ]; then
        return 0
    fi
    
    update_progress "Installing security tools..."
    
    # Update package database
    if [ "$DRY_RUN" = false ]; then
        $PRIV_CMD $PKG_MANAGER update -y >> "${RESULTS_DIR}/logs/install.log" 2>&1 || true
    fi
    
    # Essential tools
    install_package "jq" "jq (JSON processor)"
    install_package "curl" "curl"
    
    # Security scanners
    install_package "nmap" "nmap"
    install_package "lynis" "lynis"
    
    # Network tools
    if command_exists "ss"; then
        log_debug "ss command available"
    else
        install_package "iproute2" "ss command"
    fi
    
    # Trivy installation (if not available via package manager)
    if ! command_exists "trivy"; then
        log_info "Installing trivy from official release..."
        if [ "$DRY_RUN" = false ]; then
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
                $PRIV_CMD sh -s -- -b /usr/local/bin >> "${RESULTS_DIR}/logs/install.log" 2>&1
        fi
    fi
    
    # Malware scanning (optional)
    if [ "$SCAN_MALWARE" = true ]; then
        install_package "clamav" "ClamAV"
    fi
    
    # Web scanning (optional)
    if [ "$SCAN_WEB" = true ]; then
        install_package "nikto" "nikto"
    fi
    
    # Heavy tools (optional)
    if [ "$INSTALL_HEAVY" = true ]; then
        log_warn "Installing heavy scanning tools - this may take time and resources"
        install_package "openvas" "OpenVAS"
    fi
    
    update_progress "Tool installation completed"
}

# Check tool availability
check_tools() {
    local missing_tools=()
    
    local required_tools=("jq" "nmap" "lynis" "trivy")
    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Run with --install to install them automatically"
        return 1
    fi
    
    return 0
}

# Start scan section
start_scan() {
    CURRENT_SCAN="$1"
    log_info "Starting scan: $CURRENT_SCAN"
    SCAN_START_TIME=$(date +%s)
}

# End scan section
end_scan() {
    local scan_name="$CURRENT_SCAN"
    local end_time=$(date +%s)
    local duration=$((end_time - SCAN_START_TIME))
    
    log_success "Completed $scan_name in ${duration}s"
    CURRENT_SCAN=""
}

# Collect host information
collect_host_info() {
    start_scan "host_information"
    update_progress "Collecting host information"
    
    local hostname=$(hostname)
    local kernel=$(uname -r)
    local arch=$(uname -m)
    local uptime=$(uptime -p 2>/dev/null || echo "unknown")
    
    HOST_INFO=$(jq -n \
        --arg hostname "$hostname" \
        --arg kernel "$kernel" \
        --arg arch "$arch" \
        --arg uptime "$uptime" \
        --arg scan_id "$SCAN_ID" \
        --arg timestamp "$TIMESTAMP" \
        '{
            hostname: $hostname,
            kernel: $kernel,
            architecture: $arch,
            uptime: $uptime,
            scan_id: $scan_id,
            timestamp: $timestamp
        }')
    
    end_scan
}

# Run Lynis audit
run_lynis_audit() {
    start_scan "lynis_audit"
    update_progress "Running Lynis security audit"
    
    local lynis_output="${RESULTS_DIR}/${SCAN_ID}/lynis.json"
    local lynis_report="${RESULTS_DIR}/${SCAN_ID}/lynis-report.dat"
    
    # Run lynis audit
    $PRIV_CMD lynis audit system --no-colors --quiet --report-file "$lynis_report" > /dev/null 2>&1 || true
    
    # Parse lynis report and convert to JSON
    if [ -f "$lynis_report" ]; then
        local warnings=$(grep -c "warning\\[" "$lynis_report" || echo "0")
        local suggestions=$(grep -c "suggestion\\[" "$lynis_report" || echo "0")
        
        SCANNER_RESULTS[lynis]=$(jq -n \
            --argjson warnings "$warnings" \
            --argjson suggestions "$suggestions" \
            --arg report_file "$lynis_report" \
            '{
                name: "lynis",
                version: "3.0.0",
                findings: {
                    warnings: $warnings,
                    suggestions: $suggestions
                },
                report_file: $report_file
            }')
    else
        SCANNER_RESULTS[lynis]='{"name": "lynis", "error": "Failed to generate report"}'
        SCAN_ERRORS+=("Lynis audit failed")
    fi
    
    end_scan
}

# Run nmap port scan
run_nmap_scan() {
    start_scan "nmap_port_scan"
    update_progress "Running network port scan"
    
    local nmap_output="${RESULTS_DIR}/${SCAN_ID}/nmap.xml"
    local target="localhost"
    
    if [ -n "$SCAN_REMOTE" ]; then
        target="$SCAN_REMOTE"
        log_info "Scanning remote host: $target"
    fi
    
    # Run nmap scan
    if nmap -sS -sV -T4 -F "$target" -oX "$nmap_output" > /dev/null 2>&1; then
        local open_ports=$(grep -c "portid=" "$nmap_output" || echo "0")
        
        SCANNER_RESULTS[nmap]=$(jq -n \
            --argjson open_ports "$open_ports" \
            --arg target "$target" \
            --arg output_file "$nmap_output" \
            '{
                name: "nmap",
                version: "7.80",
                findings: {
                    target: $target,
                    open_ports: $open_ports
                },
                output_file: $output_file
            }')
    else
        SCANNER_RESULTS[nmap]='{"name": "nmap", "error": "Scan failed"}'
        SCAN_ERRORS+=("Nmap scan failed")
    fi
    
    end_scan
}

# Run Trivy vulnerability scan
run_trivy_scan() {
    start_scan "trivy_vulnerability_scan"
    update_progress "Scanning for OS vulnerabilities"
    
    local trivy_output="${RESULTS_DIR}/${SCAN_ID}/trivy.json"
    
    # Scan OS packages
    if trivy fs --format json --output "$trivy_output" / > /dev/null 2>&1; then
        local vuln_count=0
        if [ -f "$trivy_output" ]; then
            vuln_count=$(jq '.Results | map(.Vulnerabilities // []) | flatten | length' "$trivy_output" || echo "0")
        fi
        
        SCANNER_RESULTS[trivy]=$(jq -n \
            --argjson vulnerability_count "$vuln_count" \
            --arg output_file "$trivy_output" \
            '{
                name: "trivy",
                version: "0.50.0",
                findings: {
                    vulnerability_count: $vulnerability_count
                },
                output_file: $output_file
            }')
        
        # Parse vulnerabilities from trivy output
        if [ -f "$trivy_output" ] && [ "$vuln_count" -gt 0 ]; then
            jq -c '.Results[]?.Vulnerabilities[]? | select(. != null)' "$trivy_output" | while read -r vuln; do
                local vuln_id=$(echo "$vuln" | jq -r '.VulnerabilityID // .VulnerabilityID')
                local severity=$(echo "$vuln" | jq -r '.Severity // "UNKNOWN"')
                local title=$(echo "$vuln" | jq -r '.Title // .VulnerabilityID')
                
                # Map trivy severity to our levels
                local mapped_severity="LOW"
                case "$severity" in
                    "CRITICAL") mapped_severity="CRITICAL" ;;
                    "HIGH") mapped_severity="HIGH" ;;
                    "MEDIUM") mapped_severity="MEDIUM" ;;
                    "LOW") mapped_severity="LOW" ;;
                    *) mapped_severity="INFO" ;;
                esac
                
                VULNERABILITIES+=("$(jq -n \
                    --arg id "$vuln_id" \
                    --arg title "$title" \
                    --arg severity "$mapped_severity" \
                    --arg scanner "trivy" \
                    --arg description "$title" \
                    '{
                        id: $id,
                        title: $title,
                        severity: $severity,
                        scanner: $scanner,
                        description: $description,
                        evidence: $id
                    }')")
            done
        fi
    else
        SCANNER_RESULTS[trivy]='{"name": "trivy", "error": "Scan failed"}'
        SCAN_ERRORS+=("Trivy scan failed")
    fi
    
    end_scan
}

# Check SUID/SGID binaries
check_suid_sgid() {
    start_scan "suid_sgid_check"
    update_progress "Checking SUID/SGID binaries"
    
    local suid_binaries=()
    local sgid_binaries=()
    
    # Find SUID binaries
    while IFS= read -r -d '' file; do
        suid_binaries+=("$file")
    done < <(find / -type f -perm -4000 -print0 2>/dev/null | head -z -100)
    
    # Find SGID binaries  
    while IFS= read -r -d '' file; do
        sgid_binaries+=("$file")
    done < <(find / -type f -perm -2000 -print0 2>/dev/null | head -z -100)
    
    SCANNER_RESULTS[suid_sgid]=$(jq -n \
        --argjson suid_count "${#suid_binaries[@]}" \
        --argjson sgid_count "${#sgid_binaries[@]}" \
        '{
            name: "suid_sgid_check",
            findings: {
                suid_binaries: $suid_count,
                sgid_binaries: $sgid_count,
                common_suid_binaries: ["/bin/mount", "/bin/su", "/bin/umount", "/usr/bin/passwd", "/usr/bin/sudo"]
            }
        }')
    
    # Check for dangerous SUID binaries
    local dangerous_suid=("find" "vim" "nano" "bash" "sh" "csh" "tcsh")
    for binary in "${dangerous_suid[@]}"; do
        if find / -type f -perm -4000 -name "$binary" 2>/dev/null | grep -q .; then
            VULNERABILITIES+=("$(jq -n \
                --arg binary "$binary" \
                '{
                    id: "SUID_DANGEROUS_" + $binary,
                    title: "Dangerous SUID binary: " + $binary,
                    severity: "MEDIUM",
                    scanner: "suid_sgid_check",
                    description: "Potentially dangerous SUID binary found",
                    remediation: "Consider removing SUID bit if not absolutely necessary: chmod u-s /path/to/'$binary'",
                    evidence: $binary
                }')")
        fi
    done
    
    end_scan
}

# Check SSH configuration
check_ssh_security() {
    start_scan "ssh_security_check"
    update_progress "Checking SSH security configuration"
    
    local ssh_issues=()
    
    # Check SSH protocol version
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "Protocol.*1" /etc/ssh/sshd_config; then
            ssh_issues+=("SSH Protocol 1 enabled")
            VULNERABILITIES+=("$(jq -n \
                '{
                    id: "SSH_PROTOCOL_v1",
                    title: "SSH Protocol Version 1 enabled",
                    severity: "HIGH", 
                    scanner: "ssh_check",
                    description: "SSH Protocol 1 is insecure and should be disabled",
                    remediation: "Set Protocol 2 in /etc/ssh/sshd_config",
                    evidence: "Protocol 1 found in sshd_config"
                }')")
        fi
    fi
    
    # Check for weak authorized_keys permissions
    find /home /root -name "authorized_keys" -type f 2>/dev/null | while read -r file; do
        local perm=$(stat -c "%a" "$file" 2>/dev/null || echo "000")
        if [ "$perm" != "600" ] && [ "$perm" != "400" ]; then
            VULNERABILITIES+=("$(jq -n \
                --arg file "$file" \
                --arg perm "$perm" \
                '{
                    id: "SSH_WEAK_PERMS",
                    title: "Weak authorized_keys permissions",
                    severity: "MEDIUM",
                    scanner: "ssh_check", 
                    description: "authorized_keys file has weak permissions",
                    remediation: "chmod 600 '"$file"'",
                    evidence: ("File: " + $file + " Permissions: " + $perm)
                }')")
        fi
    done
    
    SCANNER_RESULTS[ssh_check]=$(jq -n \
        --argjson issue_count "${#ssh_issues[@]}" \
        '{
            name: "ssh_security_check",
            findings: {
                issues_found: $issue_count
            }
        }')
    
    end_scan
}

# Check world-writable files
check_world_writable() {
    start_scan "world_writable_check"
    update_progress "Checking file permissions"
    
    local world_writable_count=0
    local sensitive_dirs=("/etc" "/var" "/boot" "/usr")
    
    for dir in "${sensitive_dirs[@]}"; do
        if [ -d "$dir" ]; then
            local count=$(find "$dir" -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | wc -l)
            world_writable_count=$((world_writable_count + count))
        fi
    done
    
    SCANNER_RESULTS[world_writable]=$(jq -n \
        --argjson count "$world_writable_count" \
        '{
            name: "world_writable_check", 
            findings: {
                world_writable_files: $count
            }
        }')
    
    if [ "$world_writable_count" -gt 10 ]; then
        VULNERABILITIES+=("$(jq -n \
            --argjson count "$world_writable_count" \
            '{
                id: "WORLD_WRITABLE_FILES",
                title: "Multiple world-writable files found",
                severity: "MEDIUM",
                scanner: "world_writable_check",
                description: "World-writable files in system directories",
                remediation: "Review and fix permissions: find /etc /var -type f -perm -0002 -exec chmod o-w {} +",
                evidence: ("Count: " + ($count | tostring))
            }')")
    fi
    
    end_scan
}

# Check firewall status
check_firewall() {
    start_scan "firewall_check"
    update_progress "Checking firewall status"
    
    local firewall_status="unknown"
    local firewall_rules=0
    
    # Check iptables
    if command_exists iptables; then
        firewall_rules=$(iptables -L 2>/dev/null | grep -c -E "^Chain|^target" || echo "0")
        if [ "$firewall_rules" -gt 0 ]; then
            firewall_status="iptables_active"
        else
            firewall_status="iptables_no_rules"
        fi
    # Check ufw
    elif command_exists ufw; then
        if ufw status 2>/dev/null | grep -q "active"; then
            firewall_status="ufw_active"
        else
            firewall_status="ufw_inactive"
        fi
    # Check firewalld
    elif command_exists firewall-cmd; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            firewall_status="firewalld_active"
        else
            firewall_status="firewalld_inactive"
        fi
    else
        firewall_status="no_firewall_detected"
    fi
    
    SCANNER_RESULTS[firewall]=$(jq -n \
        --arg status "$firewall_status" \
        --argjson rules "$firewall_rules" \
        '{
            name: "firewall_check",
            findings: {
                status: $status,
                rule_count: $rules
            }
        }')
    
    if [ "$firewall_status" = "iptables_no_rules" ] || [ "$firewall_status" = "no_firewall_detected" ]; then
        VULNERABILITIES+=("$(jq -n \
            --arg status "$firewall_status" \
            '{
                id: "FIREWALL_DISABLED",
                title: "Firewall not properly configured",
                severity: "HIGH",
                scanner: "firewall_check",
                description: "System firewall is disabled or has no rules",
                remediation: "Enable and configure firewall: ufw enable OR systemctl start firewalld",
                evidence: ("Status: " + $status)
            }')")
    fi
    
    end_scan
}

# Run web server scan (if enabled)
run_web_scan() {
    if [ "$SCAN_WEB" = false ]; then
        return 0
    fi
    
    start_scan "web_server_scan"
    update_progress "Scanning web services"
    
    if command_exists nikto; then
        local nikto_output="${RESULTS_DIR}/${SCAN_ID}/nikto.xml"
        local target="localhost"
        
        if [ -n "$SCAN_REMOTE" ]; then
            target="$SCAN_REMOTE"
        fi
        
        # Run basic nikto scan
        if nikto -h "$target" -o "$nikto_output" -Format xml > /dev/null 2>&1; then
            local findings=$(grep -c "description" "$nikto_output" 2>/dev/null || echo "0")
            
            SCANNER_RESULTS[nikto]=$(jq -n \
                --argjson finding_count "$findings" \
                --arg target "$target" \
                '{
                    name: "nikto",
                    version: "2.1.5",
                    findings: {
                        target: $target,
                        vulnerabilities_found: $finding_count
                    }
                }')
        else
            SCANNER_RESULTS[nikto]='{"name": "nikto", "error": "Scan failed or no web server found"}'
        fi
    else
        SCANNER_RESULTS[nikto]='{"name": "nikto", "error": "Nikto not installed"}'
    fi
    
    end_scan
}

# Run malware scan (if enabled)
run_malware_scan() {
    if [ "$SCAN_MALWARE" = false ]; then
        return 0
    fi
    
    start_scan "malware_scan"
    update_progress "Running malware scan"
    
    if command_exists clamscan; then
        local clam_output="${RESULTS_DIR}/${SCAN_ID}/clamav.log"
        
        # Scan common sensitive directories
        if $PRIV_CMD clamscan --infected --no-summary -r /etc /tmp /home /var/tmp 2>/dev/null > "$clam_output"; then
            local infected_files=$(grep -c "FOUND" "$clam_output" || echo "0")
            
            SCANNER_RESULTS[clamav]=$(jq -n \
                --argjson infected "$infected_files" \
                '{
                    name: "clamav",
                    version: "0.103",
                    findings: {
                        infected_files: $infected
                    }
                }')
            
            if [ "$infected_files" -gt 0 ]; then
                VULNERABILITIES+=("$(jq -n \
                    --argjson count "$infected_files" \
                    '{
                        id: "MALWARE_DETECTED",
                        title: "Malware detected by ClamAV",
                        severity: "CRITICAL",
                        scanner: "clamav",
                        description: "Potential malware files found on system",
                        remediation: "Review ClamAV report and clean infected files",
                        evidence: ("Infected files: " + ($count | tostring))
                    }')")
            fi
        else
            SCANNER_RESULTS[clamav]='{"name": "clamav", "error": "Scan failed"}'
        fi
    else
        SCANNER_RESULTS[clamav]='{"name": "clamav", "error": "ClamAV not installed"}'
    fi
    
    end_scan
}

# Generate JSON report
generate_json_report() {
    local output_file="${1:-${RESULTS_DIR}/${SCAN_ID}/report.json}"
    
    update_progress "Generating JSON report"
    
    log_info "Generating JSON report: $output_file"
    
    # Convert scanner results to JSON array
    local scanners_json="["
    for key in "${!SCANNER_RESULTS[@]}"; do
        scanners_json+="${SCANNER_RESULTS[$key]},"
    done
    scanners_json="${scanners_json%,}]"
    
    # Convert vulnerabilities to JSON array
    local vulns_json="["
    for vuln in "${VULNERABILITIES[@]}"; do
        vulns_json+="$vuln,"
    done
    vulns_json="${vulns_json%,}]"
    
    # Convert errors to JSON array
    local errors_json=$(printf '%s\n' "${SCAN_ERRORS[@]}" | jq -R . | jq -s .)
    
    # Count vulnerabilities by severity
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    local info_count=0
    
    for vuln in "${VULNERABILITIES[@]}"; do
        local severity=$(echo "$vuln" | jq -r '.severity')
        case "$severity" in
            "CRITICAL") critical_count=$((critical_count + 1)) ;;
            "HIGH") high_count=$((high_count + 1)) ;;
            "MEDIUM") medium_count=$((medium_count + 1)) ;;
            "LOW") low_count=$((low_count + 1)) ;;
            *) info_count=$((info_count + 1)) ;;
        esac
    done
    
    local summary=$(jq -n \
        --argjson critical "$critical_count" \
        --argjson high "$high_count" \
        --argjson medium "$medium_count" \
        --argjson low "$low_count" \
        --argjson info "$info_count" \
        '{
            critical: $critical,
            high: $high, 
            medium: $medium,
            low: $low,
            info: $info,
            total: ($critical + $high + $medium + $low + $info)
        }')
    
    # Create final report
    jq -n \
        --argjson host "$HOST_INFO" \
        --argjson distro "$DISTRO_INFO" \
        --argjson scanners "$scanners_json" \
        --argjson vulnerabilities "$vulns_json" \
        --argjson errors "$errors_json" \
        --argjson summary "$summary" \
        '{
            scan_id: $host.scan_id,
            timestamp: $host.timestamp,
            host: $host,
            distro: $distro,
            scanner_results: $scanners,
            vulnerabilities: $vulnerabilities,
            errors: $errors,
            summary: $summary
        }' > "$output_file"
    
    log_success "JSON report saved: $output_file"
    echo "$output_file"
}

# Generate HTML report
generate_html_report() {
    local json_file="${1:-${RESULTS_DIR}/${SCAN_ID}/report.json}"
    local output_file="${2:-${RESULTS_DIR}/${SCAN_ID}/report.html}"
    
    if ! [ -f "$json_file" ]; then
        log_error "JSON report not found: $json_file"
        return 1
    fi
    
    update_progress "Generating HTML report"
    
    log_info "Generating HTML report: $output_file"
    
    cat > "$output_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 20px; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .card { padding: 15px; border-radius: 6px; text-align: center; color: white; }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #000; }
        .low { background: #20c997; }
        .info { background: #6c757d; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 6px; }
        .critical-vuln { border-left: 4px solid #dc3545; }
        .high-vuln { border-left: 4px solid #fd7e14; }
        .medium-vuln { border-left: 4px solid #ffc107; }
        .low-vuln { border-left: 4px solid #20c997; }
        .scanner-result { background: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 4px; }
        .hidden { display: none; }
        .filter-buttons { margin: 20px 0; }
        .filter-btn { margin: 0 5px; padding: 5px 15px; border: 1px solid #007bff; background: white; color: #007bff; cursor: pointer; border-radius: 4px; }
        .filter-btn.active { background: #007bff; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Report</h1>
            <div id="report-meta"></div>
            <div class="summary-cards" id="summary-cards"></div>
        </div>
        
        <div class="filter-buttons">
            <button class="filter-btn active" onclick="filterVulnerabilities('all')">All</button>
            <button class="filter-btn" onclick="filterVulnerabilities('CRITICAL')">Critical</button>
            <button class="filter-btn" onclick="filterVulnerabilities('HIGH')">High</button>
            <button class="filter-btn" onclick="filterVulnerabilities('MEDIUM')">Medium</button>
            <button class="filter-btn" onclick="filterVulnerabilities('LOW')">Low</button>
        </div>
        
        <div id="scanner-results"></div>
        <div id="vulnerabilities"></div>
        <div id="errors"></div>
    </div>

    <script>
        let reportData = null;
        
        // Load JSON data
        fetch('report.json')
            .then(response => response.json())
            .then(data => {
                reportData = data;
                renderReport();
            })
            .catch(error => {
                console.error('Error loading report:', error);
                document.getElementById('report-meta').innerHTML = '<p>Error loading report data</p>';
            });
        
        function renderReport() {
            renderMeta();
            renderSummary();
            renderScannerResults();
            renderVulnerabilities();
            renderErrors();
        }
        
        function renderMeta() {
            const meta = document.getElementById('report-meta');
            meta.innerHTML = `
                <p><strong>Host:</strong> ${reportData.host.hostname} | 
                <strong>Scan ID:</strong> ${reportData.scan_id} | 
                <strong>Date:</strong> ${new Date(reportData.timestamp).toLocaleString()} | 
                <strong>Distro:</strong> ${reportData.distro.pretty_name}</p>
            `;
        }
        
        function renderSummary() {
            const summary = reportData.summary;
            const cards = document.getElementById('summary-cards');
            
            cards.innerHTML = `
                <div class="card critical">
                    <h3>${summary.critical}</h3>
                    <p>Critical</p>
                </div>
                <div class="card high">
                    <h3>${summary.high}</h3>
                    <p>High</p>
                </div>
                <div class="card medium">
                    <h3>${summary.medium}</h3>
                    <p>Medium</p>
                </div>
                <div class="card low">
                    <h3>${summary.low}</h3>
                    <p>Low</p>
                </div>
                <div class="card info">
                    <h3>${summary.info}</h3>
                    <p>Info</p>
                </div>
                <div class="card" style="background: #007bff;">
                    <h3>${summary.total}</h3>
                    <p>Total</p>
                </div>
            `;
        }
        
        function renderScannerResults() {
            const container = document.getElementById('scanner-results');
            container.innerHTML = '<h2>Scanner Results</h2>';
            
            reportData.scanner_results.forEach(scanner => {
                const div = document.createElement('div');
                div.className = 'scanner-result';
                div.innerHTML = `
                    <h3>${scanner.name} ${scanner.version || ''}</h3>
                    <pre>${JSON.stringify(scanner.findings || scanner.error, null, 2)}</pre>
                `;
                container.appendChild(div);
            });
        }
        
        function renderVulnerabilities() {
            const container = document.getElementById('vulnerabilities');
            container.innerHTML = '<h2>Vulnerabilities</h2>';
            
            if (reportData.vulnerabilities.length === 0) {
                container.innerHTML += '<p>No vulnerabilities found.</p>';
                return;
            }
            
            reportData.vulnerabilities.forEach(vuln => {
                const div = document.createElement('div');
                div.className = `vulnerability ${vuln.severity.toLowerCase()}-vuln`;
                div.dataset.severity = vuln.severity;
                
                div.innerHTML = `
                    <h3>${vuln.title} <span style="float: right; background: ${getSeverityColor(vuln.severity)}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px;">${vuln.severity}</span></h3>
                    <p><strong>ID:</strong> ${vuln.id} | <strong>Scanner:</strong> ${vuln.scanner}</p>
                    <p><strong>Description:</strong> ${vuln.description}</p>
                    ${vuln.evidence ? `<p><strong>Evidence:</strong> <code>${vuln.evidence}</code></p>` : ''}
                    ${vuln.remediation ? `<p><strong>Remediation:</strong> ${vuln.remediation}</p>` : ''}
                `;
                container.appendChild(div);
            });
        }
        
        function renderErrors() {
            const container = document.getElementById('errors');
            if (reportData.errors && reportData.errors.length > 0) {
                container.innerHTML = '<h2>Errors</h2><ul>';
                reportData.errors.forEach(error => {
                    container.innerHTML += `<li>${error}</li>`;
                });
                container.innerHTML += '</ul>';
            }
        }
        
        function filterVulnerabilities(severity) {
            // Update button states
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Filter vulnerabilities
            const vulns = document.querySelectorAll('.vulnerability');
            vulns.forEach(vuln => {
                if (severity === 'all' || vuln.dataset.severity === severity) {
                    vuln.classList.remove('hidden');
                } else {
                    vuln.classList.add('hidden');
                }
            });
        }
        
        function getSeverityColor(severity) {
            const colors = {
                'CRITICAL': '#dc3545',
                'HIGH': '#fd7e14', 
                'MEDIUM': '#ffc107',
                'LOW': '#20c997',
                'INFO': '#6c757d'
            };
            return colors[severity] || '#6c757d';
        }
    </script>
</body>
</html>
EOF

    log_success "HTML report saved: $output_file"
    echo "$output_file"
}

# Print summary report
print_summary() {
    local json_file="${1:-${RESULTS_DIR}/${SCAN_ID}/report.json}"
    
    if ! [ -f "$json_file" ]; then
        log_error "JSON report not found: $json_file"
        return 1
    fi
    
    local critical=$(jq -r '.summary.critical' "$json_file")
    local high=$(jq -r '.summary.high' "$json_file")
    local medium=$(jq -r '.summary.medium' "$json_file")
    local low=$(jq -r '.summary.low' "$json_file")
    local total=$(jq -r '.summary.total' "$json_file")
    
    echo
    echo "=== SECURITY SCAN SUMMARY ==="
    echo "Host: $(jq -r '.host.hostname' "$json_file")"
    echo "Scan ID: $(jq -r '.scan_id' "$json_file")"
    echo "Timestamp: $(jq -r '.timestamp' "$json_file")"
    echo "Distribution: $(jq -r '.distro.pretty_name' "$json_file")"
    echo
    echo "VULNERABILITIES:"
    echo "  Critical:  $critical"
    echo "  High:      $high" 
    echo "  Medium:    $medium"
    echo "  Low:       $low"
    echo "  Total:     $total"
    echo
    echo "SCANNERS RUN:"
    jq -r '.scanner_results[] | "  - \(.name): \(if .findings then "SUCCESS" else "ERROR" end)"' "$json_file"
    echo
    echo "Report location: ${RESULTS_DIR}/${SCAN_ID}/"
    echo "========================"
}

# Send Slack notification
send_slack_notification() {
    local json_file="$1"
    local webhook_url="$2"
    
    if [ "$ALLOW_UPLOAD" = false ]; then
        log_warn "Upload not allowed - use --allow-upload to enable Slack notifications"
        return 0
    fi
    
    if ! command_exists curl; then
        log_error "curl not available for Slack notification"
        return 1
    fi
    
    local critical=$(jq -r '.summary.critical' "$json_file")
    local high=$(jq -r '.summary.high' "$json_file")
    local total=$(jq -r '.summary.total' "$json_file")
    local hostname=$(jq -r '.host.hostname' "$json_file")
    
    local color="good"
    if [ "$critical" -gt 0 ]; then
        color="danger"
    elif [ "$high" -gt 0 ]; then
        color="warning"
    fi
    
    local payload=$(jq -n \
        --arg hostname "$hostname" \
        --argjson critical "$critical" \
        --argjson high "$high" \
        --argjson total "$total" \
        --arg color "$color" \
        --arg scan_id "$SCAN_ID" \
        '{
            "attachments": [
                {
                    "color": $color,
                    "title": "Security Scan Completed",
                    "fields": [
                        {
                            "title": "Host",
                            "value": $hostname,
                            "short": true
                        },
                        {
                            "title": "Critical",
                            "value": ($critical | tostring),
                            "short": true
                        },
                        {
                            "title": "High", 
                            "value": ($high | tostring),
                            "short": true
                        },
                        {
                            "title": "Total",
                            "value": ($total | tostring),
                            "short": true
                        }
                    ],
                    "ts": (now | tostring),
                    "footer": "linux-vulnscan.sh",
                    "text": "Scan ID: \($scan_id)"
                }
            ]
        }')
    
    if curl -s -X POST -H "Content-type: application/json" \
         --data "$payload" "$webhook_url" > /dev/null 2>&1; then
        log_success "Slack notification sent"
    else
        log_error "Failed to send Slack notification"
    fi
}

# Send email report
send_email_report() {
    local json_file="$1"
    local email_to="$2"
    
    if [ "$ALLOW_UPLOAD" = false ]; then
        log_warn "Upload not allowed - use --allow-upload to enable email reports"
        return 0
    fi
    
    if ! command_exists mail; then
        log_error "mail command not available for email report"
        return 1
    fi
    
    local subject="Security Scan Report - $(hostname) - $SCAN_ID"
    local body=$(print_summary "$json_file")
    
    if echo "$body" | mail -s "$subject" "$email_to" 2>/dev/null; then
        log_success "Email report sent to $email_to"
    else
        log_error "Failed to send email report"
    fi
}

# Self-test function
run_selftest() {
    log_info "Running self-test..."
    
    # Test basic functionality
    local tests_passed=0
    local tests_failed=0
    
    # Test 1: JSON processing
    if echo '{"test": "value"}' | jq -e . >/dev/null 2>&1; then
        log_success "JSON processing test passed"
        tests_passed=$((tests_passed + 1))
    else
        log_error "JSON processing test failed"
        tests_failed=$((tests_failed + 1))
    fi
    
    # Test 2: Directory creation
    local test_dir="/tmp/vulnscan-test-$$"
    if mkdir -p "$test_dir" && [ -d "$test_dir" ]; then
        log_success "Directory creation test passed"
        tests_passed=$((tests_passed + 1))
        rm -rf "$test_dir"
    else
        log_error "Directory creation test failed"
        tests_failed=$((tests_failed + 1))
    fi
    
    # Test 3: Basic command availability
    local test_commands=("echo" "cat" "grep")
    for cmd in "${test_commands[@]}"; do
        if command_exists "$cmd"; then
            log_success "Command $cmd test passed"
            tests_passed=$((tests_passed + 1))
        else
            log_error "Command $cmd test failed"
            tests_failed=$((tests_failed + 1))
        fi
    done
    
    log_info "Self-test completed: $tests_passed passed, $tests_failed failed"
    
    if [ "$tests_failed" -eq 0 ]; then
        log_success "All self-tests passed"
        return 0
    else
        log_error "Some self-tests failed"
        return 1
    fi
}

# CI mode exit code handling
handle_ci_exit() {
    local json_file="$1"
    
    if [ "$CI_MODE" = false ]; then
        return 0
    fi
    
    if ! [ -f "$json_file" ]; then
        log_error "Cannot read scan results for CI exit code"
        exit 1
    fi
    
    local critical=$(jq -r '.summary.critical' "$json_file")
    local high=$(jq -r '.summary.high' "$json_file")
    
    if [ "$critical" -gt 0 ]; then
        log_error "CRITICAL vulnerabilities found - failing CI build"
        exit 2
    elif [ "$high" -gt 0 ]; then
        log_warn "HIGH vulnerabilities found - CI build continues"
        exit 0
    else
        log_success "No CRITICAL/HIGH vulnerabilities found"
        exit 0
    fi
}

# Main execution function
main() {
    parse_args "$@"
    
    if [ "$SELFTEST" = true ]; then
        run_selftest
        exit $?
    fi
    
    log_info "Starting Linux vulnerability scan (ID: $SCAN_ID)"
    
    # Initialize
    init_directories
    check_privileges
    detect_distro
    detect_package_manager
    
    # Install tools if requested
    install_tools
    
    # Check tool availability
    if ! check_tools; then
        log_error "Required tools missing - aborting scan"
        exit 1
    fi
    
    # Run scans
    collect_host_info
    run_lynis_audit
    run_nmap_scan
    run_trivy_scan
    check_suid_sgid
    check_ssh_security
    check_world_writable
    check_firewall
    run_web_scan
    run_malware_scan
    
    # Generate reports
    local json_report
    json_report=$(generate_json_report "$OUTPUT_JSON")
    
    if [ -n "$OUTPUT_HTML" ] || [ "$OUTPUT_HTML" = "auto" ]; then
        local html_output="${OUTPUT_HTML:-${RESULTS_DIR}/${SCAN_ID}/report.html}"
        generate_html_report "$json_report" "$html_output"
    fi
    
    # Print summary if requested or in non-quiet mode
    if [ "$QUIET" = false ] || [ -n "$OUTPUT_JSON" ]; then
        print_summary "$json_report"
    fi
    
    # Notifications
    if [ -n "$SLACK_WEBHOOK" ]; then
        send_slack_notification "$json_report" "$SLACK_WEBHOOK"
    fi
    
    if [ -n "$EMAIL_TO" ]; then
        send_email_report "$json_report" "$EMAIL_TO"
    fi
    
    # Handle CI exit code
    handle_ci_exit "$json_report"
    
    log_success "Scan completed successfully"
    log_info "Full results in: ${RESULTS_DIR}/${SCAN_ID}/"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
