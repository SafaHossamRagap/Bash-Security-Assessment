#!/bin/bash

# secscan.sh
# Simple Bash Security Assessment Tool
# Usage: ./secscan.sh <target>
#
# Only use this script on machines you own
# or authorized lab/CTF environments.

REPORT_DIR="report"
SCAN_FILE="$REPORT_DIR/scan.txt"
FINDINGS_FILE="$REPORT_DIR/findings.txt"
SUMMARY_FILE="$REPORT_DIR/summary.txt"
PORTS_FILE="$REPORT_DIR/ports.txt"
RAW_NMAP="$REPORT_DIR/nmap_raw.txt"
LOG_FILE="$REPORT_DIR/secscan.log"

FINDINGS_COUNT=0

# --------------------------------------------------
# 1. Check arguments
# --------------------------------------------------

if [ $# -lt 1 ]; then
    echo "Usage: ./secscan.sh <target>"
    exit 1
fi

TARGET="$1"

mkdir -p "$REPORT_DIR"

# Save terminal output to a log file
exec > >(tee -a "$LOG_FILE") 2>&1


# --------------------------------------------------
# 2. Check required tools
# --------------------------------------------------

check_dependencies() {

    if ! command -v nmap >/dev/null 2>&1; then
        echo "[-] nmap is not installed"
        exit 2
    fi

    echo "[+] Required dependency check passed"
}


# --------------------------------------------------
# 3. Check target availability
# --------------------------------------------------

check_target() {

    echo "[*] Checking if target is reachable..."

    ping -c 2 -W 2 "$TARGET" >/dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "[-] Target is unreachable"
        exit 3
    fi

    echo "[+] Target is reachable"
}


# --------------------------------------------------
# 4. Reconnaissance
# --------------------------------------------------

recon() {

    echo "[*] Starting reconnaissance..."

    {
        echo "========================================"
        echo "        RECONNAISSANCE"
        echo "========================================"
        echo "Target: $TARGET"
        echo "Scan Date: $(date)"
        echo ""

        echo "--- Hostname / IP Information ---"
        getent hosts "$TARGET" 2>/dev/null

        echo ""

        echo "--- Basic Network Information ---"
        ip route get "$TARGET" 2>/dev/null

    } > "$REPORT_DIR/recon.txt"

    echo "[+] Reconnaissance completed"
}


# --------------------------------------------------
# 5. Port and Service Scan
# --------------------------------------------------

scan_target() {

    echo "[*] Starting TCP port and service scan..."

    if ! nmap -sV "$TARGET" -oN "$RAW_NMAP" >/dev/null 2>&1; then
        echo "[-] nmap scan failed"
        return 1
    fi

    # Extract open TCP ports
    awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {print}' \
        "$RAW_NMAP" > "$PORTS_FILE"

    {
        echo "========================================"
        echo "          PORT SCAN REPORT"
        echo "========================================"
        echo "Target: $TARGET"
        echo "Scan Date: $(date)"
        echo ""

        echo "--- Reconnaissance ---"
        cat "$REPORT_DIR/recon.txt"

        echo ""

        echo "--- Open Ports and Services ---"

        if [ -s "$PORTS_FILE" ]; then
            cat "$PORTS_FILE"
        else
            echo "(No open TCP ports found)"
        fi

        echo ""

        echo "--- Raw Nmap Output ---"
        cat "$RAW_NMAP"

    } > "$SCAN_FILE"

    if [ -s "$PORTS_FILE" ]; then
        echo "[+] Open ports detected:"
        cat "$PORTS_FILE"
    else
        echo "[-] No open TCP ports found"
    fi

    echo "[+] Port scan completed"

    return 0
}


# --------------------------------------------------
# 6. Add a security finding
# --------------------------------------------------

add_finding() {

    TITLE="$1"
    EVIDENCE="$2"
    RISK="$3"
    RECOMMENDATION="$4"

    FINDINGS_COUNT=$((FINDINGS_COUNT + 1))

    echo "[!] $TITLE"

    {
        echo "Finding #$FINDINGS_COUNT: $TITLE"

        echo "Evidence:"
        echo "$EVIDENCE"

        echo "Risk:"
        echo "$RISK"

        echo "Recommendation:"
        echo "$RECOMMENDATION"

        echo "----------------------------------------"

    } >> "$FINDINGS_FILE"
}


# --------------------------------------------------
# 7. FTP Enumeration
# --------------------------------------------------

check_ftp() {

    PORT="$1"

    echo "[*] Checking FTP anonymous login on port $PORT..."

    if ! command -v curl >/dev/null 2>&1; then
        echo "[-] curl is not installed - skipping FTP check"
        return
    fi

    RESULT=$(curl -s --max-time 5 \
        "ftp://anonymous:anonymous@$TARGET:$PORT/" -l)

    if [ -n "$RESULT" ]; then

        add_finding \
        "Anonymous FTP login allowed" \
        "Anonymous FTP login succeeded on port $PORT.
Directory listing:
$RESULT" \
        "Unauthenticated users may read or access files on the FTP server." \
        "Disable anonymous FTP access unless it is required."

    else
        echo "[+] Anonymous FTP login not allowed"
    fi
}


# --------------------------------------------------
# 8. SSH Enumeration
# --------------------------------------------------

check_ssh() {

    PORT="$1"

    echo "[*] Checking SSH banner on port $PORT..."

    if ! command -v nc >/dev/null 2>&1; then
        echo "[-] nc is not installed - skipping SSH check"
        return
    fi

    if ! command -v timeout >/dev/null 2>&1; then
        echo "[-] timeout is not installed - skipping SSH check"
        return
    fi

    BANNER=$(timeout 3 nc "$TARGET" "$PORT" < /dev/null | head -n 1)

    if [ -n "$BANNER" ]; then

        add_finding \
        "SSH banner information disclosed" \
        "SSH banner received on port $PORT:
$BANNER" \
        "The disclosed software/version information can help identify the SSH service." \
        "Keep SSH updated and avoid unnecessary version disclosure."

    else
        echo "[+] SSH banner could not be read"
    fi
}


# --------------------------------------------------
# 9. SMB Enumeration
# --------------------------------------------------

check_smb() {

    PORT="$1"

    echo "[*] Checking SMB shares on port $PORT..."

    if ! command -v smbclient >/dev/null 2>&1; then
        echo "[-] smbclient is not installed - skipping SMB check"
        return
    fi

    RESULT=$(smbclient -L "//$TARGET/" -N --port="$PORT" 2>/dev/null)

    if echo "$RESULT" | grep -qi "Sharename"; then

        add_finding \
        "SMB shares accessible without authentication" \
        "SMB share enumeration succeeded on port $PORT:
$RESULT" \
        "Unauthenticated users may discover internal file shares." \
        "Require authentication and review SMB share permissions."

    else
        echo "[+] No unauthenticated SMB shares found"
    fi
}


# --------------------------------------------------
# 10. SMTP Enumeration
# --------------------------------------------------

check_smtp() {

    PORT="$1"

    echo "[*] Checking SMTP relay on port $PORT..."

    if ! command -v nc >/dev/null 2>&1; then
        echo "[-] nc is not installed - skipping SMTP check"
        return
    fi

    if ! command -v timeout >/dev/null 2>&1; then
        echo "[-] timeout is not installed - skipping SMTP check"
        return
    fi

    # Open relay check
    RELAY_OUT=$(printf \
        "HELO test\r\nMAIL FROM:<a@test.com>\r\nRCPT TO:<b@example.com>\r\n" |
        timeout 5 nc "$TARGET" "$PORT")

    RCPT_REPLY=$(echo "$RELAY_OUT" | tail -n 1)

    if echo "$RCPT_REPLY" | grep -qE "^25[0-9]"; then

        add_finding \
        "Possible open SMTP relay" \
        "External RCPT TO request was accepted:
$RCPT_REPLY

Full SMTP session:
$RELAY_OUT" \
        "The mail server may allow unauthorized users to relay email." \
        "Restrict SMTP relay to authenticated users or trusted networks."

    else
        echo "[+] SMTP relay attempt was rejected"
    fi


    # User enumeration check
    echo "[*] Checking SMTP VRFY user enumeration..."

    VRFY_OUT=$(printf \
        "HELO test\r\nVRFY root\r\n" |
        timeout 5 nc "$TARGET" "$PORT")

    VRFY_REPLY=$(echo "$VRFY_OUT" | tail -n 1)

    if echo "$VRFY_REPLY" | grep -qE "^25[02]"; then

        add_finding \
        "SMTP user enumeration possible" \
        "VRFY root returned:
$VRFY_REPLY" \
        "The server may reveal valid usernames to an attacker." \
        "Disable or restrict VRFY/EXPN commands."

    else
        echo "[+] SMTP VRFY did not confirm a valid user"
    fi
}


# --------------------------------------------------
# 11. DNS Enumeration
# --------------------------------------------------

check_dns() {

    PORT="$1"

    echo "[*] Checking DNS zone transfer on port $PORT..."

    if ! command -v dig >/dev/null 2>&1; then
        echo "[-] dig is not installed - skipping DNS check"
        return
    fi

    RESULT=$(dig @"$TARGET" -p "$PORT" "$TARGET" AXFR 2>/dev/null)

    if echo "$RESULT" | grep -q "SOA"; then

        add_finding \
        "DNS zone transfer succeeded" \
        "AXFR request returned DNS zone information:
$RESULT" \
        "A successful zone transfer may expose hostnames and IP information." \
        "Allow zone transfers only to trusted secondary DNS servers."

    else
        echo "[+] DNS zone transfer was not successful"
    fi
}


# --------------------------------------------------
# 12. HTTP Enumeration
# --------------------------------------------------

check_http() {

    PORT="$1"

    echo "[*] Checking HTTP on port $PORT..."

    if ! command -v curl >/dev/null 2>&1; then
        echo "[-] curl is not installed - skipping HTTP check"
        return
    fi

    SCHEME="http"

    if [ "$PORT" -eq 443 ]; then
        SCHEME="https"
    fi

    # Check HTTP headers
    HEADERS=$(curl -skI --max-time 5 \
        "$SCHEME://$TARGET:$PORT/")

    SERVER_INFO=$(echo "$HEADERS" |
        grep -Ei '^(Server|X-Powered-By):')

    if [ -n "$SERVER_INFO" ]; then

        add_finding \
        "Web server information disclosed" \
        "HTTP headers from port $PORT:
$SERVER_INFO" \
        "Server information can help identify software used by the web server." \
        "Hide or reduce unnecessary server/version information."

    else
        echo "[+] No identifying web server header found"
    fi


    # Check robots.txt
    ROBOTS=$(curl -sk --max-time 5 \
        "$SCHEME://$TARGET:$PORT/robots.txt")

    if echo "$ROBOTS" | grep -qi "^Disallow:"; then

        add_finding \
        "robots.txt reveals restricted paths" \
        "robots.txt on port $PORT returned:
$ROBOTS" \
        "The file may reveal paths that administrators do not want indexed." \
        "Do not rely on robots.txt for access control and review exposed paths."

    else
        echo "[+] No useful robots.txt information found"
    fi
}


# --------------------------------------------------
# 13. Decision Logic
# --------------------------------------------------

decide_checks() {

    echo "[*] Deciding which checks to run..."

    if [ ! -s "$PORTS_FILE" ]; then
        echo "[*] No open ports - no service checks required"
        return
    fi

    while read -r LINE; do

        PORT=$(echo "$LINE" | awk '{print $1}' | cut -d'/' -f1)
        SERVICE=$(echo "$LINE" | awk '{print $3}')

        case "$SERVICE" in

            ftp)
                echo "[+] FTP detected on port $PORT"
                check_ftp "$PORT"
                ;;

            ssh)
                echo "[+] SSH detected on port $PORT"
                check_ssh "$PORT"
                ;;

            netbios-ssn|microsoft-ds|smb)
                echo "[+] SMB detected on port $PORT"
                check_smb "$PORT"
                ;;

            smtp|submission)
                echo "[+] SMTP detected on port $PORT"
                check_smtp "$PORT"
                ;;

            domain)
                echo "[+] DNS detected on port $PORT"
                check_dns "$PORT"
                ;;

            http|http-proxy|http-alt|https|ssl/http)
                echo "[+] HTTP detected on port $PORT"
                check_http "$PORT"
                ;;

            *)
                echo "[*] No specific check for service: $SERVICE on port $PORT"
                ;;

        esac

    done < "$PORTS_FILE"
}


# --------------------------------------------------
# 14. Generate Summary
# --------------------------------------------------

make_summary() {

    echo "[*] Generating summary..."

    if [ "$FINDINGS_COUNT" -eq 0 ]; then
        echo "No security findings were confirmed during this scan." \
            >> "$FINDINGS_FILE"
    fi

    {
        echo "========================================"
        echo "          SCAN SUMMARY"
        echo "========================================"
        echo "Target: $TARGET"
        echo "Scan Date: $(date)"
        echo ""

        echo "Open Ports and Services:"

        if [ -s "$PORTS_FILE" ]; then
            cat "$PORTS_FILE"
        else
            echo "(none)"
        fi

        echo ""
        echo "Total Findings: $FINDINGS_COUNT"
        echo ""
        echo "Reports:"
        echo "scan.txt      - scan and reconnaissance results"
        echo "findings.txt  - findings with evidence and recommendations"
        echo "summary.txt   - short scan summary"

    } > "$SUMMARY_FILE"

    echo "[+] Reports saved in: $REPORT_DIR/"
}


# ==================================================
# MAIN
# ==================================================

echo "========================================"
echo "     Bash Security Assessment Tool"
echo "========================================"

echo "[+] Target: $TARGET"

check_dependencies
check_target
recon

if ! scan_target; then
    echo "[-] Security scan failed"
    exit 4
fi

# Start findings report
{
    echo "========================================"
    echo "        SECURITY FINDINGS"
    echo "========================================"
    echo "Target: $TARGET"
    echo "Scan Date: $(date)"
    echo ""
} > "$FINDINGS_FILE"

decide_checks
make_summary

echo "========================================"
echo "             Scan Complete"
echo "========================================"

exit 0
