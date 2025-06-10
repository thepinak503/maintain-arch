#!/bin/bash

# ============================================================================
# ULTIMATE ARCH LINUX MAINTENANCE & SYSTEM VERIFICATION SCRIPT
# Enhanced with UKI detection and comprehensive file verification
# GitHub: https://github.com/thepinak503/maintain-arch
# ============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script version and metadata
SCRIPT_VERSION="4.0.0"
SCRIPT_DATE="2025-06-10"
GITHUB_REPO="https://github.com/thepinak503/maintain-arch"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
JOURNAL_RETENTION="2weeks"
PACMAN_CACHE_KEEP=3
LOG_FILE="/var/log/arch_maintenance.log"
REQUIRED_FREE_SPACE_GB=5
MAX_DISK_USAGE_PERCENT=85

# Function to print headers
print_header() {
    echo -e "\n${BLUE}${BOLD}======================================${NC}"
    echo -e "${BLUE}${BOLD}$1${NC}"
    echo -e "${BLUE}${BOLD}======================================${NC}\n"
}

# Status indicators
print_warning() { echo -e "${YELLOW}⚠️  WARNING: $1${NC}"; }
print_error() { echo -e "${RED}❌ ERROR: $1${NC}"; }
print_success() { echo -e "${GREEN}✅ SUCCESS: $1${NC}"; }
print_info() { echo -e "${PURPLE}ℹ️  INFO: $1${NC}"; }
print_tip() { echo -e "${CYAN}💡 TIP: $1${NC}"; }
print_critical() { echo -e "${RED}${BOLD}🚨 CRITICAL: $1${NC}"; }
print_found() { echo -e "${GREEN}🔍 FOUND: $1${NC}"; }
print_missing() { echo -e "${RED}🔍 MISSING: $1${NC}"; }

# Logging function
log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | sudo tee -a "$LOG_FILE" >/dev/null 2>&1 || true
}

# Error handling
handle_error() {
    print_error "Script encountered an error on line $1"
    log_action "Script error on line $1: ${BASH_COMMAND}" || true
    exit 1
}
trap 'handle_error $LINENO' ERR

# Check prerequisites
check_prerequisites() {
    print_header "CHECKING PREREQUISITES"
    
    # Check if running on Arch Linux
    if ! grep -q "Arch Linux" /etc/os-release 2>/dev/null; then
        print_warning "This script is designed for Arch Linux. Proceed with caution."
    fi
    
    # Check required commands
    local required_commands=("systemctl" "journalctl" "pacman" "df" "du" "find")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            print_error "Required command '$cmd' not found"
            exit 1
        fi
    done
    
    # Check if running with appropriate permissions
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some user-specific checks may not work properly."
    fi
    
    print_success "Prerequisites check completed"
    log_action "Prerequisites check completed"
}

# 1. PRE-UPDATE SAFETY CHECKS
pre_update_checks() {
    print_header "1. PRE-UPDATE SAFETY CHECKS"
    
    # Check Arch Linux news
    print_info "Checking Arch Linux news for breaking changes..."
    if command -v curl &>/dev/null; then
        local news_check
        if news_check=$(curl -s --connect-timeout 10 https://archlinux.org/news/ 2>/dev/null); then
            echo "$news_check" | grep -o '<h2[^>]*>[^<]*</h2>' | head -5 | sed 's/<[^>]*>//g' 2>/dev/null || true
            print_tip "Always check https://archlinux.org/news/ before major updates!"
        else
            print_warning "Could not fetch Arch news (network issue)"
        fi
    else
        print_info "Install curl to check Arch news: sudo pacman -S curl"
    fi
    
    # Check available disk space
    print_info "Checking available disk space..."
    local root_usage root_avail_gb
    root_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//' || echo "0")
    root_avail_gb=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//' || echo "0")
    
    if (( root_usage > MAX_DISK_USAGE_PERCENT )); then
        print_critical "Disk usage is ${root_usage}% (>${MAX_DISK_USAGE_PERCENT}%). Clean up before updating!"
    elif (( root_avail_gb < REQUIRED_FREE_SPACE_GB )); then
        print_warning "Less than ${REQUIRED_FREE_SPACE_GB}GB free space. Consider cleaning up."
    else
        print_success "Sufficient disk space available (${root_usage}% used, ${root_avail_gb}GB free)"
    fi
    
    # Check for partial updates
    print_info "Checking for partial updates..."
    if pacman -Qu &>/dev/null; then
        local pending_updates
        pending_updates=$(pacman -Qu | wc -l || echo "0")
        print_info "$pending_updates package updates available"
    else
        print_success "No pending updates found"
    fi
    
    log_action "Pre-update checks completed"
}

# 2. COMPREHENSIVE FAILED SERVICES CHECK
check_failed_services() {
    print_header "2. FAILED SERVICES ANALYSIS"
    
    # System services
    print_info "Checking system-wide failed services..."
    local failed_system
    failed_system=$(systemctl --failed --no-legend | wc -l || echo "0")
    if (( failed_system == 0 )); then
        print_success "No failed system services"
    else
        print_error "$failed_system failed system services found:"
        systemctl --failed || true
        echo ""
        print_tip "Use 'systemctl status <service>' for detailed error info"
        print_tip "Use 'journalctl -u <service>' for service logs"
    fi
    
    # User services (if not root)
    if [[ $EUID -ne 0 ]]; then
        print_info "Checking user failed services..."
        local failed_user
        failed_user=$(systemctl --user --failed --no-legend 2>/dev/null | wc -l || echo "0")
        if (( failed_user == 0 )); then
            print_success "No failed user services"
        else
            print_error "$failed_user failed user services found:"
            systemctl --user --failed || true
        fi
    fi
    
    # Common service fixes
    print_info "Common service troubleshooting tips:"
    echo "• Bluetooth issues: sudo systemctl restart bluetooth"
    echo "• Network issues: sudo systemctl restart NetworkManager"
    echo "• Audio issues: systemctl --user restart pipewire pipewire-pulse"
    echo "• GNOME issues: systemctl --user restart gnome-session-manager"
    
    log_action "Failed services check completed - $failed_system system failures"
}

# 3. ENHANCED LOG ANALYSIS
check_system_logs() {
    print_header "3. SYSTEM LOG ANALYSIS"
    
    # Critical boot errors
    print_info "Checking critical boot errors..."
    local critical_errors
    critical_errors=$(journalctl -b -p crit --no-pager 2>/dev/null | wc -l || echo "0")
    if (( critical_errors == 0 )); then
        print_success "No critical boot errors found"
    else
        print_error "$critical_errors critical errors found:"
        journalctl -b -p crit --no-pager 2>/dev/null | tail -10 || true
    fi
    
    # Recent errors (last 24 hours)
    print_info "Checking recent error messages..."
    local recent_errors
    recent_errors=$(journalctl --since "24 hours ago" -p err --no-pager 2>/dev/null | wc -l || echo "0")
    if (( recent_errors == 0 )); then
        print_success "No recent errors found"
    else
        print_warning "$recent_errors error messages in last 24 hours:"
        journalctl --since "24 hours ago" -p err --no-pager 2>/dev/null | tail -10 || true
    fi
    
    # Kernel issues
    print_info "Checking kernel messages..."
    local kernel_errors
    kernel_errors=$(dmesg 2>/dev/null | grep -i "error\|failed\|critical" | wc -l || echo "0")
    if (( kernel_errors == 0 )); then
        print_success "No kernel errors found"
    else
        print_warning "$kernel_errors kernel issues found:"
        dmesg 2>/dev/null | grep -i "error\|failed\|critical" | tail -10 || true
    fi
    
    # Common log errors and fixes
    print_info "Checking for common known issues..."
    
    # Wireless regulatory database
    if dmesg 2>/dev/null | grep -q "regulatory.db"; then
        print_warning "Wireless regulatory database issue detected"
        print_tip "Fix: sudo pacman -S wireless-regdb"
    fi
    
    # Bluetooth firmware
    if dmesg 2>/dev/null | grep -q "Bluetooth.*failed"; then
        print_warning "Bluetooth firmware issue detected"  
        print_tip "Fix: Update firmware or restart bluetooth service"
    fi
    
    # GNOME keyring
    if journalctl -b 2>/dev/null | grep -q "gkr-pam.*unable to locate daemon"; then
        print_warning "GNOME keyring daemon issue detected"
        print_tip "Fix: sudo pacman -S gnome-keyring && log out/in"
    fi
    
    log_action "Log analysis completed - $critical_errors critical, $recent_errors recent errors"
}

# 4. COMPREHENSIVE BOOT FILE DETECTION
comprehensive_boot_detection() {
    print_header "4. COMPREHENSIVE BOOT FILE DETECTION"
    
    local boot_files_found=()
    local bootloader_files=()
    local kernel_files=()
    local initramfs_files=()
    local microcode_files=()
    
    print_info "Scanning entire filesystem for boot-related files..."
    
    # 1. DETECT CURRENT BOOTLOADER USING MULTIPLE METHODS
    print_info "Method 1: Using efibootmgr to detect current bootloader..."
    if command -v efibootmgr &>/dev/null; then
        local efi_output
        efi_output=$(efibootmgr -v 2>/dev/null || echo "")
        if [[ -n "$efi_output" ]]; then
            print_success "EFI boot information:"
            echo "$efi_output" | head -10
            
            # Extract current boot entry
            local current_boot
            current_boot=$(echo "$efi_output" | grep "BootCurrent" | awk '{print $2}' || echo "")
            print_info "Current boot entry: $current_boot"
            
            # Identify bootloader from path
            if echo "$efi_output" | grep -qi "systemd"; then
                print_found "systemd-boot detected in EFI entries"
            elif echo "$efi_output" | grep -qi "grub"; then
                print_found "GRUB detected in EFI entries"
            elif echo "$efi_output" | grep -qi "refind"; then
                print_found "rEFInd detected in EFI entries"
            fi
        fi
    else
        print_warning "efibootmgr not available - installing for better detection"
        print_tip "Install with: sudo pacman -S efibootmgr"
    fi
    
    print_info "Method 2: Checking boot command line from dmesg..."
    local boot_cmdline
    boot_cmdline=$(dmesg 2>/dev/null | grep "Command line" || echo "")
    if [[ -n "$boot_cmdline" ]]; then
        print_success "Boot command line found:"
        echo "$boot_cmdline"
        
        if echo "$boot_cmdline" | grep -q "BOOT_IMAGE="; then
            print_found "GRUB boot signature detected"
        else
            print_found "Possible EFI stub or systemd-boot detected"
        fi
    fi
    
    # 2. COMPREHENSIVE BOOTLOADER FILE SEARCH
    print_info "Searching for bootloader files across filesystem..."
    
    # systemd-boot files
    print_info "Searching for systemd-boot files..."
    local systemd_boot_files=(
        "systemd-bootx64.efi"
        "systemd-bootia32.efi"
        "BOOTX64.EFI"
        "BOOTIA32.EFI"
        "loader.conf"
    )
    
    for file in "${systemd_boot_files[@]}"; do
        local found_paths
        found_paths=$(find / -name "$file" -type f 2>/dev/null | head -10 || true)
        if [[ -n "$found_paths" ]]; then
            print_found "systemd-boot file: $file"
            echo "$found_paths" | while read -r path; do
                echo "    → $path"
                ls -la "$path" 2>/dev/null || true
            done
            bootloader_files+=("$file:$found_paths")
        fi
    done
    
    # GRUB files
    print_info "Searching for GRUB files..."
    local grub_files=(
        "grub.cfg"
        "grubx64.efi" 
        "grub.efi"
        "core.img"
        "grubenv"
    )
    
    for file in "${grub_files[@]}"; do
        local found_paths
        found_paths=$(find / -name "$file" -type f 2>/dev/null | head -10 || true)
        if [[ -n "$found_paths" ]]; then
            print_found "GRUB file: $file"
            echo "$found_paths" | while read -r path; do
                echo "    → $path"
                ls -la "$path" 2>/dev/null || true
            done
            bootloader_files+=("$file:$found_paths")
        fi
    done
    
    # 3. KERNEL AND INITRAMFS DETECTION
    print_info "Searching for kernel files..."
    local kernel_patterns=(
        "vmlinuz-*"
        "bzImage*"
        "kernel*"
        "linux*"
    )
    
    for pattern in "${kernel_patterns[@]}"; do
        local found_kernels
        found_kernels=$(find /boot /efi /esp -name "$pattern" -type f 2>/dev/null || true)
        if [[ -n "$found_kernels" ]]; then
            print_found "Kernel files matching $pattern:"
            echo "$found_kernels" | while read -r path; do
                echo "    → $path ($(ls -lh "$path" 2>/dev/null | awk '{print $5}' || echo 'unknown'))"
            done
            kernel_files+=("$pattern:$found_kernels")
        fi
    done
    
    print_info "Searching for initramfs files..."
    local initramfs_patterns=(
        "initramfs-*"
        "initrd-*"
        "initrd.img*"
    )
    
    for pattern in "${initramfs_patterns[@]}"; do
        local found_initramfs
        found_initramfs=$(find /boot /efi /esp -name "$pattern" -type f 2>/dev/null || true)
        if [[ -n "$found_initramfs" ]]; then
            print_found "Initramfs files matching $pattern:"
            echo "$found_initramfs" | while read -r path; do
                echo "    → $path ($(ls -lh "$path" 2>/dev/null | awk '{print $5}' || echo 'unknown'))"
            done
            initramfs_files+=("$pattern:$found_initramfs")
        fi
    done
    
    # 4. MICROCODE DETECTION
    print_info "Searching for microcode files..."
    local microcode_patterns=(
        "intel-ucode.img"
        "amd-ucode.img"
        "*-ucode.img"
    )
    
    for pattern in "${microcode_patterns[@]}"; do
        local found_microcode
        found_microcode=$(find / -name "$pattern" -type f 2>/dev/null | head -5 || true)
        if [[ -n "$found_microcode" ]]; then
            print_found "Microcode files matching $pattern:"
            echo "$found_microcode" | while read -r path; do
                echo "    → $path ($(ls -lh "$path" 2>/dev/null | awk '{print $5}' || echo 'unknown'))"
            done
            microcode_files+=("$pattern:$found_microcode")
        fi
    done
    
    # 5. CRITICAL BOOT FILE VERIFICATION
    print_info "Verifying critical boot files..."
    local critical_files=(
        "/boot/vmlinuz-linux"
        "/boot/initramfs-linux.img"
        "/boot/initramfs-linux-fallback.img"
    )
    
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]]; then
            print_found "Critical file: $file ✓"
        else
            print_missing "Critical file: $file ✗"
            print_tip "Reinstall kernel: sudo pacman -S linux"
        fi
    done
    
    log_action "Comprehensive boot detection completed - ${#bootloader_files[@]} bootloader files, ${#kernel_files[@]} kernel files found"
}

# 5. UNIFIED KERNEL IMAGE (UKI) DETECTION
unified_kernel_detection() {
    print_header "5. UNIFIED KERNEL IMAGE (UKI) DETECTION"
    
    local uki_found=false
    local uki_files=()
    local traditional_setup=false
    local uki_tools_available=false
    
    print_info "Scanning for Unified Kernel Images (UKI)..."
    
    # 1. CHECK FOR UKI FILES
    print_info "Method 1: Searching for UKI .efi files..."
    local uki_patterns=(
        "linux*.efi"
        "arch*.efi"
        "vmlinuz*.efi"
        "kernel*.efi"
        "*-linux*.efi"
    )
    
    for pattern in "${uki_patterns[@]}"; do
        local found_uki
        found_uki=$(find /boot /efi /esp -name "$pattern" -type f 2>/dev/null || true)
        if [[ -n "$found_uki" ]]; then
            print_found "Potential UKI files matching $pattern:"
            echo "$found_uki" | while read -r uki_file; do
                echo "    → $uki_file ($(ls -lh "$uki_file" 2>/dev/null | awk '{print $5}' || echo 'unknown'))"
                
                # Verify if it's actually a UKI by checking file type and size
                local file_info
                file_info=$(file "$uki_file" 2>/dev/null || echo "")
                if echo "$file_info" | grep -qi "PE32.*executable"; then
                    local file_size_mb
                    file_size_mb=$(stat -c%s "$uki_file" 2>/dev/null | awk '{print int($1/1024/1024)}' || echo "0")
                    if (( file_size_mb > 10 )); then  # UKI files are typically >10MB
                        print_success "    ✓ Confirmed UKI: $uki_file ($file_size_mb MB)"
                        uki_files+=("$uki_file")
                        uki_found=true
                    else
                        print_info "    ⚠ Small EFI file: $uki_file ($file_size_mb MB) - may not be UKI"
                    fi
                fi
            done
        fi
    done
    
    # 2. CHECK SYSTEMD-BOOT ENTRIES FOR UKI
    print_info "Method 2: Analyzing systemd-boot entries for UKI configuration..."
    local boot_entries
    boot_entries=$(find /boot /efi /esp -path "*/entries/*.conf" 2>/dev/null || true)
    if [[ -n "$boot_entries" ]]; then
        echo "$boot_entries" | while read -r entry_file; do
            if [[ -f "$entry_file" ]]; then
                print_info "Analyzing boot entry: $(basename "$entry_file")"
                
                # Check if entry points to .efi file (UKI) or traditional linux+initrd
                if grep -q "^efi" "$entry_file" 2>/dev/null; then
                    local efi_line
                    efi_line=$(grep "^efi" "$entry_file" | head -1 || echo "")
                    print_found "UKI entry detected: $efi_line"
                    uki_found=true
                elif grep -q "^linux" "$entry_file" && grep -q "^initrd" "$entry_file"; then
                    print_info "Traditional kernel+initrd setup detected in $(basename "$entry_file")"
                    traditional_setup=true
                else
                    print_warning "Unknown boot entry format in $(basename "$entry_file")"
                fi
                
                # Show entry content for analysis
                echo "    Entry content:"
                head -8 "$entry_file" 2>/dev/null | sed 's/^/      /' || true
            fi
        done
    fi
    
    # 3. CHECK FOR UKI GENERATION TOOLS
    print_info "Method 3: Checking for UKI generation tools..."
    local uki_tools=(
        "ukify"
        "dracut"
        "mkinitcpio"
        "systemd-stub"
    )
    
    for tool in "${uki_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            print_found "UKI tool available: $tool"
            uki_tools_available=true
            
            case "$tool" in
                "ukify")
                    # Check ukify configuration
                    if ukify --help &>/dev/null; then
                        print_success "ukify is functional"
                    fi
                    ;;
                "mkinitcpio")
                    # Check mkinitcpio for UKI support
                    if mkinitcpio --help 2>&1 | grep -q "uki\|unified"; then
                        print_found "mkinitcpio supports UKI generation"
                    fi
                    ;;
                "systemd-stub")
                    local stub_location
                    stub_location=$(find /usr -name "systemd-stub*" -type f 2>/dev/null | head -1 || echo "")
                    if [[ -n "$stub_location" ]]; then
                        print_found "systemd-stub available at: $stub_location"
                    fi
                    ;;
            esac
        fi
    done
    
    # 4. CHECK CURRENT RUNNING KERNEL SOURCE
    print_info "Method 4: Analyzing current running kernel source..."
    local cmdline_source
    cmdline_source=$(cat /proc/cmdline 2>/dev/null || echo "")
    if [[ -n "$cmdline_source" ]]; then
        print_info "Current kernel command line:"
        echo "    $cmdline_source"
        
        # UKI kernels often have embedded command lines
        if ! echo "$cmdline_source" | grep -q "root="; then
            print_warning "No explicit root= parameter - may indicate UKI with embedded cmdline"
        fi
    fi
    
    # 5. GENERATE UKI DETECTION SUMMARY
    print_header "UKI DETECTION SUMMARY"
    
    if [[ "$uki_found" == true ]]; then
        print_success "🎯 UNIFIED KERNEL IMAGE (UKI) DETECTED!"
        print_info "Your system appears to be using Unified Kernel Images"
        print_info "UKI files found: ${#uki_files[@]}"
        if (( ${#uki_files[@]} > 0 )); then
            print_info "UKI files:"
            for uki_file in "${uki_files[@]}"; do
                echo "    → $uki_file"
            done
        fi
        
        print_tip "UKI Benefits:"
        echo "  • Single file contains kernel + initramfs + cmdline"
        echo "  • Better security with signed images"
        echo "  • Simplified boot process"
        echo "  • Secure Boot friendly"
        
    elif [[ "$traditional_setup" == true ]]; then
        print_info "📁 TRADITIONAL KERNEL SETUP DETECTED"
        print_info "Your system uses separate kernel and initramfs files"
        print_tip "Consider migrating to UKI for:"
        echo "  • Enhanced security"
        echo "  • Simplified maintenance"
        echo "  • Better Secure Boot integration"
        
    else
        print_warning "⚠️ UNCLEAR KERNEL SETUP"
        print_warning "Could not definitively determine kernel configuration"
        print_tip "Manual investigation recommended"
    fi
    
    # 6. UKI MIGRATION RECOMMENDATIONS
    if [[ "$uki_found" == false && "$uki_tools_available" == true ]]; then
        print_info "🔄 UKI MIGRATION POSSIBLE"
        print_tip "You have UKI tools available. To migrate to UKI:"
        echo ""
        echo "# Install ukify (if not available):"
        echo "sudo pacman -S systemd-ukify"
        echo ""
        echo "# Generate UKI with ukify:"
        echo "sudo ukify build \\"
        echo "  --linux=/boot/vmlinuz-linux \\"
        echo "  --initrd=/boot/initramfs-linux.img \\"
        echo "  --cmdline=\"\$(cat /proc/cmdline)\" \\"
        echo "  --output=/boot/EFI/Linux/arch-linux.efi"
        echo ""
        echo "# Update systemd-boot entry to use UKI:"
        echo "echo 'efi /EFI/Linux/arch-linux.efi' | sudo tee /boot/loader/entries/arch-uki.conf"
    fi
    
    log_action "UKI detection completed - UKI found: $uki_found, Traditional: $traditional_setup, Tools available: $uki_tools_available"
}

# 6. INTELLIGENT DISK SPACE ANALYSIS
intelligent_disk_analysis() {
    print_header "6. INTELLIGENT DISK SPACE ANALYSIS"
    
    # Current disk usage
    print_info "Current disk usage overview:"
    df -h | grep -E '^/dev' || true
    
    # Check for AI model directories (common space hogs)
    print_info "Scanning for large directories..."
    local ai_space=0
    
    if [[ -d "$HOME/.lmstudio" ]]; then
        local lmstudio_size
        lmstudio_size=$(du -sb "$HOME/.lmstudio" 2>/dev/null | cut -f1 || echo "0")
        ai_space=$((ai_space + lmstudio_size))
        print_warning "LM Studio found: $(du -sh "$HOME/.lmstudio" 2>/dev/null | cut -f1 || echo 'unknown')"
        print_tip "Consider removing if you prefer Ollama: rm -rf ~/.lmstudio"
    fi
    
    if [[ -d "$HOME/.ollama" ]]; then
        local ollama_size
        ollama_size=$(du -sb "$HOME/.ollama" 2>/dev/null | cut -f1 || echo "0")
        ai_space=$((ai_space + ollama_size))
        print_warning "Ollama user directory found: $(du -sh "$HOME/.ollama" 2>/dev/null | cut -f1 || echo 'unknown')"
    fi
    
    if [[ -d "/var/lib/ollama" ]]; then
        local ollama_sys_size
        ollama_sys_size=$(sudo du -sb "/var/lib/ollama" 2>/dev/null | cut -f1 || echo "0")
        ai_space=$((ai_space + ollama_sys_size))
        print_warning "Ollama system directory found: $(sudo du -sh "/var/lib/ollama" 2>/dev/null | cut -f1 || echo 'unknown')"
    fi
    
    if (( ai_space > 10737418240 )); then  # 10GB
        print_critical "Multiple AI model systems detected (>10GB). Consider consolidating!"
        print_tip "Choose either LM Studio OR Ollama, not both"
    fi
    
    # Large file detection
    print_info "Scanning for large files (>500MB)..."
    local large_files
    large_files=$(find "$HOME" -type f -size +500M -not -path "*/.*" 2>/dev/null | head -10 || true)
    if [[ -n "$large_files" ]]; then
        print_warning "Large files found:"
        echo "$large_files" | while read -r file; do
            echo "  $(du -sh "$file" 2>/dev/null || echo "unknown size $file")"
        done
    fi
    
    log_action "Disk analysis completed"
}

# 7. SMART PACKAGE MAINTENANCE
smart_package_maintenance() {
    print_header "7. SMART PACKAGE MAINTENANCE"
    
    # Check for updates
    print_info "Checking for system updates..."
    if command -v checkupdates &>/dev/null; then
        local updates
        updates=$(checkupdates 2>/dev/null | wc -l || echo "0")
        if (( updates == 0 )); then
            print_success "System is up to date"
        else
            print_warning "$updates package updates available"
            print_tip "Update with: sudo pacman -Syu"
        fi
    else
        print_info "Install pacman-contrib for better update checking"
        print_tip "Install: sudo pacman -S pacman-contrib"
    fi
    
    # AUR packages
    local aur_helper=""
    if command -v yay &>/dev/null; then
        aur_helper="yay"
    elif command -v paru &>/dev/null; then
        aur_helper="paru"
    fi
    
    if [[ -n "$aur_helper" ]]; then
        print_info "Checking AUR packages with $aur_helper..."
        local aur_updates
        aur_updates=$($aur_helper -Qua 2>/dev/null | wc -l || echo "0")
        if (( aur_updates > 0 )); then
            print_warning "$aur_updates AUR package updates available"
            print_tip "Update with: $aur_helper -Sua"
        else
            print_success "AUR packages up to date"
        fi
    else
        print_info "No AUR helper detected"
        print_tip "Install yay or paru for AUR package management"
    fi
    
    # Orphaned packages
    print_info "Checking for orphaned packages..."
    local orphans
    orphans=$(pacman -Qdtq 2>/dev/null | wc -l || echo "0")
    if (( orphans == 0 )); then
        print_success "No orphaned packages found"
    else
        print_warning "$orphans orphaned packages found"
        if (( orphans <= 10 )); then
            pacman -Qdtq 2>/dev/null || true
        else
            pacman -Qdtq 2>/dev/null | head -10 || true
            echo "... and $((orphans - 10)) more"
        fi
        print_tip "Remove with: sudo pacman -Rns \$(pacman -Qdtq)"
    fi
    
    log_action "Package maintenance completed - $updates updates, $orphans orphans"
}

# 8. SECURITY AND PERFORMANCE CHECKS
security_performance_checks() {
    print_header "8. SECURITY & PERFORMANCE ANALYSIS"
    
    # Boot security
    print_info "Checking boot security..."
    if [[ -d "/boot" ]]; then
        local boot_perms
        boot_perms=$(stat -c "%a" /boot 2>/dev/null || echo "unknown")
        if [[ "$boot_perms" == "755" ]]; then
            print_warning "/boot has world-readable permissions ($boot_perms)"
            print_tip "Secure with: sudo chmod 700 /boot"
        else
            print_success "/boot permissions are secure ($boot_perms)"
        fi
        
        # Check random seed permissions
        if [[ -f "/boot/loader/random-seed" ]]; then
            local seed_perms
            seed_perms=$(stat -c "%a" /boot/loader/random-seed 2>/dev/null || echo "unknown")
            if [[ "$seed_perms" != "600" ]]; then
                print_warning "Random seed file permissions: $seed_perms (should be 600)"
                print_tip "Fix: sudo chmod 600 /boot/loader/random-seed"
            fi
        fi
    fi
    
    # Memory usage
    print_info "Memory usage analysis:"
    free -h || true
    
    # Security packages
    print_info "Checking security packages..."
    local security_packages=("sudo" "ufw" "fail2ban" "rkhunter" "clamav")
    local missing_security=()
    for pkg in "${security_packages[@]}"; do
        if pacman -Q "$pkg" &>/dev/null; then
            print_success "$pkg is installed"
        else
            missing_security+=("$pkg")
        fi
    done
    
    if (( ${#missing_security[@]} > 0 )); then
        print_info "Consider installing security packages: ${missing_security[*]}"
        print_tip "Install with: sudo pacman -S ${missing_security[*]}"
    fi
    
    log_action "Security and performance checks completed"
}

# 9. COMPREHENSIVE FIX GENERATOR
generate_comprehensive_fixes() {
    print_header "9. COMPREHENSIVE FIX COMMANDS"
    
    echo "# ============================================================================"
    echo "# COMPREHENSIVE ARCH LINUX MAINTENANCE & FIX COMMANDS"
    echo "# Generated on: $(date)"
    echo "# Script version: $SCRIPT_VERSION"
    echo "# GitHub: $GITHUB_REPO"
    echo "# ============================================================================"
    echo ""
    
    echo "# CRITICAL: Always check Arch news before updating!"
    echo "curl -s https://archlinux.org/news/ | grep -o '<h2[^>]*>[^<]*</h2>' | head -5"
    echo "echo 'Review breaking changes above before proceeding!'"
    echo ""
    
    echo "# 1. SYSTEM UPDATE"
    echo "sudo pacman -Syu"
    echo ""
    
    echo "# 2. BOOTLOADER MAINTENANCE"
    echo "# For systemd-boot:"
    echo "sudo bootctl update"
    echo "sudo systemctl enable systemd-boot-update.service"
    echo ""
    echo "# For GRUB:"
    echo "sudo grub-mkconfig -o /boot/grub/grub.cfg"
    echo ""
    
    echo "# 3. UKI MANAGEMENT"
    echo "# Check if system uses UKI:"
    echo "bootctl list | grep -i unified || echo 'No UKI detected'"
    echo "find /boot -name '*.efi' -size +10M  # Large .efi files are likely UKI"
    echo ""
    echo "# Generate UKI manually (if tools available):"
    echo "sudo ukify build \\"
    echo "  --linux=/boot/vmlinuz-linux \\"
    echo "  --initrd=/boot/initramfs-linux.img \\"
    echo "  --cmdline=\"\$(cat /proc/cmdline)\" \\"
    echo "  --output=/boot/EFI/Linux/arch-linux.efi"
    echo ""
    
    echo "# 4. COMMON ERROR FIXES"
    echo "# Fix wireless regulatory database:"
    echo "sudo pacman -S wireless-regdb"
    echo ""
    echo "# Fix Bluetooth issues:"
    echo "sudo systemctl restart bluetooth"
    echo "sudo pacman -S bluez bluez-utils"
    echo ""
    echo "# Fix GNOME keyring issues:"
    echo "sudo pacman -S gnome-keyring"
    echo "# Then log out and log back in"
    echo ""
    echo "# Fix audio issues:"
    echo "systemctl --user restart pipewire pipewire-pulse wireplumber"
    echo ""
    
    echo "# 5. SECURITY HARDENING"
    echo "sudo chmod 700 /boot"
    echo "sudo chmod 600 /boot/loader/random-seed 2>/dev/null || true"
    echo "sudo pacman -S --needed ufw fail2ban"
    echo ""
    
    echo "# 6. DISK SPACE OPTIMIZATION"
    echo "# Clean package cache:"
    echo "sudo paccache -r || sudo pacman -Sc"
    echo ""
    echo "# Remove orphaned packages:"
    echo "sudo pacman -Rns \$(pacman -Qdtq) 2>/dev/null || echo 'No orphans'"
    echo ""
    echo "# Clean development caches:"
    echo "rm -rf ~/.config/Code/CachedExtensionVSIXs/* 2>/dev/null || true"
    echo "rm -rf ~/.cache/google-chrome/* 2>/dev/null || true"
    echo "npm cache clean --force 2>/dev/null || true"
    echo "rm -rf ~/.cargo/registry/cache/* 2>/dev/null || true"
    echo ""
    echo "# Clean system logs:"
    echo "sudo journalctl --vacuum-time=2weeks"
    echo ""
    
    echo "# 7. AI MODEL OPTIMIZATION (if applicable)"
    echo "# Choose ONE AI platform to avoid duplication:"
    echo "# Remove LM Studio: rm -rf ~/.lmstudio"
    echo "# OR optimize Ollama models:"
    echo "# ollama list  # Review installed models"
    echo "# ollama rm <large-model-name>  # Remove unused models"
    echo ""
    
    echo "# 8. KERNEL AND INITRAMFS"
    echo "sudo mkinitcpio -P  # Regenerate initramfs"
    echo "sudo pacman -S linux-lts  # Install LTS kernel (optional)"
    echo ""
    
    echo "# 9. INSTALL ESSENTIAL TOOLS"
    echo "sudo pacman -S --needed pacman-contrib smartmontools wireless-regdb"
    echo "sudo pacman -S --needed base-devel git wget curl"
    echo ""
    
    echo "# 10. VERIFICATION COMMANDS"
    echo "# After fixes, verify system health:"
    echo "systemctl --failed  # Check for failures"
    echo "df -h  # Check disk space"
    echo "pacman -Qdt  # Check for orphans"
    echo "dmesg | grep -i error | tail -5  # Recent errors"
    
    log_action "Comprehensive fix commands generated"
}

# 10. SYSTEM HEALTH SUMMARY
generate_health_summary() {
    print_header "10. SYSTEM HEALTH SUMMARY"
    
    local health_score=100
    local issues_found=()
    
    # Check critical factors
    local root_usage
    root_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//' || echo "0")
    if (( root_usage > 85 )); then
        health_score=$((health_score - 20))
        issues_found+=("High disk usage: ${root_usage}%")
    elif (( root_usage > 70 )); then
        health_score=$((health_score - 10))
        issues_found+=("Moderate disk usage: ${root_usage}%")
    fi
    
    # Check failed services
    local failed_services
    failed_services=$(systemctl --failed --no-legend | wc -l || echo "0")
    if (( failed_services > 0 )); then
        health_score=$((health_score - failed_services * 5))
        issues_found+=("$failed_services failed services")
    fi
    
    # Check recent errors
    local recent_errors
    recent_errors=$(journalctl --since "24 hours ago" -p err --no-pager 2>/dev/null | wc -l || echo "0")
    if (( recent_errors > 10 )); then
        health_score=$((health_score - 15))
        issues_found+=("High error count: $recent_errors errors in 24h")
    elif (( recent_errors > 0 )); then
        health_score=$((health_score - 5))
        issues_found+=("$recent_errors recent errors")
    fi
    
    # Health rating
    if (( health_score >= 90 )); then
        print_success "System Health: EXCELLENT ($health_score/100)"
    elif (( health_score >= 75 )); then
        print_success "System Health: GOOD ($health_score/100)"
    elif (( health_score >= 60 )); then
        print_warning "System Health: FAIR ($health_score/100)"
    else
        print_error "System Health: POOR ($health_score/100)"
    fi
    
    # Issues summary
    if (( ${#issues_found[@]} > 0 )); then
        print_info "Issues found:"
        for issue in "${issues_found[@]}"; do
            echo "  • $issue"
        done
    else
        print_success "No significant issues found!"
    fi
    
    # System info
    print_info "System Information:"
    echo "  • Uptime: $(uptime -p 2>/dev/null || echo 'unknown')"
    echo "  • Kernel: $(uname -r)"
    echo "  • Architecture: $(uname -m)"
    echo "  • Memory: $(free -h | awk 'NR==2{printf "%.1fG used", $3/1024/1024}' 2>/dev/null || echo 'unknown')"
    
    log_action "Health summary completed - Score: $health_score/100"
}

# Main execution function
main() {
    print_header "ULTIMATE ARCH LINUX MAINTENANCE SUITE"
    print_info "Version: $SCRIPT_VERSION | Date: $SCRIPT_DATE"
    print_info "Enhanced with UKI detection and comprehensive file verification"
    print_info "GitHub: $GITHUB_REPO"
    print_info "Log file: $LOG_FILE"
    echo ""
    
    log_action "Ultimate maintenance script started (version $SCRIPT_VERSION)"
    
    # Execute all checks
    check_prerequisites
    pre_update_checks
    check_failed_services
    check_system_logs
    comprehensive_boot_detection
    unified_kernel_detection
    intelligent_disk_analysis
    smart_package_maintenance
    security_performance_checks
    generate_comprehensive_fixes
    generate_health_summary
    
    print_header "ULTIMATE MAINTENANCE ANALYSIS COMPLETE"
    print_success "Comprehensive system analysis with UKI detection finished!"
    print_tip "Review all warnings and apply suggested fixes as needed"
    print_tip "Save this output: bash <(curl -fsSL $GITHUB_REPO/raw/main/maintain.sh) > maintenance_report_\$(date +%Y%m%d_%H%M%S).txt"
    print_info "For latest updates and issues: $GITHUB_REPO"
    
    log_action "Ultimate maintenance script completed successfully"
}

# Enhanced script execution handler
script_entry_point() {
    # Verify bash environment
    if [[ -z "${BASH_VERSION:-}" ]]; then
        printf "ERROR: This script requires bash\n" >&2
        printf "Current shell: %s\n" "${0}" >&2
        printf "Please run: bash %s %s\n" "${0}" "$*" >&2
        return 1
    fi
    
    # Check bash version
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        printf "ERROR: This script requires bash 4.0 or later\n" >&2
        printf "Current version: %s\n" "${BASH_VERSION}" >&2
        return 1
    fi
    
    printf "🚀 Starting Arch Linux Maintenance Suite...\n" >&2
    main "$@"
}

# Bulletproof script entry point
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]] 2>/dev/null; then
    script_entry_point "$@"
elif [[ -n "${ZSH_VERSION:-}" ]]; then
    # Handle zsh compatibility
    if [[ "${(%):-%x}" == "${0}" ]]; then
        script_entry_point "$@"
    fi
else
    # Final fallback
    if [[ "$0" != "-bash" ]] && [[ "$0" != "-sh" ]]; then
        script_entry_point "$@"
    fi
fi
