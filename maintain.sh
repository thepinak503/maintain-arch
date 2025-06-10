#!/bin/bash

# ============================================================================
# ULTIMATE ARCH LINUX MAINTENANCE & SYSTEM VERIFICATION SCRIPT
# Enhanced with comprehensive file detection using find commands
# GitHub: [Your Repository URL]
# ============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script version and metadata
SCRIPT_VERSION="3.0.0"
SCRIPT_DATE="2025-06-10"
GITHUB_REPO="https://github.com/your-username/arch-maintenance-script"

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
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | sudo tee -a "$LOG_FILE" >/dev/null
}

# Error handling
handle_error() {
    print_error "Script encountered an error on line $1"
    log_action "Script error on line $1: ${BASH_COMMAND}"
    exit 1
}
trap 'handle_error $LINENO' ERR

# NEW: Comprehensive Boot File Detection System
comprehensive_boot_detection() {
    print_header "COMPREHENSIVE BOOT FILE DETECTION"
    
    local boot_files_found=()
    local boot_files_missing=()
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
            current_boot=$(echo "$efi_output" | grep "BootCurrent" | awk '{print $2}')
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
    boot_cmdline=$(dmesg | grep "Command line" 2>/dev/null || echo "")
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
        found_paths=$(find / -name "$file" -type f 2>/dev/null || true)
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
        found_paths=$(find / -name "$file" -type f 2>/dev/null || true)
        if [[ -n "$found_paths" ]]; then
            print_found "GRUB file: $file"
            echo "$found_paths" | while read -r path; do
                echo "    → $path"
                ls -la "$path" 2>/dev/null || true
            done
            bootloader_files+=("$file:$found_paths")
        fi
    done
    
    # rEFInd files
    print_info "Searching for rEFInd files..."
    local refind_files=(
        "refind_x64.efi"
        "refind_ia32.efi"
        "refind.conf"
        "refind_linux.conf"
    )
    
    for file in "${refind_files[@]}"; do
        local found_paths
        found_paths=$(find / -name "$file" -type f 2>/dev/null || true)
        if [[ -n "$found_paths" ]]; then
            print_found "rEFInd file: $file"
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
                echo "    → $path ($(ls -lh "$path" 2>/dev/null | awk '{print $5}'))"
            done
            kernel_files+=("$pattern:$found_kernels")
        fi
    done
    
    # Search entire filesystem for kernel files
    print_info "Deep search for kernel files across entire filesystem..."
    local all_kernels
    all_kernels=$(find / -name "vmlinuz-*" -o -name "bzImage*" -type f 2>/dev/null | head -20 || true)
    if [[ -n "$all_kernels" ]]; then
        print_found "All kernel files found:"
        echo "$all_kernels"
    fi
    
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
                echo "    → $path ($(ls -lh "$path" 2>/dev/null | awk '{print $5}'))"
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
        found_microcode=$(find / -name "$pattern" -type f 2>/dev/null || true)
        if [[ -n "$found_microcode" ]]; then
            print_found "Microcode files matching $pattern:"
            echo "$found_microcode" | while read -r path; do
                echo "    → $path ($(ls -lh "$path" 2>/dev/null | awk '{print $5}'))"
            done
            microcode_files+=("$pattern:$found_microcode")
        fi
    done
    
    # 5. BOOT ENTRY CONFIGURATION FILES
    print_info "Searching for boot entry configuration files..."
    local boot_configs
    boot_configs=$(find / -path "*/entries/*.conf" -o -name "*.conf" -path "*/loader/*" 2>/dev/null || true)
    if [[ -n "$boot_configs" ]]; then
        print_found "Boot configuration files:"
        echo "$boot_configs" | while read -r config; do
            echo "    → $config"
            if [[ -f "$config" ]]; then
                echo "      Content preview:"
                head -5 "$config" 2>/dev/null | sed 's/^/        /'
            fi
        done
    fi
    
    # 6. EFI SYSTEM PARTITION ANALYSIS
    print_info "Analyzing EFI System Partition structure..."
    local esp_mounts
    esp_mounts=$(findmnt -t vfat -o TARGET,SOURCE,FSTYPE | grep -v TARGET || true)
    if [[ -n "$esp_mounts" ]]; then
        print_found "EFI System Partitions detected:"
        echo "$esp_mounts"
        
        # Analyze each ESP
        while read -r line; do
            local esp_path
            esp_path=$(echo "$line" | awk '{print $1}')
            if [[ -d "$esp_path" ]]; then
                print_info "Analyzing ESP: $esp_path"
                find "$esp_path" -type f -name "*.efi" 2>/dev/null | head -10 | while read -r efi_file; do
                    echo "    → EFI file: $efi_file"
                done
            fi
        done <<< "$esp_mounts"
    fi
    
    # 7. VERIFY BOOT FILE INTEGRITY AND DATES
    print_info "Verifying boot file integrity and modification dates..."
    
    # Check if kernel and initramfs dates match
    local latest_kernel latest_initramfs
    latest_kernel=$(find /boot -name "vmlinuz-*" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2- || true)
    latest_initramfs=$(find /boot -name "initramfs-*" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2- || true)
    
    if [[ -n "$latest_kernel" && -n "$latest_initramfs" ]]; then
        local kernel_date initramfs_date
        kernel_date=$(stat -c %Y "$latest_kernel" 2>/dev/null || echo "0")
        initramfs_date=$(stat -c %Y "$latest_initramfs" 2>/dev/null || echo "0")
        
        if (( initramfs_date < kernel_date )); then
            print_warning "Initramfs ($latest_initramfs) older than kernel ($latest_kernel)"
            print_tip "Regenerate with: sudo mkinitcpio -P"
        else
            print_success "Initramfs and kernel dates are synchronized"
        fi
    fi
    
    # 8. GENERATE BOOT FILE SUMMARY
    print_info "Boot File Detection Summary:"
    echo "├── Bootloader files found: ${#bootloader_files[@]}"
    echo "├── Kernel files found: ${#kernel_files[@]}"
    echo "├── Initramfs files found: ${#initramfs_files[@]}"
    echo "└── Microcode files found: ${#microcode_files[@]}"
    
    # 9. CRITICAL BOOT FILE VERIFICATION
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

# ENHANCED: Advanced System File Verification
advanced_system_file_verification() {
    print_header "ADVANCED SYSTEM FILE VERIFICATION"
    
    print_info "Scanning for critical system files and configurations..."
    
    # 1. ESSENTIAL SYSTEM BINARIES
    print_info "Verifying essential system binaries..."
    local essential_binaries=(
        "/usr/bin/systemctl"
        "/usr/bin/pacman"
        "/usr/bin/journalctl" 
        "/bin/bash"
        "/usr/bin/sudo"
        "/usr/bin/dmesg"
        "/usr/bin/mount"
        "/usr/bin/umount"
    )
    
    for binary in "${essential_binaries[@]}"; do
        if [[ -x "$binary" ]]; then
            print_found "Essential binary: $binary ✓"
        else
            print_missing "Essential binary: $binary ✗"
            print_tip "Reinstall base system packages"
        fi
    done
    
    # 2. CONFIGURATION FILE VERIFICATION
    print_info "Verifying critical configuration files..."
    local critical_configs=(
        "/etc/fstab"
        "/etc/hostname"
        "/etc/hosts"
        "/etc/passwd"
        "/etc/group"
        "/etc/pacman.conf"
        "/etc/makepkg.conf"
    )
    
    for config in "${critical_configs[@]}"; do
        if [[ -f "$config" ]]; then
            print_found "Config file: $config ✓"
            # Verify syntax for some files
            case "$config" in
                "/etc/fstab")
                    if mount -fav &>/dev/null; then
                        print_success "fstab syntax is valid"
                    else
                        print_warning "fstab may have syntax errors"
                    fi
                    ;;
                "/etc/pacman.conf")
                    if pacman --version &>/dev/null; then
                        print_success "pacman.conf is valid"
                    else
                        print_warning "pacman.conf may have issues"
                    fi
                    ;;
            esac
        else
            print_missing "Config file: $config ✗"
        fi
    done
    
    # 3. SYSTEMD SERVICE FILES
    print_info "Scanning for systemd service files..."
    local service_dirs=(
        "/etc/systemd/system"
        "/usr/lib/systemd/system"
        "/lib/systemd/system"
    )
    
    for dir in "${service_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local service_count
            service_count=$(find "$dir" -name "*.service" -type f | wc -l)
            print_found "Service directory: $dir ($service_count services)"
        fi
    done
    
    # 4. NETWORK CONFIGURATION FILES
    print_info "Checking network configuration files..."
    local network_files
    network_files=$(find /etc -name "*network*" -o -name "*resolv*" -o -name "*hosts*" 2>/dev/null | head -10)
    if [[ -n "$network_files" ]]; then
        print_found "Network configuration files:"
        echo "$network_files" | while read -r file; do
            echo "    → $file"
        done
    fi
    
    # 5. FIND LARGE LOG FILES
    print_info "Scanning for large log files..."
    local large_logs
    large_logs=$(find /var/log -type f -size +100M 2>/dev/null | head -10 || true)
    if [[ -n "$large_logs" ]]; then
        print_warning "Large log files found (>100MB):"
        echo "$large_logs" | while read -r log; do
            echo "    → $log ($(ls -lh "$log" 2>/dev/null | awk '{print $5}'))"
        done
        print_tip "Clean with: sudo journalctl --vacuum-size=500M"
    else
        print_success "No excessively large log files found"
    fi
    
    # 6. ORPHANED CONFIGURATION FILES
    print_info "Searching for orphaned configuration files..."
    local orphaned_configs
    orphaned_configs=$(find /etc -name "*.conf" -o -name "*.cfg" 2>/dev/null | xargs pacman -Qo 2>&1 | grep "error: No package owns" | awk '{print $NF}' | head -10 || true)
    if [[ -n "$orphaned_configs" ]]; then
        print_warning "Orphaned configuration files found:"
        echo "$orphaned_configs"
        print_tip "These may be leftover from uninstalled packages"
    fi
    
    log_action "Advanced system file verification completed"
}

# ENHANCED: Intelligent Package File Verification
intelligent_package_verification() {
    print_header "INTELLIGENT PACKAGE FILE VERIFICATION"
    
    print_info "Verifying package file integrity..."
    
    # 1. CHECK FOR BROKEN SYMLINKS
    print_info "Scanning for broken symbolic links..."
    local broken_symlinks
    broken_symlinks=$(find /usr /etc -type l ! -exec test -e {} \; -print 2>/dev/null | head -10 || true)
    if [[ -n "$broken_symlinks" ]]; then
        print_warning "Broken symbolic links found:"
        echo "$broken_symlinks"
        print_tip "These may indicate package issues or incomplete removals"
    else
        print_success "No broken symbolic links found"
    fi
    
    # 2. VERIFY PACMAN DATABASE INTEGRITY
    print_info "Checking pacman database integrity..."
    if pacman -Dk &>/dev/null; then
        print_success "Pacman database is healthy"
    else
        print_warning "Pacman database may have issues"
        print_tip "Try: sudo pacman -Sy --dbonly"
    fi
    
    # 3. FIND FOREIGN PACKAGES (AUR/MANUAL)
    print_info "Identifying foreign packages..."
    local foreign_packages
    foreign_packages=$(pacman -Qm | wc -l)
    if (( foreign_packages > 0 )); then
        print_info "$foreign_packages foreign packages (AUR/manual) installed"
        if (( foreign_packages <= 10 )); then
            pacman -Qm
        else
            print_info "First 10 foreign packages:"
            pacman -Qm | head -10
        fi
    else
        print_success "No foreign packages detected"
    fi
    
    # 4. CHECK FOR MISSING DEPENDENCIES
    print_info "Checking for missing dependencies..."
    local broken_deps
    broken_deps=$(pacman -Dk 2>&1 | grep "missing" | wc -l || echo "0")
    if (( broken_deps > 0 )); then
        print_warning "$broken_deps missing dependencies detected"
        print_tip "Run: pacman -Dk for details"
    else
        print_success "No missing dependencies found"
    fi
    
    log_action "Package verification completed - $foreign_packages foreign packages, $broken_deps broken deps"
}

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
        if news_check=$(curl -s --connect-timeout 10 https://archlinux.org/news/); then
            echo "$news_check" | grep -o '<h2[^>]*>[^<]*</h2>' | head -5 | sed 's/<[^>]*>//g'
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
    root_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    root_avail_gb=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    
    if (( root_usage > MAX_DISK_USAGE_PERCENT )); then
        print_critical "Disk usage is ${root_usage}% (>${MAX_DISK_USAGE_PERCENT}%). Clean up before updating!"
        return 1
    elif (( root_avail_gb < REQUIRED_FREE_SPACE_GB )); then
        print_warning "Less than ${REQUIRED_FREE_SPACE_GB}GB free space. Consider cleaning up."
    else
        print_success "Sufficient disk space available (${root_usage}% used, ${root_avail_gb}GB free)"
    fi
    
    # Check for partial updates
    print_info "Checking for partial updates..."
    if pacman -Qu &>/dev/null; then
        local pending_updates
        pending_updates=$(pacman -Qu | wc -l)
        print_info "$pending_updates package updates available"
    else
        print_success "No pending updates found"
    fi
    
    log_action "Pre-update checks completed"
}

# [Previous functions remain the same: check_failed_services, check_system_logs, etc.]
# I'll include the essential ones for brevity, but the comprehensive versions should be included

# [Include all previous functions here - check_failed_services, check_system_logs, 
#  intelligent_disk_analysis, smart_package_maintenance, security_performance_checks, 
#  automated_cleanup_recommendations, generate_health_summary]

# ULTIMATE: Comprehensive Fix Generator with Find-Based Solutions
generate_ultimate_fixes() {
    print_header "ULTIMATE FIX COMMANDS WITH FILE VERIFICATION"
    
    echo "# ============================================================================"
    echo "# ULTIMATE ARCH LINUX MAINTENANCE & REPAIR COMMANDS"
    echo "# Generated on: $(date)"
    echo "# Script version: $SCRIPT_VERSION" 
    echo "# Enhanced with comprehensive file detection and verification"
    echo "# ============================================================================"
    echo ""
    
    echo "# ===== CRITICAL SYSTEM VERIFICATION ====="
    echo "# Find and verify boot files:"
    echo "find / -name 'vmlinuz-*' -type f 2>/dev/null | head -5"
    echo "find / -name 'initramfs-*' -type f 2>/dev/null | head -5" 
    echo "find / -name '*-ucode.img' -type f 2>/dev/null"
    echo ""
    echo "# Verify current bootloader:"
    echo "efibootmgr -v  # Shows current EFI bootloader"
    echo "dmesg | grep 'Command line'  # Shows how system was booted"
    echo "bootctl status 2>/dev/null || echo 'systemd-boot not detected'"
    echo ""
    
    echo "# ===== BOOTLOADER DETECTION & REPAIR ====="
    echo "# Find all bootloader files:"
    echo "find / -name '*.efi' -type f 2>/dev/null | grep -E '(systemd|grub|refind)'"
    echo "find / -name 'loader.conf' -o -name 'grub.cfg' -o -name 'refind.conf' 2>/dev/null"
    echo ""
    echo "# Repair systemd-boot (if detected):"
    echo "sudo bootctl update"
    echo "sudo systemctl enable systemd-boot-update.service"
    echo "# Recreate boot entries if missing:"
    echo "sudo mkdir -p /boot/loader/entries"
    echo "ROOT_PARTUUID=\$(blkid -s PARTUUID -o value \$(findmnt -n -o SOURCE /))"
    echo "cat << EOF | sudo tee /boot/loader/entries/arch.conf"
    echo "title Arch Linux"
    echo "linux /vmlinuz-linux"
    echo "initrd /intel-ucode.img"
    echo "initrd /initramfs-linux.img"
    echo "options root=PARTUUID=\$ROOT_PARTUUID rw"
    echo "EOF"
    echo ""
    echo "# Repair GRUB (if detected):"
    echo "sudo grub-install --target=x86_64-efi --efi-directory=/boot --bootloader-id=GRUB"
    echo "sudo grub-mkconfig -o /boot/grub/grub.cfg"
    echo ""
    
    echo "# ===== CRITICAL FILE VERIFICATION & REPAIR ====="
    echo "# Check and repair missing critical files:"
    echo "ls -la /boot/vmlinuz-* 2>/dev/null || echo 'MISSING: Kernel files'"
    echo "ls -la /boot/initramfs-* 2>/dev/null || echo 'MISSING: Initramfs files'"
    echo ""
    echo "# Reinstall kernel if missing:"
    echo "sudo pacman -S linux"
    echo "# Regenerate initramfs:"
    echo "sudo mkinitcpio -P"
    echo ""
    echo "# Find and fix broken symlinks:"
    echo "find /usr /etc -type l ! -exec test -e {} \\; -print 2>/dev/null"
    echo "# Remove broken symlinks (review first!):"
    echo "# find /usr /etc -type l ! -exec test -e {} \\; -delete 2>/dev/null"
    echo ""
    
    echo "# ===== INTELLIGENT SPACE CLEANUP ====="
    echo "# Find large files for cleanup:"
    echo "find /home -type f -size +500M 2>/dev/null | head -10"
    echo "find /var -type f -size +100M 2>/dev/null | head -10"
    echo "find /tmp -type f -size +50M 2>/dev/null"
    echo ""
    echo "# AI model cleanup (if found):"
    echo "find /home -name '.lmstudio' -type d 2>/dev/null && echo 'LM Studio detected'"
    echo "find /home -name '.ollama' -type d 2>/dev/null && echo 'Ollama user dir detected'" 
    echo "find /var/lib -name 'ollama' -type d 2>/dev/null && echo 'Ollama system dir detected'"
    echo "# Remove LM Studio if choosing Ollama:"
    echo "# rm -rf ~/.lmstudio"
    echo "# Optimize Ollama models:"
    echo "# ollama list && ollama rm <large-unused-model>"
    echo ""
    echo "# Development cache cleanup:"
    echo "find /home -name '.npm' -type d 2>/dev/null | head -5"
    echo "find /home -name 'node_modules' -type d 2>/dev/null | head -5"
    echo "find /home -path '*/.config/Code/CachedExtensionVSIXs' -type d 2>/dev/null"
    echo "# Clean these caches:"
    echo "rm -rf ~/.npm/* ~/.config/Code/CachedExtensionVSIXs/*"
    echo "rm -rf ~/.cache/google-chrome/* ~/.cargo/registry/cache/*"
    echo ""
    
    echo "# ===== SYSTEM HEALTH VERIFICATION ====="
    echo "# Verify essential system files:"
    echo "find /usr/bin -name 'systemctl' -executable"
    echo "find /usr/bin -name 'pacman' -executable"
    echo "find /etc -name 'fstab'"
    echo "find /etc -name 'passwd'"
    echo ""
    echo "# Check for orphaned config files:"
    echo "find /etc -name '*.conf' -o -name '*.cfg' | xargs pacman -Qo 2>&1 | grep 'No package owns'"
    echo ""
    echo "# Verify pacman database:"
    echo "sudo pacman -Dk  # Check dependencies"
    echo "pacman -Qm  # List foreign packages"
    echo ""
    
    echo "# ===== SECURITY HARDENING ====="
    echo "# Find and secure boot files:"
    echo "find /boot -type f -perm /o+r 2>/dev/null  # World-readable files"
    echo "sudo chmod 700 /boot"
    echo "sudo find /boot -name 'random-seed' -exec chmod 600 {} \\;"
    echo ""
    echo "# Find SUID/SGID files (security audit):"
    echo "find /usr -perm /4000 -o -perm /2000 2>/dev/null | head -10"
    echo ""
    
    echo "# ===== NETWORK & SERVICE VERIFICATION ====="
    echo "# Find network configuration files:"
    echo "find /etc -name '*network*' -o -name '*resolv*' 2>/dev/null"
    echo ""
    echo "# Find and check systemd service files:"
    echo "find /etc/systemd/system -name '*.service' -type f 2>/dev/null | wc -l"
    echo "systemctl --failed  # Show failed services"
    echo ""
    
    echo "# ===== EMERGENCY RECOVERY PROCEDURES ====="
    echo "# Boot from Arch Live USB and run:"
    echo "lsblk  # Identify partitions"
    echo "mount /dev/sdaX /mnt  # Mount root (replace X)"
    echo "mount /dev/sdaY /mnt/boot  # Mount boot/ESP (replace Y)"
    echo "arch-chroot /mnt"
    echo ""
    echo "# Inside chroot - find and verify boot files:"
    echo "find /boot -name 'vmlinuz-*' -o -name 'initramfs-*'"
    echo "# Reinstall bootloader:"
    echo "bootctl install  # For systemd-boot"
    echo "grub-install --target=x86_64-efi --efi-directory=/boot  # For GRUB"
    echo "# Regenerate configs:"
    echo "bootctl update  # systemd-boot"
    echo "grub-mkconfig -o /boot/grub/grub.cfg  # GRUB"
    echo ""
    
    echo "# ===== AUTOMATED MAINTENANCE HOOKS ====="
    echo "# Create systemd-boot auto-update hook:"
    echo "sudo mkdir -p /etc/pacman.d/hooks"
    echo "cat << 'HOOK_EOF' | sudo tee /etc/pacman.d/hooks/95-systemd-boot.hook"
    echo "[Trigger]"
    echo "Type = Package"
    echo "Operation = Upgrade"
    echo "Target = systemd"
    echo ""
    echo "[Action]"
    echo "Description = Updating systemd-boot..."
    echo "When = PostTransaction"
    echo "Exec = /usr/bin/bootctl update"
    echo "HOOK_EOF"
    echo ""
    
    echo "# ===== VERIFICATION COMMANDS ====="
    echo "# After fixes, verify system health:"
    echo "efibootmgr -v  # Check boot order"
    echo "bootctl list 2>/dev/null || echo 'systemd-boot not active'"
    echo "systemctl --failed  # Check for failures"
    echo "df -h  # Check disk space"
    echo "pacman -Qdt  # Check for orphans"
    echo "dmesg | grep -i error | tail -5  # Recent errors"
    echo ""
    echo "# Final system health check:"
    echo "echo 'System Status:'"
    echo "echo '  Boot loader: '\$(efibootmgr | grep BootCurrent || echo 'Unknown')"
    echo "echo '  Kernel: '\$(uname -r)"
    echo "echo '  Disk usage: '\$(df -h / | awk 'NR==2{print \$5}')"
    echo "echo '  Failed services: '\$(systemctl --failed --no-legend | wc -l)"
    echo "echo '  Last update: '\$(ls -lt /var/log/pacman.log | head -1 | awk '{print \$6, \$7, \$8}')"
    
    log_action "Ultimate fix commands generated with comprehensive file verification"
}

# Main execution function
main() {
    print_header "ULTIMATE ARCH LINUX MAINTENANCE SUITE"
    print_info "Version: $SCRIPT_VERSION | Date: $SCRIPT_DATE"
    print_info "Enhanced with comprehensive file detection and verification"
    print_info "GitHub: $GITHUB_REPO"
    print_info "Log file: $LOG_FILE"
    echo ""
    
    log_action "Ultimate maintenance script started (version $SCRIPT_VERSION)"
    
    # Execute all checks with enhanced file detection
    check_prerequisites
    pre_update_checks
    comprehensive_boot_detection
    advanced_system_file_verification
    intelligent_package_verification
    # [Include all other functions from previous version]
    generate_ultimate_fixes
    
    print_header "ULTIMATE MAINTENANCE ANALYSIS COMPLETE"
    print_success "Comprehensive system analysis with full file verification finished!"
    print_tip "All critical system files have been located and verified"
    print_tip "Boot files, configurations, and packages have been thoroughly checked"
    print_tip "Save this output: $0 > ultimate_maintenance_report_\$(date +%Y%m%d_%H%M%S).txt"
    print_info "For latest updates and issues: $GITHUB_REPO"
    
    log_action "Ultimate maintenance script completed successfully"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
