#!/bin/bash

# ============================================================================
# FINAL COMPREHENSIVE ARCH LINUX MAINTENANCE SCRIPT
# Enhanced with systemd-boot support and bootloader detection
# ============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
JOURNAL_RETENTION="2weeks"
PACMAN_CACHE_KEEP=3
LOG_FILE="/var/log/arch_maintenance.log"

# Function to print section headers
print_header() {
    echo -e "\n${BLUE}======================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}======================================${NC}\n"
}

# Function to print warnings
print_warning() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
}

# Function to print errors
print_error() {
    echo -e "${RED}❌ ERROR: $1${NC}"
}

# Function to print success
print_success() {
    echo -e "${GREEN}✅ SUCCESS: $1${NC}"
}

# Function to print info
print_info() {
    echo -e "${PURPLE}ℹ️  INFO: $1${NC}"
}

# Function to print tips
print_tip() {
    echo -e "${CYAN}💡 TIP: $1${NC}"
}

# Log function
log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some user-specific checks may not work properly."
    fi
}

# 1. PRE-UPDATE CHECKS (From Arch Wiki recommendations)
pre_update_checks() {
    print_header "1. PRE-UPDATE SAFETY CHECKS"
    
    print_info "Checking Arch Linux news..."
    if command -v curl &>/dev/null; then
        echo "Latest Arch News (check for breaking changes):"
        curl -s https://archlinux.org/news/ | grep -o '<h2>[^<]*</h2>' | head -5 | sed 's/<[^>]*>//g' || print_warning "Could not fetch Arch news"
        echo ""
        print_tip "Always check https://archlinux.org/news/ before major updates!"
    fi
    
    print_info "Checking available disk space..."
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 1048576 ]; then  # Less than 1GB
        print_warning "Low disk space available. Consider cleaning before update."
    else
        print_success "Sufficient disk space available"
    fi
    
    print_info "Checking if system is already partially updated..."
    if pacman -Qu &>/dev/null; then
        pending_updates=$(pacman -Qu | wc -l)
        print_info "$pending_updates package updates available"
    else
        print_success "No pending updates found"
    fi
    
    log_action "Pre-update checks completed"
}

# 2. ENHANCED FAILED SERVICES CHECK
check_failed_services() {
    print_header "2. COMPREHENSIVE FAILED SERVICES CHECK"
    
    # System services
    print_info "System-wide failed services:"
    failed_system=$(systemctl --failed --no-legend | wc -l)
    if [ $failed_system -eq 0 ]; then
        print_success "No failed system services"
    else
        print_error "$failed_system failed system services found:"
        systemctl --failed
        echo ""
        print_tip "Use 'systemctl status <service>' for detailed error info"
    fi
    
    # User services
    if [[ $EUID -ne 0 ]]; then
        print_info "User failed services:"
        failed_user=$(systemctl --user --failed --no-legend 2>/dev/null | wc -l)
        if [ $failed_user -eq 0 ]; then
            print_success "No failed user services"
        else
            print_error "$failed_user failed user services found:"
            systemctl --user --failed
        fi
    fi
    
    # Check timers
    print_info "Checking systemd timers:"
    systemctl list-timers --no-pager | head -10
    
    log_action "Failed services check completed"
}

# 3. ENHANCED LOG ANALYSIS
check_system_logs() {
    print_header "3. COMPREHENSIVE LOG ANALYSIS"
    
    # Boot errors
    print_info "Critical boot errors from current session:"
    critical_errors=$(journalctl -b -p crit --no-pager | wc -l)
    if [ $critical_errors -eq 0 ]; then
        print_success "No critical boot errors found"
    else
        print_error "$critical_errors critical errors found:"
        journalctl -b -p crit --no-pager | tail -10
    fi
    
    # Recent errors
    print_info "Recent error messages (last 24 hours):"
    recent_errors=$(journalctl --since "24 hours ago" -p err --no-pager | wc -l)
    if [ $recent_errors -eq 0 ]; then
        print_success "No recent errors found"
    else
        print_warning "$recent_errors error messages in last 24 hours:"
        journalctl --since "24 hours ago" -p err --no-pager | tail -10
    fi
    
    # Kernel messages
    print_info "Checking kernel ring buffer for errors:"
    kernel_errors=$(dmesg | grep -i "error\|failed\|critical" | wc -l)
    if [ $kernel_errors -eq 0 ]; then
        print_success "No kernel errors found"
    else
        print_warning "$kernel_errors kernel issues found:"
        dmesg | grep -i "error\|failed\|critical" | tail -10
    fi
    
    log_action "Log analysis completed"
}

# 4. BOOTLOADER DETECTION AND MANAGEMENT
bootloader_management() {
    print_header "4. BOOTLOADER DETECTION AND MANAGEMENT"
    
    # Detect current bootloader
    bootloader_found=""
    
    # Check for GRUB
    if [ -d "/boot/grub" ] || [ -f "/boot/grub/grub.cfg" ]; then
        bootloader_found="GRUB"
        print_success "GRUB bootloader detected"
        
        if [ -f "/boot/grub/grub.cfg" ]; then
            grub_date=$(stat -c %Y /boot/grub/grub.cfg)
            kernel_date=$(stat -c %Y /boot/vmlinuz-linux 2>/dev/null || echo "0")
            if [ $grub_date -lt $kernel_date ]; then
                print_warning "GRUB configuration may be outdated"
                print_tip "Update with: sudo grub-mkconfig -o /boot/grub/grub.cfg"
            else
                print_success "GRUB configuration appears up to date"
            fi
        else
            print_warning "GRUB directory exists but grub.cfg missing"
        fi
    fi
    
    # Check for rEFInd
    if [ -d "/boot/EFI/refind" ] || [ -f "/boot/refind_linux.conf" ]; then
        if [ -n "$bootloader_found" ]; then
            bootloader_found="$bootloader_found + rEFInd"
        else
            bootloader_found="rEFInd"
        fi
        print_success "rEFInd bootloader detected"
        
        if [ -f "/boot/EFI/refind/refind.conf" ]; then
            print_success "rEFInd configuration file exists"
        else
            print_warning "rEFInd directory exists but refind.conf missing"
        fi
    fi
    
    # Check for systemd-boot
    if [ -d "/boot/loader" ] || [ -f "/boot/loader/loader.conf" ]; then
        if [ -n "$bootloader_found" ]; then
            bootloader_found="$bootloader_found + systemd-boot"
        else
            bootloader_found="systemd-boot"
        fi
        print_success "systemd-boot detected"
        
        # Check systemd-boot configuration
        if [ -f "/boot/loader/loader.conf" ]; then
            print_success "systemd-boot loader.conf exists"
        else
            print_warning "systemd-boot directory exists but loader.conf missing"
        fi
        
        if [ -d "/boot/loader/entries" ]; then
            entry_count=$(ls /boot/loader/entries/*.conf 2>/dev/null | wc -l)
            if [ $entry_count -gt 0 ]; then
                print_success "$entry_count boot entries found"
            else
                print_warning "No boot entries found in /boot/loader/entries/"
            fi
        fi
    fi
    
    # If no bootloader found, recommend systemd-boot
    if [ -z "$bootloader_found" ]; then
        print_warning "No recognized bootloader found!"
        print_info "Checking if system supports systemd-boot..."
        
        # Check for UEFI system
        if [ -d "/sys/firmware/efi" ]; then
            print_success "UEFI system detected - systemd-boot is recommended"
            
            # Check for ESP
            esp_mount=$(findmnt -n -o TARGET -T /boot 2>/dev/null)
            if [ -n "$esp_mount" ]; then
                print_success "EFI System Partition appears to be mounted at $esp_mount"
            else
                print_warning "EFI System Partition may not be properly mounted"
            fi
            
            # Generate systemd-boot installation commands
            print_info "systemd-boot installation commands:"
            echo ""
            echo "# Install systemd-boot:"
            echo "sudo bootctl install"
            echo ""
            echo "# Or specify custom paths:"
            echo "sudo bootctl --esp-path=/boot --boot-path=/boot install"
            echo ""
            echo "# Create basic loader.conf:"
            echo "sudo mkdir -p /boot/loader"
            echo "cat << 'EOF' | sudo tee /boot/loader/loader.conf"
            echo "default arch.conf"
            echo "timeout 5"
            echo "console-mode max"
            echo "editor no"
            echo "EOF"
            echo ""
            echo "# Create Arch Linux boot entry:"
            echo "sudo mkdir -p /boot/loader/entries"
            echo "cat << 'EOF' | sudo tee /boot/loader/entries/arch.conf"
            echo "title Arch Linux"
            echo "linux /vmlinuz-linux"
            echo "initrd /initramfs-linux.img"
            echo "options root=PARTUUID=\$(blkid -s PARTUUID -o value /dev/disk/by-label/arch_os) rw"
            echo "EOF"
            echo ""
            echo "# Enable automatic updates:"
            echo "sudo systemctl enable systemd-boot-update.service"
            echo ""
            
        else
            print_warning "Legacy BIOS system detected - consider GRUB instead"
            print_tip "Install GRUB with: sudo pacman -S grub && sudo grub-install --target=i386-pc /dev/sdX"
        fi
    else
        print_success "Bootloader(s) found: $bootloader_found"
    fi
    
    # systemd-boot specific checks and maintenance
    if [[ "$bootloader_found" == *"systemd-boot"* ]]; then
        print_info "Performing systemd-boot maintenance checks..."
        
        # Check if systemd-boot update service is enabled
        if systemctl is-enabled systemd-boot-update.service &>/dev/null; then
            print_success "systemd-boot automatic updates are enabled"
        else
            print_warning "systemd-boot automatic updates are not enabled"
            print_tip "Enable with: sudo systemctl enable systemd-boot-update.service"
        fi
        
        # Check bootctl status
        if command -v bootctl &>/dev/null; then
            print_info "systemd-boot status:"
            bootctl status 2>/dev/null | head -10 || print_warning "Could not get bootctl status"
        fi
        
        # Check for boot entries
        if [ -d "/boot/loader/entries" ]; then
            print_info "Available boot entries:"
            ls -la /boot/loader/entries/
        fi
    fi
    
    log_action "Bootloader management completed"
}

# 5. ADVANCED SYSTEM MAINTENANCE (Enhanced from community best practices)
advanced_maintenance() {
    print_header "5. ADVANCED SYSTEM MAINTENANCE"
    
    # Check for updates
    print_info "Checking for system updates..."
    if command -v checkupdates &>/dev/null; then
        updates=$(checkupdates 2>/dev/null | wc -l)
        if [ $updates -eq 0 ]; then
            print_success "System is up to date"
        else
            print_warning "$updates package updates available"
            echo "Recent updates:"
            checkupdates 2>/dev/null | head -10
        fi
    else
        print_info "Installing pacman-contrib for better update checking..."
        echo "Run: sudo pacman -S pacman-contrib"
    fi
    
    # AUR packages check
    if command -v yay &>/dev/null || command -v paru &>/dev/null; then
        print_info "Checking AUR packages..."
        if command -v yay &>/dev/null; then
            aur_updates=$(yay -Qua 2>/dev/null | wc -l)
            print_info "$aur_updates AUR package updates available"
        elif command -v paru &>/dev/null; then
            aur_updates=$(paru -Qua 2>/dev/null | wc -l)
            print_info "$aur_updates AUR package updates available"
        fi
    else
        print_tip "Consider installing 'yay' or 'paru' for AUR package management"
    fi
    
    # Orphaned packages
    print_info "Checking for orphaned packages..."
    orphans=$(pacman -Qdtq 2>/dev/null | wc -l)
    if [ $orphans -eq 0 ]; then
        print_success "No orphaned packages found"
    else
        print_warning "$orphans orphaned packages found:"
        pacman -Qdtq 2>/dev/null | head -10
        if [ $orphans -gt 10 ]; then
            echo "... and $(($orphans - 10)) more"
        fi
        print_tip "Remove with: sudo pacman -Rns \$(pacman -Qdtq)"
    fi
    
    # Package cache analysis
    print_info "Analyzing package cache..."
    if [ -d "/var/cache/pacman/pkg" ]; then
        cache_size=$(du -sh /var/cache/pacman/pkg 2>/dev/null | cut -f1)
        cache_count=$(ls /var/cache/pacman/pkg/*.pkg.tar.* 2>/dev/null | wc -l)
        print_info "Package cache: $cache_size ($cache_count packages)"
        print_tip "Clean with: sudo paccache -r (keeps $PACMAN_CACHE_KEEP versions)"
        print_tip "Aggressive clean: sudo pacman -Sc"
    fi
    
    log_action "Advanced maintenance check completed"
}

# 6. DISK AND STORAGE HEALTH (New addition from search results)
check_disk_health() {
    print_header "6. DISK AND STORAGE HEALTH"
    
    # Disk usage
    print_info "Disk usage analysis:"
    df -h | grep -E '^/dev' | while read filesystem size used avail percent mount; do
        usage_percent=$(echo $percent | sed 's/%//')
        if [ $usage_percent -gt 90 ]; then
            print_error "Disk $mount is $percent full ($used/$size used)"
        elif [ $usage_percent -gt 80 ]; then
            print_warning "Disk $mount is $percent full ($used/$size used)"
        else
            print_success "Disk $mount: $percent full ($used/$size used)"
        fi
    done
    
    # Check for SMART support
    if command -v smartctl &>/dev/null; then
        print_info "SMART disk health available - checking main drive..."
        main_disk=$(lsblk -ndo NAME,TYPE | awk '$2=="disk" {print "/dev/"$1; exit}')
        if [ -n "$main_disk" ]; then
            smart_status=$(smartctl -H "$main_disk" 2>/dev/null | grep "SMART overall-health" | awk '{print $NF}')
            if [ "$smart_status" = "PASSED" ]; then
                print_success "Main disk SMART status: $smart_status"
            else
                print_warning "Main disk SMART status: $smart_status"
                print_tip "Run: sudo smartctl -a $main_disk for detailed info"
            fi
        fi
    else
        print_tip "Install smartmontools for disk health monitoring: sudo pacman -S smartmontools"
    fi
    
    # Check for filesystem errors
    print_info "Checking for filesystem errors in logs..."
    fs_errors=$(dmesg | grep -i "filesystem\|ext4\|btrfs\|xfs" | grep -i "error" | wc -l)
    if [ $fs_errors -eq 0 ]; then
        print_success "No filesystem errors detected"
    else
        print_warning "$fs_errors filesystem-related errors found in kernel log"
        print_tip "Consider running fsck on unmounted partitions"
    fi
    
    log_action "Disk health check completed"
}

# 7. CACHE AND TEMPORARY FILES CLEANUP
cleanup_system() {
    print_header "7. CACHE AND TEMPORARY FILES ANALYSIS"
    
    # User cache
    if [ -d "$HOME/.cache" ]; then
        user_cache_size=$(du -sh "$HOME/.cache" 2>/dev/null | cut -f1)
        print_info "User cache size: $user_cache_size"
        print_tip "Clean with: rm -rf ~/.cache/* (or selective cleanup)"
    fi
    
    # System logs
    print_info "System journal analysis..."
    if command -v journalctl &>/dev/null; then
        journal_size=$(journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[KMGT]B')
        if [ -n "$journal_size" ]; then
            print_info "Journal size: $journal_size"
            print_tip "Clean old logs: sudo journalctl --vacuum-time=$JOURNAL_RETENTION"
        fi
    fi
    
    # Thumbnail cache
    if [ -d "$HOME/.thumbnails" ]; then
        thumb_size=$(du -sh "$HOME/.thumbnails" 2>/dev/null | cut -f1)
        print_info "Thumbnail cache: $thumb_size"
        print_tip "Clean with: rm -rf ~/.thumbnails/*"
    fi
    
    # Temporary files
    temp_size=$(sudo du -sh /tmp 2>/dev/null | cut -f1)
    print_info "Temporary files (/tmp): $temp_size"
    
    log_action "Cache analysis completed"
}

# 8. SECURITY AND CONFIGURATION CHECKS
security_checks() {
    print_header "8. SECURITY AND CONFIGURATION CHECKS"
    
    # Boot permissions
    if [ -d "/boot" ]; then
        boot_perms=$(stat -c "%a" /boot)
        if [ "$boot_perms" = "755" ]; then
            print_warning "/boot has world-readable permissions ($boot_perms)"
            print_tip "Secure with: sudo chmod 700 /boot"
        else
            print_success "/boot permissions are secure ($boot_perms)"
        fi
    fi
    
    # SSH configuration
    if [ -f "/etc/ssh/sshd_config" ]; then
        print_info "SSH service status:"
        if systemctl is-active ssh &>/dev/null || systemctl is-active sshd &>/dev/null; then
            print_info "SSH is active"
            # Check for common security settings
            if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
                print_success "Root login disabled via SSH"
            else
                print_warning "Root login may be enabled via SSH"
            fi
        else
            print_info "SSH service is not active"
        fi
    fi
    
    # Check for available security updates
    print_info "Checking for security-related packages..."
    security_packages=("sudo" "ufw" "fail2ban" "rkhunter" "clamav")
    for pkg in "${security_packages[@]}"; do
        if pacman -Q "$pkg" &>/dev/null; then
            print_success "$pkg is installed"
        else
            print_info "$pkg is not installed (consider for security)"
        fi
    done
    
    log_action "Security checks completed"
}

# 9. KERNEL AND BOOT CONFIGURATION (Enhanced with systemd-boot)
kernel_checks() {
    print_header "9. KERNEL AND BOOT CONFIGURATION"
    
    # Current kernel
    current_kernel=$(uname -r)
    print_info "Current kernel: $current_kernel"
    
    # Available kernels
    print_info "Installed kernels:"
    pacman -Q | grep "^linux " | head -5
    
    # Check for LTS kernel
    if pacman -Q linux-lts &>/dev/null; then
        print_success "LTS kernel is installed (recommended for stability)"
    else
        print_tip "Consider installing LTS kernel: sudo pacman -S linux-lts"
    fi
    
    # Initramfs check
    if [ -f "/boot/initramfs-linux.img" ]; then
        initramfs_date=$(stat -c %Y /boot/initramfs-linux.img)
        kernel_date=$(stat -c %Y /boot/vmlinuz-linux)
        if [ $initramfs_date -lt $kernel_date ]; then
            print_warning "Initramfs may be outdated"
            print_tip "Regenerate with: sudo mkinitcpio -P"
        else
            print_success "Initramfs appears up to date"
        fi
    fi
    
    log_action "Kernel checks completed"
}

# 10. PERFORMANCE MONITORING
performance_monitoring() {
    print_header "10. PERFORMANCE MONITORING"
    
    # System load
    print_info "System load averages:"
    uptime
    
    # Memory usage
    print_info "Memory usage:"
    free -h
    
    # Top processes by CPU
    print_info "Top 5 CPU-consuming processes:"
    ps aux --sort=-%cpu | head -6
    
    # Top processes by memory
    print_info "Top 5 memory-consuming processes:"
    ps aux --sort=-%mem | head -6
    
    # Check for swap usage
    swap_usage=$(free | grep Swap | awk '{if($2>0) print ($3/$2)*100; else print 0}')
    if (( $(echo "$swap_usage > 50" | bc -l 2>/dev/null || echo 0) )); then
        print_warning "High swap usage: ${swap_usage}%"
    else
        print_success "Swap usage is normal: ${swap_usage}%"
    fi
    
    log_action "Performance monitoring completed"
}

# 11. COMPREHENSIVE MAINTENANCE COMMANDS (Enhanced with systemd-boot)
generate_maintenance_commands() {
    print_header "11. COMPREHENSIVE MAINTENANCE COMMANDS"
    
    echo "# ============================================================================"
    echo "# COMPLETE ARCH LINUX MAINTENANCE COMMANDS"
    echo "# Review each command before running - DO NOT run blindly!"
    echo "# ============================================================================"
    echo ""
    
    echo "# 1. PRE-UPDATE SAFETY CHECK"
    echo "curl -s https://archlinux.org/news/ | grep -o '<h2>[^<]*</h2>' | head -5"
    echo "echo 'Review Arch news above before proceeding!'"
    echo ""
    
    echo "# 2. SYSTEM UPDATE"
    echo "sudo pacman -Syu"
    echo ""
    
    echo "# 3. BOOTLOADER MAINTENANCE"
    echo "# For GRUB users:"
    echo "sudo grub-mkconfig -o /boot/grub/grub.cfg"
    echo ""
    echo "# For systemd-boot users:"
    echo "sudo bootctl update"
    echo "sudo systemctl enable systemd-boot-update.service"
    echo ""
    echo "# Install systemd-boot (if no bootloader detected):"
    echo "sudo bootctl install"
    echo "sudo mkdir -p /boot/loader/entries"
    echo "cat << 'EOF' | sudo tee /boot/loader/loader.conf"
    echo "default arch.conf"
    echo "timeout 5"
    echo "console-mode max"
    echo "editor no"
    echo "EOF"
    echo ""
    echo "# Create Arch Linux boot entry for systemd-boot:"
    echo "cat << 'EOF' | sudo tee /boot/loader/entries/arch.conf"
    echo "title Arch Linux"
    echo "linux /vmlinuz-linux"
    echo "initrd /initramfs-linux.img"
    echo "options root=PARTUUID=\$(blkid -s PARTUUID -o value \$(findmnt -n -o SOURCE /)) rw"
    echo "EOF"
    echo ""
    echo "# For rEFInd users:"
    echo "sudo refind-install  # Update rEFInd"
    echo ""
    
    echo "# 4. PACKAGE MAINTENANCE"
    echo "sudo paccache -r  # Clean package cache (keeps $PACMAN_CACHE_KEEP versions)"
    echo "sudo pacman -Rns \$(pacman -Qdtq)  # Remove orphaned packages"
    echo ""
    
    echo "# 5. AUR MAINTENANCE (if using AUR helper)"
    echo "yay -Sua  # or paru -Sua"
    echo ""
    
    echo "# 6. SYSTEM CLEANUP"
    echo "rm -rf ~/.cache/*  # Clean user cache"
    echo "sudo journalctl --vacuum-time=$JOURNAL_RETENTION  # Clean old logs"
    echo "rm -rf ~/.thumbnails/*  # Clean thumbnails"
    echo ""
    
    echo "# 7. SECURITY FIXES"
    echo "sudo chmod 700 /boot  # Secure boot directory"
    echo "sudo chmod 600 /boot/loader/random-seed 2>/dev/null || true"
    echo ""
    
    echo "# 8. KERNEL MAINTENANCE"
    echo "sudo mkinitcpio -P  # Regenerate initramfs"
    echo "sudo pacman -S linux-lts  # Install LTS kernel (optional)"
    echo ""
    
    echo "# 9. SYSTEM SERVICES"
    echo "systemctl --failed  # Check for failed services"
    echo "sudo systemctl restart bluetooth NetworkManager  # Restart common services"
    echo ""
    
    echo "# 10. DISK HEALTH"
    echo "sudo smartctl -H /dev/sda  # Check disk health (replace sda)"
    echo "sudo fsck -n /dev/sdaX  # Check filesystem (unmounted partition)"
    echo ""
    
    echo "# 11. INSTALL ESSENTIAL TOOLS"
    echo "sudo pacman -S --needed pacman-contrib smartmontools wireless-regdb"
    echo "sudo pacman -S --needed ufw fail2ban  # Security tools"
    echo ""
    
    echo "# 12. AUTOMATION SETUP"
    echo "# Create systemd-boot auto-update hook:"
    echo "sudo mkdir -p /etc/pacman.d/hooks"
    echo "cat << 'EOF' | sudo tee /etc/pacman.d/hooks/95-systemd-boot.hook"
    echo "[Trigger]"
    echo "Type = Package"
    echo "Operation = Upgrade"
    echo "Target = systemd"
    echo ""
    echo "[Action]"
    echo "Description = Gracefully upgrading systemd-boot..."
    echo "When = PostTransaction"
    echo "Exec = /usr/bin/bootctl update"
    echo "EOF"
    echo ""
    
    echo "# 13. EMERGENCY RECOVERY (from live USB)"
    echo "# Mount system:"
    echo "mount /dev/sdaX /mnt  # Replace X with root partition"
    echo "mount /dev/sdaY /mnt/boot  # Replace Y with boot/ESP partition"
    echo "arch-chroot /mnt"
    echo ""
    echo "# Reinstall bootloader:"
    echo "bootctl --path=/boot install  # For systemd-boot"
    echo "grub-install --target=x86_64-efi --efi-directory=/boot  # For GRUB"
    echo ""
    
    log_action "Comprehensive maintenance commands generated"
}

# MAIN EXECUTION
main() {
    print_header "FINAL COMPREHENSIVE ARCH LINUX MAINTENANCE SUITE"
    print_info "Enhanced with complete bootloader support including systemd-boot"
    print_info "Log file: $LOG_FILE"
    echo ""
    
    log_action "Maintenance script started"
    
    check_root
    pre_update_checks
    check_failed_services
    check_system_logs
    bootloader_management
    advanced_maintenance
    check_disk_health
    cleanup_system
    security_checks
    kernel_checks
    performance_monitoring
    generate_maintenance_commands
    
    print_header "FINAL MAINTENANCE ANALYSIS COMPLETE"
    print_success "Comprehensive system analysis with bootloader support finished!"
    print_tip "Review all warnings and apply suggested fixes as needed"
    print_tip "Save this output: ./script.sh > maintenance_report_\$(date +%Y%m%d).txt"
    print_tip "Schedule regular maintenance with systemd timer or crontab"
    print_info "This script now includes full systemd-boot detection and management!"
    
    log_action "Final maintenance script completed successfully"
}

# Run main function
main "$@"
