#!/bin/bash
# Setup script for eBPF/XDP dependencies on Linux

set -e

echo "=========================================="
echo "DDoS Mitigation System - Linux Setup"
echo "=========================================="

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect Linux distribution"
    exit 1
fi

echo "Detected OS: $OS"

# Install dependencies based on distribution
case $OS in
    ubuntu|debian)
        echo "Installing dependencies for Ubuntu/Debian..."
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            clang \
            llvm \
            libelf-dev \
            linux-headers-$(uname -r) \
            python3-pip \
            python3-dev \
            libbpf-dev \
            bpfcc-tools \
            python3-bpfcc
        ;;
    
    rhel|centos|fedora)
        echo "Installing dependencies for RHEL/CentOS/Fedora..."
        sudo yum install -y \
            gcc \
            clang \
            llvm \
            elfutils-libelf-devel \
            kernel-devel-$(uname -r) \
            python3-pip \
            python3-devel \
            bcc-tools \
            python3-bcc
        ;;
    
    arch)
        echo "Installing dependencies for Arch Linux..."
        sudo pacman -Syu --noconfirm \
            base-devel \
            clang \
            llvm \
            libelf \
            linux-headers \
            python-pip \
            bpf \
            bcc \
            python-bcc
        ;;
    
    *)
        echo "Unsupported distribution: $OS"
        echo "Please manually install: clang, llvm, libelf-dev, kernel-headers, BCC"
        exit 1
        ;;
esac

# Verify kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
REQUIRED_VERSION="4.18"

echo "Kernel version: $KERNEL_VERSION"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$KERNEL_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "WARNING: Kernel version $KERNEL_VERSION may not fully support XDP"
    echo "Recommended: Linux kernel 4.18 or higher"
fi

# Check for XDP support
if [ -d /sys/kernel/debug/bpf ]; then
    echo "✓ BPF filesystem mounted"
else
    echo "Mounting BPF filesystem..."
    sudo mount -t debugfs none /sys/kernel/debug || true
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install --user -r requirements.txt

# Create necessary directories
mkdir -p logs data src/ebpf simulation tests

echo ""
echo "=========================================="
echo "Setup completed successfully!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Compile eBPF programs: cd src/ebpf && make"
echo "2. Run the system: sudo python3 main.py --interface <your-interface>"
echo ""
echo "Note: You need root/sudo privileges to load XDP programs"
