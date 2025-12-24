# Setup script for Microsoft eBPF on Windows
# Requires: Windows 11 or Windows Server 2022 or later

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "DDoS Mitigation System - Windows Setup" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check Windows version
$osVersion = [System.Environment]::OSVersion.Version
$buildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber

Write-Host "Windows Version: $osVersion (Build $buildNumber)"

if ($buildNumber -lt 22000) {
    Write-Host "ERROR: Microsoft eBPF requires Windows 11 (build 22000+) or Windows Server 2022+" -ForegroundColor Red
    Write-Host "Your build: $buildNumber" -ForegroundColor Red
    exit 1
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Install Chocolatey if not present
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey package manager..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Install build tools
Write-Host "Installing build tools..." -ForegroundColor Yellow
choco install -y llvm python3 git

# Clone and install Microsoft eBPF
$ebpfDir = "$env:TEMP\ebpf-for-windows"

if (Test-Path $ebpfDir) {
    Write-Host "Removing old eBPF directory..." -ForegroundColor Yellow
    Remove-Item -Path $ebpfDir -Recurse -Force
}

Write-Host "Cloning Microsoft eBPF for Windows..." -ForegroundColor Yellow
git clone --recursive https://github.com/microsoft/ebpf-for-windows.git $ebpfDir

Write-Host "Building Microsoft eBPF..." -ForegroundColor Yellow
Push-Location $ebpfDir

# Build eBPF
if (Test-Path ".\build.cmd") {
    .\build.cmd
    
    # Install drivers
    Write-Host "Installing eBPF drivers..." -ForegroundColor Yellow
    if (Test-Path ".\x64\Release\ebpf.msi") {
        Start-Process msiexec.exe -ArgumentList "/i x64\Release\ebpf.msi /quiet /norestart" -Wait -NoNewWindow
    } else {
        Write-Host "WARNING: Could not find ebpf.msi, you may need to build manually" -ForegroundColor Yellow
    }
} else {
    Write-Host "WARNING: Build script not found, please build Microsoft eBPF manually" -ForegroundColor Yellow
}

Pop-Location

# Install Python dependencies
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
python -m pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
Write-Host "Creating project directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "logs", "data", "src\ebpf", "simulation", "tests" | Out-Null

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Setup completed!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Reboot your system to load eBPF drivers" -ForegroundColor White
Write-Host "2. Compile eBPF programs: cd src\ebpf; clang -target bpf ..." -ForegroundColor White
Write-Host "3. Run the system: python main.py --interface 'Ethernet'" -ForegroundColor White
Write-Host ""
Write-Host "Note: Administrative privileges required to load eBPF programs" -ForegroundColor Yellow
