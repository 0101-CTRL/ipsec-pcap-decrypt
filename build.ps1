param(
    [string]$WiresharkDir = "C:\Program Files\Wireshark"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "IPsec PCAP Decryptor - SINGLE EXE BUILD" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python is required on the BUILD machine only. End users do not need Python."
}

if (-not (Test-Path "$WiresharkDir\tshark.exe")) {
    throw "Wireshark/TShark was not found at '$WiresharkDir'. It is required on the BUILD machine only."
}

python -m pip install --upgrade pip
python -m pip install -r requirements-build.txt

Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue

Write-Host "Building one-file Windows executable..." -ForegroundColor Cyan

python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name "IPsecDecryptor" `
    --add-data "$WiresharkDir;wireshark" `
    main.py

if (-not (Test-Path ".\dist\IPsecDecryptor.exe")) {
    throw "Build completed without producing dist\IPsecDecryptor.exe"
}

Write-Host ""
Write-Host "SUCCESS" -ForegroundColor Green
Write-Host "Single-file application:" -ForegroundColor Green
Write-Host "  dist\IPsecDecryptor.exe"
Write-Host ""
Write-Host "Copy that EXE to a clean Windows PC to test it." -ForegroundColor Yellow
