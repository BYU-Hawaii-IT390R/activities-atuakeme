# Builds answer.iso containing only Autounattend.xml
$iso = "answer.iso"
$xml = "Autounattend.xml"
$tempDir = "answerfiles"

# Create temp folder and copy Autounattend.xml into it
if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
New-Item -ItemType Directory -Path $tempDir | Out-Null
Copy-Item $xml "$tempDir\Autounattend.xml"

# Path to oscdimg.exe (adjust if needed)
$oscdimg = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"

# Build ISO from the temp directory
& $oscdimg -u2 -udfver102 -lANS -m $tempDir $iso

Write-Host "✅ Created $iso"
