# build-vbox.ps1 – Automate VM creation and Windows installation using VirtualBox

$vmName = "AutomatedWin10"
$basePath = "C:\ISO Folder"

# Create VM
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name $vmName --register
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm $vmName --memory 4096 --cpus 2 --ostype "Windows10_64"

# Create and attach virtual disk
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createmedium disk --filename "$basePath\$vmName.vdi" --size 40000
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl $vmName --name "SATA Controller" --add sata --controller IntelAhci
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$basePath\$vmName.vdi"

# Attach ISO files (Windows and Answer)
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl $vmName --name "IDE Controller" --add ide
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium "$basePath\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium "$basePath\answer.iso"

# Start VM
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm $vmName
