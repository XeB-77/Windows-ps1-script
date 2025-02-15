# ASCII Art Header
Write-Host """
    ██╗  ██╗███████╗██████╗       ██╗  ██╗██╗  ██╗
    ╚██╗██╔╝██╔════╝██╔══██╗      ██║  ██║██║  ██║
     ╚███╔╝ █████╗  ██████╔╝█████╗███████║███████║
     ██╔██╗ ██╔══╝  ██╔══██╗╚════╝╚════██║╚════██║
    ██╔╝ ██╗███████╗██████╔╝           ██║     ██║
    ╚═╝  ╚═╝╚══════╝╚═════╝            ╚═╝     ╚═╝
    Windows PowerShell Toolkit --> XEB-44
""" -ForegroundColor Cyan

# Automatically Relaunch as Administrator if Needed
function Ensure-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Restarting script with administrator privileges..." -ForegroundColor Yellow
        Start-Process powershell -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}
Ensure-Admin

# Navigate to Script Directory Automatically
Set-Location -Path $PSScriptRoot

# Check and Set Execution Policy
Set-ExecutionPolicy Bypass -Scope Process -Force

# Ensure Required Modules and Tools are Installed
function Install-RequiredTools {
    $tools = @(
        "Nmap", "Wireshark", "Sysinternals Suite", "7zip", "Netcat", 
        "Chocolatey", "Postman", "Visual Studio Code", "Notepad++", 
        "Docker", "Vagrant", "Terraform", "Azure CLI", "AWS CLI", 
        "Slack", "Git", "curl", "jq", "Kubernetes CLI", "Terraform",
        "Microsoft Edge", "Zoom", "Microsoft Teams", "Skype"
    )
    foreach ($tool in $tools) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            Write-Host "Installing $tool..." -ForegroundColor Cyan
            winget install --id $tool -e --silent
        }
    }
    Write-Host "All required tools are installed."
}
Install-RequiredTools

# Command Categories with Definitions and Examples
$commands = @{
    "Security & User Management" = @( 
        @{Name="List Users"; Command="Get-LocalUser"; Description="Shows all local users."; Example="Get-LocalUser"},
        @{Name="Enable User"; Command="Enable-LocalUser -Name 'User1'"; Description="Enables a user account."; Example="Enable-LocalUser -Name 'JohnDoe'"},
        @{Name="Check Account Lockouts"; Command="Search-ADAccount -LockedOut"; Description="Lists locked out AD accounts."; Example="Search-ADAccount -LockedOut"},
        @{Name="Reset User Password"; Command="Set-LocalUser -Name 'User1' -Password (ConvertTo-SecureString 'NewPass' -AsPlainText -Force)"; Description="Resets a local user password."; Example="Set-LocalUser -Name 'JohnDoe' -Password (ConvertTo-SecureString 'NewPass' -AsPlainText -Force)"},
        @{Name="Create User"; Command="New-LocalUser -Name 'NewUser' -Password (ConvertTo-SecureString 'Password123' -AsPlainText -Force)"; Description="Creates a new local user."; Example="New-LocalUser -Name 'NewUser' -Password (ConvertTo-SecureString 'Password123' -AsPlainText -Force)"},
        @{Name="Add User to Group"; Command="Add-LocalGroupMember -Group 'Administrators' -Member 'NewUser'"; Description="Adds a user to a local group."; Example="Add-LocalGroupMember -Group 'Administrators' -Member 'NewUser'"},
        @{Name="Remove User"; Command="Remove-LocalUser -Name 'User1'"; Description="Removes a local user."; Example="Remove-LocalUser -Name 'User1'"},
        @{Name="List Groups"; Command="Get-LocalGroup"; Description="Shows all local groups."; Example="Get-LocalGroup"}
    );
    "File & Folder Management" = @( 
        @{Name="List Files"; Command="Get-ChildItem"; Description="Lists files in a directory."; Example="Get-ChildItem -Path C:\Windows"},
        @{Name="Delete File"; Command="Remove-Item -Path C:\temp\file.txt"; Description="Deletes a specific file."; Example="Remove-Item -Path C:\temp\file.txt"},
        @{Name="Find Large Files"; Command="Get-ChildItem -Path C:\ -Recurse | Sort-Object Length -Descending | Select-Object -First 10"; Description="Lists the largest 10 files."; Example="Get-ChildItem -Path C:\ -Recurse | Sort-Object Length -Descending | Select-Object -First 10"},
        @{Name="Copy File"; Command="Copy-Item -Path C:\temp\file.txt -Destination C:\backup\"; Description="Copies a file to a new location."; Example="Copy-Item -Path C:\temp\file.txt -Destination C:\backup\""},
        @{Name="Move File"; Command="Move-Item -Path C:\temp\file.txt -Destination C:\backup\"; Description="Moves a file to a new location."; Example="Move-Item -Path C:\temp\file.txt -Destination C:\backup\""},
        @{Name="Create Directory"; Command="New-Item -Path 'C:\NewFolder' -ItemType Directory"; Description="Creates a new folder."; Example="New-Item -Path 'C:\NewFolder' -ItemType Directory"},
        @{Name="Delete Directory"; Command="Remove-Item -Path 'C:\OldFolder' -Recurse"; Description="Deletes a directory and its contents."; Example="Remove-Item -Path 'C:\OldFolder' -Recurse"},
        @{Name="Get File Content"; Command="Get-Content -Path 'C:\temp\file.txt'"; Description="Reads the content of a file."; Example="Get-Content -Path 'C:\temp\file.txt'"}
    );
    "Firewall & Network Tools" = @( 
        @{Name="Check Firewall Status"; Command="Get-NetFirewallProfile"; Description="Displays firewall profiles."; Example="Get-NetFirewallProfile"},
        @{Name="Enable Firewall"; Command="Set-NetFirewallProfile -Enabled True"; Description="Enables the Windows Firewall."; Example="Set-NetFirewallProfile -Enabled True"},
        @{Name="Test Network Connectivity"; Command="Test-NetConnection -ComputerName google.com"; Description="Tests network connection to a remote host."; Example="Test-NetConnection -ComputerName 8.8.8.8"},
        @{Name="List Active Connections"; Command="netstat -ano"; Description="Displays active network connections and ports."; Example="netstat -ano"},
        @{Name="Scan Network"; Command="nmap -sP 192.168.1.0/24"; Description="Scan the local network for devices."; Example="nmap -sP 192.168.1.0/24"},
        @{Name="Get IP Configuration"; Command="Get-NetIPAddress"; Description="Displays IP address configuration."; Example="Get-NetIPAddress"},
        @{Name="Ping Host"; Command="Test-Connection -ComputerName google.com"; Description="Pings a host to check connectivity."; Example="Test-Connection -ComputerName google.com"},
        @{Name="Get DNS Client Cache"; Command="Get-DnsClientCache"; Description="Displays the DNS client cache."; Example="Get-DnsClientCache"}
    );
    "System Information" = @( 
        @{Name="Get System Info"; Command="Get-ComputerInfo"; Description="Displays detailed system information."; Example="Get-ComputerInfo"},
        @{Name="List Installed Software"; Command="Get-WmiObject -Class Win32_Product"; Description="Lists installed software on the system."; Example="Get-WmiObject -Class Win32_Product"},
        @{Name="Show Disk Usage"; Command="Get-PSDrive -PSProvider FileSystem"; Description="Displays disk usage statistics."; Example="Get-PSDrive -PSProvider FileSystem"},
        @{Name="Get CPU Info"; Command="Get-WmiObject -Class Win32_Processor"; Description="Shows CPU details."; Example="Get-WmiObject -Class Win32_Processor"},
        @{Name="Get RAM Info"; Command="Get-WmiObject -Class Win32_PhysicalMemory"; Description="Displays RAM details."; Example="Get-WmiObject -Class Win32_PhysicalMemory"},
        @{Name="Get OS Version"; Command="Get-CimInstance Win32_OperatingSystem"; Description="Displays OS version and details."; Example="Get-CimInstance Win32_OperatingSystem"},
        @{Name="Get System Uptime"; Command="Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime"; Description="Shows system uptime."; Example="Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime"},
        @{Name="List Services"; Command="Get-Service"; Description="Displays all services on the system."; Example="Get-Service"}
    );
    "Process Management" = @( 
        @{Name="List Running Processes"; Command="Get-Process"; Description="Displays all running processes."; Example="Get-Process"},
        @{Name="Kill Process"; Command="Stop-Process -Name 'notepad'"; Description="Ends a running process by name."; Example="Stop-Process -Name 'notepad'"},
        @{Name="Start Process"; Command="Start-Process 'notepad.exe'"; Description="Starts a new process."; Example="Start-Process 'notepad.exe'"},
        @{Name="Get Process by ID"; Command="Get-Process -Id 1234"; Description="Displays a process by its ID."; Example="Get-Process -Id 1234"},
        @{Name="Get Process Memory Usage"; Command="Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10"; Description="Displays top 10 memory consuming processes."; Example="Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10"},
        @{Name="Get Process Details"; Command="Get-Process | Format-Table -Property Id, ProcessName, CPU, WS"; Description="Displays detailed process information."; Example="Get-Process | Format-Table -Property Id, ProcessName, CPU, WS"}
    );
    "Disk & Filesystem Management" = @( 
        @{Name="List Disk Drives"; Command="Get-Disk"; Description="Displays all disk drives."; Example="Get-Disk"},
        @{Name="Get Disk Partitions"; Command="Get-Partition"; Description="Lists partitions on all disks."; Example="Get-Partition"},
        @{Name="Format Disk"; Command="Get-Disk | Where-Object PartitionCount -eq 0 | Format-Disk -FileSystem NTFS -NewFileSystemLabel 'NewVolume'"; Description="Formats a disk."; Example="Get-Disk | Where-Object PartitionCount -eq 0 | Format-Disk -FileSystem NTFS -NewFileSystemLabel 'NewVolume'"},
        @{Name="Check Disk Status"; Command="Get-PhysicalDisk"; Description="Displays status of physical disks."; Example="Get-PhysicalDisk"},
        @{Name="Check Disk Space"; Command="Get-PSDrive -PSProvider FileSystem | Select-Object @{Name='Drive'; Expression={$_.Name}}, @{Name='Used'; Expression={$_.Used}}, @{Name='Free'; Expression={$_.Free}}"; Description="Shows used and free disk space."; Example="Get-PSDrive -PSProvider FileSystem | Select-Object Drive, Used, Free"}
    );
    "Backup & Restore" = @( 
        @{Name="Backup Files"; Command="Copy-Item -Path C:\Data\* -Destination D:\Backup\"; Description="Creates a backup copy of files."; Example="Copy-Item -Path C:\Data\* -Destination D:\Backup\""},
        @{Name="Restore Files"; Command="Copy-Item -Path D:\Backup\* -Destination C:\Data\"; Description="Restores files from backup."; Example="Copy-Item -Path D:\Backup\* -Destination C:\Data\""},
        @{Name="Create System Restore Point"; Command="Checkpoint-Computer -Description 'Before Updates' -RestorePointType 'MODIFY_SETTINGS'"; Description="Creates a system restore point."; Example="Checkpoint-Computer -Description 'Before Updates' -RestorePointType 'MODIFY_SETTINGS'"},
        @{Name="Get Restore Points"; Command="Get-ComputerRestorePoint"; Description="Lists available restore points."; Example="Get-ComputerRestorePoint"}
    );
    "Remote Access" = @( 
        @{Name="Remote Desktop"; Command="mstsc"; Description="Starts Remote Desktop Connection."; Example="mstsc"},
        @{Name="Connect via SSH"; Command="ssh user@hostname"; Description="Uses SSH to connect to a remote host."; Example="ssh user@hostname"},
        @{Name="Copy Files Securely"; Command="scp file.txt user@hostname:C:\path\"; Description="Securely copies files over SSH."; Example="scp file.txt user@hostname:C:\path\""},
        @{Name="Use SFTP"; Command="sftp user@hostname"; Description="Uses SFTP to connect to a remote host."; Example="sftp user@hostname"}
    );
    "Miscellaneous Utilities" = @( 
        @{Name="Get Current Date/Time"; Command="Get-Date"; Description="Displays current date and time."; Example="Get-Date"},
        @{Name="Clear Console"; Command="Clear-Host"; Description="Clears the PowerShell console."; Example="Clear-Host"},
        @{Name="Show Environment Variables"; Command="Get-ChildItem Env:"; Description="Displays all environment variables."; Example="Get-ChildItem Env:"},
        @{Name="Convert to JSON"; Command="ConvertTo-Json -InputObject @{Name='Test'; Value='Hello'}"; Description="Converts an object to JSON."; Example="ConvertTo-Json -InputObject @{Name='Test'; Value='Hello'}"},
        @{Name="Show PowerShell Version"; Command="$PSVersionTable.PSVersion"; Description="Displays the installed PowerShell version."; Example="$PSVersionTable.PSVersion"},
        @{Name="Get System Uptime"; Command="Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime"; Description="Shows the last boot time."; Example="Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime"}
    );
}

# Function to Display Commands in a Readable Format
function Show-CommandList {
    Write-Host "Available Commands and Categories:" -ForegroundColor Green
    foreach ($category in $commands.Keys) {
        Write-Host "➡️  $category" -ForegroundColor Cyan
        foreach ($cmd in $commands[$category]) {
            Write-Host "    ➜ $($cmd.Name): $($cmd.Description)"
            Write-Host "      🔹 Command: $($cmd.Command)"
            Write-Host "      🔹 Example: $($cmd.Example)"
        }
    }
}

# GUI Enhancements
Add-Type -AssemblyName System.Windows.Forms
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Windows PowerShell Toolkit - XEB-77"
$Form.Size = New-Object System.Drawing.Size(700,800)
$Form.StartPosition = "CenterScreen"

# Search Bar
$SearchBox = New-Object System.Windows.Forms.TextBox
$SearchBox.Size = New-Object System.Drawing.Size(550,20)
$SearchBox.Location = New-Object System.Drawing.Point(20,50)
$SearchBox.PlaceholderText = "Search Commands..."
$Form.Controls.Add($SearchBox)

# ListBox with Categories
$ListBox = New-Object System.Windows.Forms.ListBox
$ListBox.Size = New-Object System.Drawing.Size(550,400)
$ListBox.Location = New-Object System.Drawing.Point(20,80)
$ListBox.Items.AddRange($commands.Keys)
$Form.Controls.Add($ListBox)

# Run Button
$RunButton = New-Object System.Windows.Forms.Button
$RunButton.Text = "Run Selected"
$RunButton.Location = New-Object System.Drawing.Point(200,650)
$RunButton.Add_Click({ Run-SelectedFunction $ListBox.SelectedItem })
$Form.Controls.Add($RunButton)

# Function to Run Selected Option
function Run-SelectedFunction {
    param ($Selection)
    if ($commands.ContainsKey($Selection)) {
        Write-Host "Executing: $Selection" -ForegroundColor Green
        foreach ($cmd in $commands[$Selection]) {
            Write-Host "➡️ Running: $($cmd.Name) - $($cmd.Description)" -ForegroundColor Yellow
            Invoke-Expression $cmd.Command
        }
    }
}

$Form.ShowDialog()
