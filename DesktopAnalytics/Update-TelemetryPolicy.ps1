function Write-Log {
    [CmdletBinding()] 
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
 
        [Parameter(Mandatory = $false)]
        $ErrorMessage,
 
        [Parameter(Mandatory = $false)]
        $Component,
 
        [Parameter(Mandatory = $false, HelpMessage = "1 = Normal, 2 = Warning (yellow), 3 = Error (red)")]
        [ValidateSet(1, 2, 3)]
        [int]$Type,
		
        [Parameter(Mandatory = $false, HelpMessage = "Size in KB")]
        [int]$LogSizeKB = 512,

        [Parameter(Mandatory = $true)]
        $LogFile
    )
    <#
    Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
    #>
    Write-Verbose -Message $Message
    If ($ErrorMessage) { Write-Verbose -Message $ErrorMessage }
    Try {
        IF (!(Test-Path ([System.IO.DirectoryInfo]$LogFile).Parent.FullName)) {
            New-Item -ItemType directory -Path ([System.IO.DirectoryInfo]$LogFile).Parent.FullName
        }
    }
    Catch {
        Throw 'Failed to find/set parent directory path'
    }
    $LogLength = $LogSizeKB * 1024
    try {
        $log = Get-Item $LogFile -ErrorAction Stop
        If (($log.length) -gt $LogLength) {
            $Time = Get-Date -Format "HH:mm:ss.ffffff"
            $Date = Get-Date -Format "MM-dd-yyyy"
            $LogMessage = "<![LOG[Closing log and generating new log file" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"1`" thread=`"`" file=`"`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
            Move-Item -Path "$LogFile" -Destination "$($LogFile.TrimEnd('g'))_" -Force
        }
    }
    catch { Write-Verbose "Nothing to move or move failed." }

    $Time = Get-Date -Format "HH:mm:ss.ffffff"
    $Date = Get-Date -Format "MM-dd-yyyy"
 
    if ($ErrorMessage -ne $null) { $Type = 3 }
    if ($Component -eq $null) { $Component = " " }
    if ($Type -eq $null) { $Type = 1 }
 
    $LogMessage = "<![LOG[$Message $ErrorMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
}

#$Items = get-item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection\Users\*'|where {$_.Property.AllowTelemetry -eq 3}

$PSDefaultParameterValues["Write-Log:LogFile"] = "C:\Windows\Logs\Software\Update-TelemetryPolicy.log"
$PSDefaultParameterValues["Write-Log:Verbose"] = $false


$TempHive = 'TempUser'
Write-Log "******************Beginning Telemetry User Blocking Evaluation******************"
Write-Log "Getting all users from registry that are blocking telemetry."
$BlockingUsers = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection\Users\*'
Write-Log "Getting all user profiles on this machine."
$MachineUserProfiles = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*'
Write-Log "Getting all user profile hives already loaded on this machine."
$LoadedHives = Get-ChildItem -Path 'Microsoft.PowerShell.Core\Registry::HKEY_USERS' | Where-Object { $_.PSChildName -notlike "*_classes" }
Write-Log "looping through all of the blocking users [$($BlockingUsers.count)]."
Foreach ($user in $BlockingUsers) {
    $UserSid = $User.PSChildName
    Write-Log "Processing user with following SID [$UserSid]."
    If ($User.AllowTelemetry -eq 0) {
        Write-Log "Searching Machine Profiles for user that matches the SID of the blocking user [$UserSid]."
        Foreach ($Profile in $MachineUserProfiles) {
            If ($Profile.PSChildName -eq $UserSid) {
                Write-Log "Found Machine Profile that matches the SID of the blocking user [$UserSid]."
                If ($Profile.PSChildName -in ($LoadedHives.PSChildName)) {
                    Write-Log "Profile matches that of one of the already loaded registry hive files.  No need to load a hive."
                    IF (!([string]::IsNullOrEmpty((Get-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\Software\Policies\Microsoft\Windows\DataCollection" -ErrorAction Ignore).AllowTelemetry))) {
                        Write-Log "AllowTelemetry Value found in [HKEY_USERS\$($Profile.PSChildName)\Software\Policies\Microsoft\Windows\DataCollection]"
                        try {
                            Remove-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\Software\Policies\Microsoft\Windows\DataCollection" -Name 'AllowTelemetry'
                            Write-Log "Successfully removed AllowTelemetry value from HKEY_USERS\$($Profile.PSChildName)\Software\Policies\Microsoft\Windows\DataCollection"
                        }
                        Catch {
                            Write-Log "Failed to remove AllowTelemetry value from HKEY_USERS\$($Profile.PSChildName)\Software\Policies\Microsoft\Windows\DataCollection" -Type 3
                            Write-Log "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
                        }
                    }
                    Else {
                        Write-Log "AllowTelemetry Value Not Found in [HKEY_USERS\$($Profile.PSChildName)\Software\Policies\Microsoft\Windows\DataCollection]" -Type 2
                    }
                }
                else {
                    REG.EXE LOAD HKU\$TempHive "$($Profile.ProfileImagePath)\NTUSER.DAT"
                    If (Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software\Policies\Microsoft\Windows") {
                        Write-Log "Loaded user hive for [$($Profile.PSChildName)] into [HKEY_USERS\$TempHive] successfully."
                        try {
                            Remove-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software\Policies\Microsoft\Windows\DataCollection" -Name 'AllowTelemetry'
                            Write-Log "Successfully removed AllowTelemetry value from HKEY_USERS\$TempHive\Software\Policies\Microsoft\Windows\DataCollection"
                        }
                        Catch {
                            Write-Log "failed to remove AllowTelemetry value from HKEY_USERS\$TempHive\Software\Policies\Microsoft\Windows\DataCollection" -Type 3
                            Write-Log "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
                        }
                    }
                    else {
                        Write-Log "Failed to load Hive into temporary space." -Type 3
                    }
                    REG.EXE UNLOAD HKU\$TempHive
                    If (!(Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software")) {
                        Write-Log "Successfully Unloaded user hive for [$($Profile.PSChildName)] out of [HKEY_USERS\$TempHive]"
                    }
                    else {
                        Write-Log "Failed to Unloaded user hive for [$($Profile.PSChildName)] out of [HKEY_USERS\$TempHive]" -Type 3
                    }
                }
            }
        }
    }
    Write-Log "Removing Telemetry collected blocking user [$($User.PSPath)]"
    try {
        Remove-Item -Path "$($User.PSPath)" -Force
        Write-Log "Successfully removed Telemetry Collected blocking user [$($User.PSPath)]"
    }
    Catch {
        Write-Log "Error removing Telemetry Collected blocking user [$($User.PSPath)]" -Type 3
        Write-Log "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
    }
    Write-Log "Completed processing user with following SID [$UserSid]."
}
Write-Log "******************Completed Telemetry User Blocking Evaluation******************"
