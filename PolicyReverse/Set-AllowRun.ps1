#Version 5
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

$PSDefaultParameterValues["Write-Log:LogFile"] = "C:\Windows\Logs\Software\Update-RunPolicy.log"
$PSDefaultParameterValues["Write-Log:Verbose"] = $false

$TempHive = 'TempUser'
Write-Log -Message "******************Beginning Run Policy Update******************"
Write-Log -Message "Checking Temp Hive is Empty..."
If (Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\SOFTWARE"){
    Write-Log -Message "Temp hive [HKEY_USERS\$TempHive] was not empty. attempting to unload..."
    REG.EXE UNLOAD HKU\$TempHive
    If (!(Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software")) {
        Write-Log -Message "Successfully Unloaded user hive out of [HKEY_USERS\$TempHive]"
    } else {
        Write-Log -Message "Failed to unload existing temp hive [HKEY_USERS\$TempHive]. Searching for new temp hive..." -Type 2
        for ($i = 1; $i -lt 10; $i++){
            $NewTemp = "{0}{1}" -f $TempHive,$i
            If (!(Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$NewTemp\SOFTWARE")){
                $TempHive = $NewTemp
                Write-Log -Message "Successfully found new avialable temp hive for loading at [HKEY_USERS\$TempHive].  Continuing script..."
                Break
            }
        }    
    }
}
Write-Log -Message "Getting all user profiles on this machine."
$MachineUserProfiles = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*'
$RealUserProfiles = $MachineUserProfiles.Where({$_.PSChildName -notin @('S-1-5-18','S-1-5-19','S-1-5-20')})
Write-Log -Message "Getting all user profile hives already loaded on this machine."
$LoadedHives = Get-ChildItem -Path 'Microsoft.PowerShell.Core\Registry::HKEY_USERS' | Where-Object { $_.PSChildName -notlike "*_classes" }
Write-Log -Message "looping through all of the profile users [$($RealUserProfiles.count)]."
Foreach ($Profile in $RealUserProfiles) {
    Write-Log -Message "Updating run policy for user [$($Profile.PSChildName)]."
    If ($Profile.PSChildName -in ($LoadedHives.PSChildName)) {
        Write-Log "Profile matches that of one of the already loaded registry hive files.  No need to load a hive."
        If (((Get-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Ignore).NoRun -ne 0) -or ((Get-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Ignore).NoPinningToTaskbar -ne 0 )) {
            Write-Log -Message "NoRun Value not set as expected [HKEY_USERS\$($Profile.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]"
            If (!(Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")){
                New-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Ignore
            }
            try {
                Set-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoRun' -Value 0 -ErrorAction Stop
                Set-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoPinningToTaskbar' -Value 0 -ErrorAction Stop
                Write-Log -Message "Successfully set NoRun value for [HKEY_USERS\$($Profile.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]"
            }
            Catch {
                Write-Log -Message "Failed to set NoRun value for [HKEY_USERS\$($Profile.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]" -Type 3
                Write-Log -Message "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
            }
        }
        Else {
            Write-Log -Message "NoRun and NoPinningToTaskbar Values Already set to [0]" -Type 1
        }
        Write-Log -Message "Checking for [HKEY_USERS\$($Profile.PSChildName)\SOFTWARE\Policies\Microsoft\Windows\Explorer]" -Type 1
        if (Test-Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\SOFTWARE\Policies\Microsoft\Windows\Explorer") {
            Try {
                Remove-Item "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Recurse -Force -ErrorAction Stop
                Write-Log -Message "Successfully removed [Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\SOFTWARE\Policies\Microsoft\Windows\Explorer]" -Type 1
            }
            Catch {
                Write-Log -Message "Failed to removed [Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\SOFTWARE\Policies\Microsoft\Windows\Explorer]" -Type 3
                Write-Log -Message "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
            }
        } else {
            Write-Log -Message "Registry key [HKEY_USERS\$($Profile.PSChildName)\SOFTWARE\Policies\Microsoft\Windows\Explorer] not found on system." -Type 1
        }
    }
    else {
        REG.EXE LOAD HKU\$TempHive "$($Profile.ProfileImagePath)\NTUSER.DAT"
        If (Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software\Microsoft\Windows\CurrentVersion\Policies") {
            Write-Log "Loaded user hive for [$($Profile.PSChildName)] into [HKEY_USERS\$TempHive] successfully."
            If (!(Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")){
                New-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction Ignore
            }
            try {
                Set-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoRun' -Value 0 -ErrorAction Stop
                Set-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoPinningToTaskbar' -Value 0 -ErrorAction Stop
                Write-Log "Successfully set NoRun value for [HKEY_USERS\$TempHive\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]"
            }
            Catch {
                Write-Log "failed to set NoRun value for [HKEY_USERS\$TempHive\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]" -Type 3
                Write-Log "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
            }
            Write-Log -Message "Checking for [HKEY_USERS\$TempHive\SOFTWARE\Policies\Microsoft\Windows\Explorer]" -Type 1
            if (Test-Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\SOFTWARE\Policies\Microsoft\Windows\Explorer") {
                Try {
                    Remove-Item "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Recurse -Force -ErrorAction Stop
                    Write-Log -Message "Successfully removed [Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\SOFTWARE\Policies\Microsoft\Windows\Explorer]" -Type 1
                }
                Catch {
                    Write-Log -Message "Failed to removed [Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\SOFTWARE\Policies\Microsoft\Windows\Explorer]" -Type 3
                    Write-Log -Message "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
                }
            } else {
                Write-Log -Message "Registry key [HKEY_USERS\$TempHive\SOFTWARE\Policies\Microsoft\Windows\Explorer] not found on system." -Type 1
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
If (Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software"){
    Write-Log "Looks like there was still a Temp Registry hive loaded. Attempting to unload it.  No status will be displayed" -Type 2
    REG.EXE UNLOAD HKU\$TempHive
}

Write-Log "******************Completed Run Policy Update******************"