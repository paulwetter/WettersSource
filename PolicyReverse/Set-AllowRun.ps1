#Version 7

#These are registry settings that will be updated in the HKCU profiles on all profiles on the computer.
#If you need to add another, just copy one of the entire [PSCustomObject]@{....}
$UserRegistrySettings = @(
    [PSCustomObject]@{
        RegPath = '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        RegValue = 'NoRun'
        RegData = 0
    },
    [PSCustomObject]@{
        RegPath = '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        RegValue = 'NoPinningToTaskbar'
        RegData = 0
    },
    [PSCustomObject]@{
        RegPath = '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        RegValue = 'NoViewContextMenu'
        RegData = 0
    },
    [PSCustomObject]@{
        RegPath = '\Software\Microsoft\Windows\CurrentVersion\Policies\System'
        RegValue = 'DisableTaskMgr'
        RegData = 0
    }
)




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
 
    if ($null -ne $ErrorMessage) { $Type = 3 }
    if ($null -eq $Component) { $Component = " " }
    if ($null -eq $Type) { $Type = 1 }
 
    $LogMessage = "<![LOG[$Message $ErrorMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
}

function Get-ProcessOutput
{
    Param (
                [Parameter(Mandatory=$true)]
                [string]$FileName,
                [Parameter(Mandatory=$false)]
                [string]$Arguments
    )
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.FileName = $FileName
    if($Arguments) { $process.StartInfo.Arguments = $Arguments }
    $null = $process.Start()
    
    $StandardError = $process.StandardError.ReadToEnd()
    $StandardOutput = $process.StandardOutput.ReadToEnd()
    
    [PSCustomObject]@{
        StandardOutput = $StandardOutput
        StandardError  = $StandardError
    }
}

$PSDefaultParameterValues["Write-Log:LogFile"] = "C:\Windows\Logs\Software\Update-RunPolicy.log"
$PSDefaultParameterValues["Write-Log:Verbose"] = $false

$TempHive = 'TempUser'
Write-Log -Message "******************Beginning Run Policy Update******************"
Write-Log -Message "Checking Temp Hive is Empty..."
If (Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\SOFTWARE"){
    Write-Log -Message "Temp hive [HKEY_USERS\$TempHive] was not empty. attempting to unload..."
    $Output = Get-ProcessOutput -FileName 'REG.EXE' -Arguments "UNLOAD HKU\$TempHive"
    if ([string]::IsNullOrEmpty($Output.StandardError)){
        Write-Log -Message "Successfully Unloaded user hive out of [HKEY_USERS\$TempHive]"
    } else {
        Write-Log -Message "Failed to unload existing temp hive [HKEY_USERS\$TempHive].  Error [$($Output.StandardError)]. Searching for new temp hive..." -Type 2
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
        foreach ($UserSetting in $UserRegistrySettings) {
            $RegPath = "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)$($UserSetting.RegPath)"
            If (!(Test-Path -Path "$RegPath")){
                New-Item -Path "$RegPath" -Force -ErrorAction Ignore
            }
            If ((Get-ItemProperty -Path $RegPath -ErrorAction Ignore).$($UserSetting.RegValue) -ne $UserSetting.RegData) {
                Write-Log -Message "[$($UserSetting.RegValue)] value not set as expected [$RegPath]"
                Try{
                    Set-ItemProperty -Path $RegPath -Name "$($UserSetting.RegValue)" -Value $($UserSetting.RegData) -ErrorAction Stop
                    Write-Log -Message "Successfully set [$($UserSetting.RegValue)] value for [$RegPath]"
                }
                Catch{
                    Write-Log -Message "Failed to set [$($UserSetting.RegValue)] value for [$RegPath]" -Type 3
                    Write-Log -Message "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
                }
            } else {
                Write-Log -Message "Already set [$($UserSetting.RegValue)] value for [$RegPath]"
            }
        }
        $DeleteKey = "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($Profile.PSChildName)\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        Write-Log -Message "Checking for [$DeleteKey]" -Type 1
        if (Test-Path "$DeleteKey") {
            Try {
                Remove-Item "$DeleteKey" -Recurse -Force -ErrorAction Stop
                Write-Log -Message "Successfully removed [$DeleteKey]" -Type 1
            }
            Catch {
                Write-Log -Message "Failed to removed [$DeleteKey]" -Type 3
                Write-Log -Message "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
            }
        } else {
            Write-Log -Message "Registry key [$DeleteKey] not found on system." -Type 1
        }
    }
    else {
        $Output = Get-ProcessOutput -FileName 'REG.EXE' -Arguments "LOAD HKU\$TempHive `"$($Profile.ProfileImagePath)\NTUSER.DAT`""
        if ([string]::IsNullOrEmpty($Output.StandardError)){
            Write-Log "Loaded user hive for [$($Profile.PSChildName)] into [HKEY_USERS\$TempHive] successfully."

            foreach ($UserSetting in $UserRegistrySettings) {
                $RegPath = "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive$($UserSetting.RegPath)"
                If (!(Test-Path -Path "$RegPath")){
                    New-Item -Path "$RegPath" -Force -ErrorAction Ignore
                }
                If ((Get-ItemProperty -Path $RegPath -ErrorAction Ignore).$($UserSetting.RegValue) -ne $UserSetting.RegData) {
                    Write-Log -Message "[$($UserSetting.RegValue)] value not set as expected [$RegPath]"
                    Try{
                        Set-ItemProperty -Path $RegPath -Name "$($UserSetting.RegValue)" -Value $($UserSetting.RegData) -ErrorAction Stop
                        Write-Log -Message "Successfully set [$($UserSetting.RegValue)] value for [$RegPath]"
                    }
                    Catch{
                        Write-Log -Message "Failed to set [$($UserSetting.RegValue)] value for [$RegPath]" -Type 3
                        Write-Log -Message "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
                    }
                } else {
                    Write-Log -Message "Already set [$($UserSetting.RegValue)] value for [$RegPath]"
                }
            }
            $DeleteKey = "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\SOFTWARE\Policies\Microsoft\Windows\Explorer"
            Write-Log -Message "Checking for [$DeleteKey]" -Type 1
            if (Test-Path "$DeleteKey") {
                Try {
                    Remove-Item "$DeleteKey" -Recurse -Force -ErrorAction Stop
                    Write-Log -Message "Successfully removed [$DeleteKey]" -Type 1
                }
                Catch {
                    Write-Log -Message "Failed to removed [$DeleteKey]" -Type 3
                    Write-Log -Message "Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Type 3
                }
            } else {
                Write-Log -Message "Registry key [$DeleteKey] not found on system." -Type 1
            }
        }
        else {
            Write-Log "Failed to load Hive into temporary space. Error [$($Output.StandardError)]." -Type 3
        }
        for ($i = 0; $i -lt 10; $i++) {
            $Output = Get-ProcessOutput -FileName 'REG.EXE' -Arguments "UNLOAD HKU\$TempHive"
            if ([string]::IsNullOrEmpty($Output.StandardError)){
                Write-Log "Successfully Unloaded user hive for [$($Profile.PSChildName)] out of [HKEY_USERS\$TempHive]"
                break
            } else {
                Write-Log "Failed to Unloaded user hive for [$($Profile.PSChildName)] out of [HKEY_USERS\$TempHive].  Will wait a second and try again." -Type 3
                Start-Sleep -Seconds 1    
            }
        }
    }
}


If (Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$TempHive\Software"){
    Write-Log "Looks like there was still a Temp Registry hive loaded. Attempting to unload it.  No status will be displayed" -Type 2
    for ($i = 0; $i -lt 10; $i++) {
        $Output = Get-ProcessOutput -FileName 'REG.EXE' -Arguments "UNLOAD HKU\$TempHive"
        if ([string]::IsNullOrEmpty($Output.StandardError)){
            Write-Log "Successfully Unloaded user hive for [$($Profile.PSChildName)] out of [HKEY_USERS\$TempHive]"
            break
        } else {
            Write-Log "Failed to Unloaded user hive for [$($Profile.PSChildName)] out of [HKEY_USERS\$TempHive].  Will wait a second and try again." -Type 3
            Start-Sleep -Seconds 1    
        }
    }
}

Write-Log "******************Completed Run Policy Update******************"