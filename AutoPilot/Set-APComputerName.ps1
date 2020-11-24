#Rename Computer if domain available.
#Useful during the autopilot process.
[CmdletBinding()]
param (
    #This is the Prefix you want to append to your computer names.
    [String]$Prefix = 'BOB'
)

$PSDefaultParameterValues["Write-Log:LogFile"] = "$env:Windir\Temp\Set-APComputerName.log"
$PSDefaultParameterValues["Write-Log:Verbose"] = $false

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
    Try{
        IF (!(Test-Path ([System.IO.DirectoryInfo]$LogFile).Parent.FullName)){
            New-Item -ItemType directory -Path ([System.IO.DirectoryInfo]$LogFile).Parent.FullName
        }
    }
    Catch{
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
    catch {Write-Verbose "Nothing to move or move failed."}

    $Time = Get-Date -Format "HH:mm:ss.ffffff"
    $Date = Get-Date -Format "MM-dd-yyyy"
 
    if ($null -ne $ErrorMessage) {$Type = 3}
    if ($null -eq $Component) {$Component = " "}
    if ($null -eq $Type) {$Type = 1}
 
    $LogMessage = "<![LOG[$Message $ErrorMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
}



#Checks if domain is available
Try{
    [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()>$Null
    $DomainAvailable=$true
}
Catch {
    $DomainAvailable=$False
}
If ($DomainAvailable -eq $False){
    Write-Log "Domain not available. Exiting script.."
    Exit
}

#Check if computer exists Returns True/False
function Test-ComputerExists{
    [CmdletBinding()]
    param (
        [String]
        $ComputerName
    )
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.SearchRoot = $objDomain
    $objSearcher.Filter = "(&(objectClass=Computer)(name=$ComputerName))"
    $colResults = $objSearcher.FindAll()
    ![string]::IsNullOrEmpty($colResults)
}


#Getting Chassis type for appending to name (if used).
#$CTs=(Get-CimInstance -ClassName Win32_SystemEnclosure).ChassisTypes
#$DesktopChassisTypes = @("3","4","5","6","7","15","16","35","36")
#$LatopChassisTypes = @("8","9","10","11","12","14","18","21","30","31","32")
#$ServerChassisTypes = @("23","28")
#foreach ($CT in $CTs) {
#    If ($CT -in $LatopChassisTypes){$CompType = "L"}
#    If ($CT -in $DesktopChassisTypes){$CompType = "D"}
#}

$SN = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
# Remove any special characters (\/:*?"<>|) that could cause issues in a computer name (plus - because of HyperV). https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/naming-conventions-for-computer-domain-site-ou
$SN = $SN -replace '[\\/\:\*\?\"\<\>\|\- ]', ''
# if we found a serial number, let try to rename the computer.
If ([string]::IsNullOrEmpty($Prefix)){
    $NewCompName = $SN
}
else {
    $NewCompName = $Prefix + $SN
}

if ($NewCompName.Length -gt 15){
    $NewCompName = $NewCompName.Substring(0,15)
}

#Checks if it already is named what you want it to be named.
If ($NewCompName -eq $env:COMPUTERNAME){
    Write-Log "Already named what you want. Exiting Script.."
    Exit
}

$NewComputerExists = Test-ComputerExists -ComputerName $NewCompName
$Inc = 0
Write-Log "Computer [$NewCompName] Exists in AD: $NewComputerExists"
while ($NewComputerExists){
    Write-Log -Message "Computer [$NewCompName] Exists in AD (incrementing name and trying again)" -Type 2
    $Inc++
    if ($Inc -gt 9) {
        Write-Log -Message "Tried 9 interations of the computer name and they all existed." -type 3
        exit 9
    }
    If ($NewCompName.Length -gt 13){
        $NewCompName = $NewCompName.Substring(0,13)
    }
    $IncName = "$NewCompName-$Inc"
    $NewComputerExists = Test-ComputerExists -ComputerName $IncName
    Write-Log -Message "Computer [$IncName] Exists in AD: [$NewComputerExists]"
    if (!$NewComputerExists){
        Write-Log -Message "Arrived at available incremented Computer [$IncName]. Resetting variable."
        $NewCompName = $IncName
    }
}

# Now that we know we have a computer name that is ok, let's try to rename it.
# if it fails to rename it, exit with a general error code of 7.
try {
    Rename-Computer -NewName $NewCompName -ErrorAction Stop
    Write-Log -Message "Computer rename to [$NewCompName] Complete."
}
catch {
    Write-Log -Message "Computer rename to [$NewCompName] failed." -Type 3
    exit 7
}
