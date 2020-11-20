#Rename Computer if domain available.
#Useful during the autopilot process.
[CmdletBinding()]
param (
    [String]$Prefix = 'BOB'
)
#Checks if domain is available
Try{
    [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()>$Null
    $DomainAvailable=$true
}
Catch {
    $DomainAvailable=$False
}
If ($DomainAvailable -eq $False){
    Write-Verbose "Domain not available. Exiting script.."
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
$SN = $SN -replace '[\\/\:\*\?\"\<\>\|\-]', ''
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
    Write-Verbose "Already named what you want. Exiting Script.."
    Exit
}

$NewComputerExists = Test-ComputerExists -ComputerName $NewCompName
$Inc = 0
Write-Verbose "Computer [$NewCompName] Exists in AD: $NewComputerExists"
while ($NewComputerExists){
    Write-Verbose "Computer [$NewCompName] Exists in AD (incrementing name and trying again)"
    $Inc++
    if ($Inc -gt 9) {
        Write-Verbose "Tried 9 interations of the computer name and they all existed."
        exit 9
    }
    If ($NewCompName.Length -gt 13){
        $NewCompName = $NewCompName.Substring(0,13)
    }
    $IncName = "$NewCompName-$Inc"
    $NewComputerExists = = Test-ComputerExists -ComputerName $IncName
    Write-Verbose "Computer [$IncName] Exists in AD: [$NewComputerExists]"
    if (!$NewComputerExists){
        Write-Verbose "Arrived at final incremented Computer [$IncName]. Resetting variable."
        $NewCompName = $IncName
    }
}

# Now that we know we have a computer name that is ok, let's try to rename it.
# if it fails to rename it, exit with a general error code of 7.
try {
    Rename-Computer -NewName $NewCompName -ErrorAction Stop
    Write-Verbose -Message "Computer rename to [$NewCompName] Complete."
}
catch {
    Write-Verbose -Message "Computer rename to [$NewCompName] failed."
    exit 7
}
