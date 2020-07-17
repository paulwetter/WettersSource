Import-Module ActiveDirectory
Import-Module (Join-Path $(Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1)
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
        [int]$LogSizeKB = 5120,

        [Parameter(Mandatory = $true)]
        $LogFile
    )
    <#
    Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
    #>
    $LogTime = Get-Date
    $LogLength = $LogSizeKB * 1024
    $Time = Get-Date $LogTime -Format "HH:mm:ss.ffffff"
    $Date = Get-Date $LogTime -Format "MM-dd-yyyy"
    try {
        $log = Get-Item $LogFile -ErrorAction Stop
        If (($log.length) -gt $LogLength) {
            $LogMessage = "<![LOG[Closing log and generating new log file" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"1`" thread=`"`" file=`"`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
            Move-Item -Path "$LogFile" -Destination "$($LogFile.TrimEnd('g'))_" -Force
        }
    }
    catch { Write-Verbose "Nothing to move or move failed." }
 
    if ($null -ne $ErrorMessage) { $Type = 3 }
    if ($null -eq $Component) { $Component = " " }
    if ($null -eq $Type) { $Type = 1 }
 
    $LogMessage = "<![LOG[$Message $ErrorMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
}
Function Get-ComputersFromAD {
    $RootDSE = [ADSI]"LDAP://rootDSE"
    $obj = "LDAP://" + $rootDSE.Defaultnamingcontext
    $domain = New-Object System.DirectoryServices.DirectoryEntry($obj)
    $searcher = New-Object system.DirectoryServices.DirectorySearcher
    $searcher.searchroot = $Domain
    $searcher.Filter = "(&(objectclass=computer))"
    $searcher.pagesize = 1
    $searcher.searchscope = "subtree"
    $proplist = "name", "pwdLastSet", "lastLogonTimestamp", "operatingSystem", "CanonicalName"
    foreach ($i in $proplist) { [void]$searcher.propertiesToLoad.add($i) }
    $results = $searcher.FindAll()
    foreach ($i in $results) {
        $CN = "$($i.properties.canonicalname)"
        $CompName = "$($i.properties.name)"
        $OU = $CN.Replace("/$CompName", '')
        New-Object -TypeName psobject -Property @{'ComputerName' = "$($i.properties.name)"; 'OperatingSystem' = "$($i.properties.operatingsystem)"; 'LastLogon' = "$([datetime]::FromFileTime($($i.properties.lastlogontimestamp)))"; 'PasswordLastSet' = "$([datetime]::FromFileTime($($i.properties.pwdlastset)))"; 'CanonicalName' = "$($i.properties.canonicalname)"; 'OrgUnit' = $OU }
    }
}


Function Get-ComputersFromCM {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SiteServer,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$CMSite = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM\CcmEval -Name LastSiteCode -ErrorAction SilentlyContinue).LastSiteCode,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$Credential
    )
    if ($Credential) {
        Get-WmiObject -Namespace "ROOT\SMS\site_$CMSite" -Query "select distinct SMS_R_System.Name, SMS_R_System.Client, SMS_G_System_CH_ClientSummary.LastPolicyRequest from  SMS_R_System left join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceID = SMS_R_System.ResourceId" -ComputerName $SiteServer -Credential $Credential | Select-Object -Property @{Name = 'Name'; Expression = { $_.SMS_R_System.Name } }, @{Name = 'Client'; Expression = { $_.SMS_R_System.Client } }, @{Name = 'LastPolicyRequest'; Expression = { [Management.ManagementDateTimeConverter]::ToDateTime($_.SMS_G_System_CH_ClientSummary.LastPolicyRequest) } }
    }
    else {
        Get-WmiObject -Namespace "ROOT\SMS\site_$CMSite" -Query "select distinct SMS_R_System.Name, SMS_R_System.Client, SMS_G_System_CH_ClientSummary.LastPolicyRequest from  SMS_R_System left join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceID = SMS_R_System.ResourceId" -ComputerName $SiteServer | Select-Object -Property @{Name = 'Name'; Expression = { $_.SMS_R_System.Name } }, @{Name = 'Client'; Expression = { $_.SMS_R_System.Client } }, @{Name = 'LastPolicyRequest'; Expression = { [Management.ManagementDateTimeConverter]::ToDateTime($_.SMS_G_System_CH_ClientSummary.LastPolicyRequest) } }
    }
}

function Get-ADWithCMComputers {
    param(
        # An array of computer objects from AD
        [Parameter(Mandatory = $true)]
        $AdComputers,
        # An array of computer objects from CM
        [Parameter(Mandatory = $true)]
        $CmComputers
    )
    foreach ($Comp in $AdComputers) {
        If ($Comp.ComputerName -in $CmComputers.Name) {
            $InCM = 'True'
            $CMComputer = $CmComputers | Where-Object { $_.Name -like $Comp.ComputerName }
            if ($CMComputer.Client -eq 1) { $CMClient = 'True' }else { $CMClient = 'False' }
            $CMPolicyRequest = $CMComputer.LastPolicyRequest
        }
        else {
            $InCM = 'False'
            $CMClient = 'False'
            $CMPolicyRequest = ''
        }
        [pscustomobject][ordered]@{
            'ComputerName'      = "$($Comp.ComputerName)"
            'OperatingSystem'   = "$($Comp.OperatingSystem)"
            'LastLogon'         = "$($Comp.LastLogon)"
            'PasswordLastSet'   = "$($Comp.PasswordLastSet)"
            'CanonicalName'     = "$($Comp.CanonicalName)"
            'OrgUnit'           = "$($Comp.OrgUnit)"
            'InConfigMgr'       = "$InCM"
            'CMClient'          = "$CMClient"
            'LastPolicyRequest' = "$CMPolicyRequest"
        }
    }
}

Function Get-ADCMComparison {
    param(
        # Primary site server for this Configuration Manager Site
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SiteServer,
        # Site name for this primary site server
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CMSite = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM\CcmEval -Name LastSiteCode -ErrorAction SilentlyContinue).LastSiteCode,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $false)]
        $Logfile
    )
    if ($logfile){Write-Log -Message "Collecting computer information from AD..." -Component 'Get-ADCMComparison' -Type 1 -LogFile $Logfile}
    Try {
        $adc = Get-ComputersFromAD
        if ($logfile){Write-Log -Message "Collected [$($adc.count)] computers from AD" -Component 'Get-ADCMComparison' -Type 1 -LogFile $Logfile}
    }
    Catch {
        if ($logfile){Write-Log -Message "failed to collect computer information from AD" -Component 'Get-ADCMComparison' -Type 3 -LogFile $Logfile}
    }
    Try {
        if ($logfile){Write-Log -Message "Collecting computer information from CM..." -Component 'Get-ADCMComparison' -Type 1 -LogFile $Logfile}
        if ($Credential) {
            $cmc = Get-ComputersFromCM -SiteServer $SiteServer -CMSite $CMSite -Credential $Credential
        }
        else {
            $cmc = Get-ComputersFromCM -SiteServer $SiteServer -CMSite $CMSite
        }
        if ($logfile){Write-Log -Message "Collected [$($cmc.count)] computers from CM" -Component 'Get-ADCMComparison' -Type 1 -LogFile $Logfile}
    }
    Catch{
        if ($logfile){Write-Log -Message "failed to collect computer information from CM" -Component 'Get-ADCMComparison' -Type 3 -LogFile $Logfile}
    }
    if ($logfile){Write-Log -Message "Comparing computer lists from AD and CM" -Component 'Get-ADWithCMComputers' -Type 1 -LogFile $Logfile}
    Get-ADWithCMComputers -AdComputers $adc -CmComputers $cmc
}

Function Invoke-PWADDisableAndMoveComputer {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName,
        #A valid ou would be something like 'ou=Workstations,ou=Corp,dc=southwind,dc=net'
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$DeleteOU, #OU=DeviceCleanup,OU=VSTO-Computers,DC=VSTO,DC=VistaOutdoor,DC=com
        #Path to a log file: C:\Temp\DisableandMove.log
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$LogFile,
        [Parameter(Mandatory = $false)]
        [String]$Domain = (Get-WmiObject -Class Win32_ComputerSystem -Property Domain -ErrorAction Ignore).Domain
    )
    try { $Computer = Get-ADComputer $ComputerName -Properties Modified, CanonicalName }
    Catch { Write-Log -Message "[$ComputerName] Was not found in AD" -Component 'Invoke-PWADDisableAndMoveComputer' -Type 3 -LogFile $Logfile }
    If ($Computer) {
        If ($domain) {
            $ComputerCanonicalName = ($Computer.CanonicalName) -replace "$($Domain)/", ''
        }
        else {
            $ComputerCanonicalName = ($Computer.CanonicalName)
        }
        $ComputerCanonicalName = $ComputerCanonicalName -replace "/$($Computer.Name)", ''
        Write-Log -Message "[$ComputerName] Last Modified before move: $($Computer.Modified) -- Last OU: $($ComputerCanonicalName)" -Component 'Invoke-PWADDisableAndMoveComputer' -Type 1 -LogFile $Logfile
        try {
            Set-ADComputer $Computer -Description "Last Modified before move: $($Computer.Modified) -- Last OU: $($ComputerCanonicalName)" -Enabled $False
            Move-ADObject -Identity $Computer -TargetPath $DeleteOU
        }
        Catch {
            Write-Log -Message "[$ComputerName] Unable to set description and/or move. Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Component 'Invoke-PWADDisableAndMoveComputer' -Type 3 -LogFile $Logfile
        }
    }
}

Function Invoke-PWCMRemoveComputer {
    param(
        #The name of the computer that we will delete from ConfigMgr
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName,
        #SCCM Site code
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$CMSite = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM\CcmEval -Name LastSiteCode -ErrorAction SilentlyContinue).LastSiteCode,
        #Path to a log file: C:\Temp\DisableandMove.log
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$LogFile
    )
    Try {
        Push-Location "$($CMSite):"
        Remove-CMDevice -Name $ComputerName -Force -ErrorAction Stop
        Write-Verbose "Removed computer [$ComputerName]."
        Write-Log -Message "Removed computer [$ComputerName]." -Component 'Invoke-PWCMRemoveComputer' -Type 1 -LogFile $Logfile
    }
    catch {
        Write-Verbose "Failed to remove computer [$ComputerName].  Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)"
        Write-Log -Message "Failed to remove computer [$ComputerName].  Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Component 'Invoke-PWCMRemoveComputer' -Type 3 -LogFile $Logfile
    }
    Finally {
        Pop-Location
    }
}


$Logfile = 'C:\Shared\ComputerCleanup.log'
$SystemReview = 'C:\Shared\ComputerCleanupReview.log'
$SystemRemove = 'C:\Shared\ComputerCleanupRemove.log'
$DeleteCsv = 'C:\Shared\ComputerCleanupRemove.csv'
$ExcludeCleanupOU = 'VSTO.VistaOutdoor.com/VSTO-Computers/DeviceCleanup'
$CleanupCM = $false
$CleanupAD = $false
$ArchiveDate = (Get-date).AddMonths(-3)  #a date that is 3 months ago.
$ArchiveDateString = $ArchiveDate.ToString()
[string]$CMSite = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM\CcmEval -Name LastSiteCode -ErrorAction SilentlyContinue).LastSiteCode
If (!($CMSite)){
    [string]$CMSite = (Get-WmiObject -Query 'SELECT Name FROM SMS_Authority' -Namespace root\ccm).name -replace 'SMS:',''
}
Try {
    $Computers = @()
    Write-Log -Message "Collecting computer information" -Component 'Get-ADCMComparison' -Type 1 -LogFile $Logfile
    $Computers = Get-ADCMComparison -SiteServer MN13SVSCCM01.vsto.vistaoutdoor.com -CMSite $CMSite -LogFile $Logfile
    Write-Log -Message "Computer information collected for [$($Computers.count)] computers" -Component 'Get-ADCMComparison' -Type 1 -LogFile $Logfile
}
Catch {
    Write-Log -Message "Unable to collect computer Information" -Component 'Get-ADCMComparison' -Type 3 -LogFile $Logfile
}
IF ($Computers) {
    Foreach ($Computer in $Computers) {
        If (($Computer.OperatingSystem -Like "Windows 7*") -or ($Computer.OperatingSystem -Like "Windows 8*") -or ($Computer.OperatingSystem -Like "Windows 10*")) {
            Try { $ThisComputer = Get-AdComputer $Computer.ComputerName -ErrorAction Stop
                $ComputerEnabled = $ThisComputer.Enabled
                Remove-Variable ThisComputer -ErrorAction Ignore
                $ComputerOrgUnit = $Computer.OrgUnit
                $PasswordLastSetDate = Try { Get-Date $Computer.PasswordLastSet } Catch { get-date 1/1/1600 }
                $LastLogonDate = Try { Get-Date $Computer.LastLogon } Catch { get-date 1/1/1600 }
                $LastPolicyRequestDate = Try { Get-Date $Computer.LastPolicyRequest } Catch { get-date 1/1/1600 }
                Write-Log -Message "[$($Computer.ComputerName)] Checking Computer Status" -Type 1 -LogFile $Logfile
                If (($PasswordLastSetDate -lt $ArchiveDate) -and ($LastLogonDate -lt $ArchiveDate)) {
                    Write-Log -Message "[$($Computer.ComputerName)] AD dates [$($Computer.PasswordLastSet)] and [$($Computer.LastLogon)] are older than [$ArchiveDateString)]" -Type 1 -LogFile $Logfile
                    Write-Log -Message "[$($Computer.ComputerName)] Checking ConfigMgr Data" -Type 1 -LogFile $Logfile
                    IF ($Computer.InConfigMgr -eq $false) {
                        Write-Log -Message "[$($Computer.ComputerName)] Not found in ConfigMgr" -Type 1 -LogFile $Logfile
                        Write-Log -Message "[$($Computer.ComputerName)] Found as computer flagged for deletion" -Type 1 -LogFile $SystemRemove
                        If (($ComputerEnabled -eq $true) -or ($ComputerOrgUnit -ne $ExcludeCleanupOU)) {
                            #Deleting AD
                            If ($CleanupAD) {
                                Invoke-PWADDisableAndMoveComputer -ComputerName $Computer.ComputerName -DeleteOU 'OU=DeviceCleanup,OU=VSTO-Computers,DC=VSTO,DC=VistaOutdoor,DC=com' -LogFile $Logfile
                            }
                            "$($Computer.ComputerName),$($Computer.OperatingSystem),$($Computer.PasswordLastSet),$($Computer.LastLogon),$($Computer.LastPolicyRequest)">>$DeleteCsv
                        }
                    }
                    elseIf ($Computer.CMClient -ne $true) {
                        Write-Log -Message "[$($Computer.ComputerName)] In ConfigMgr but no client installed" -Type 1 -LogFile $Logfile
                        Write-Log -Message "[$($Computer.ComputerName)] Found as computer flagged for deletion" -Type 1 -LogFile $SystemRemove
                        If (($ComputerEnabled -eq $true) -or ($ComputerOrgUnit -ne $ExcludeCleanupOU)) {
                            #Deleting AD
                            If ($CleanupAD) {
                                Invoke-PWADDisableAndMoveComputer -ComputerName $Computer.ComputerName -DeleteOU 'OU=DeviceCleanup,OU=VSTO-Computers,DC=VSTO,DC=VistaOutdoor,DC=com' -LogFile $Logfile
                            }
                            "$($Computer.ComputerName),$($Computer.OperatingSystem),$($Computer.PasswordLastSet),$($Computer.LastLogon),$($Computer.LastPolicyRequest)">>$DeleteCsv
                        }
                        #Deleting CM
                        If ($CleanupCM) {
                            Invoke-PWCMRemoveComputer -ComputerName $Computer.ComputerName -CMSite $CMSite -LogFile $Logfile
                        }
                    }
                    elseif (($LastPolicyRequestDate) -lt $ArchiveDate) {
                        Write-Log -Message "[$($Computer.ComputerName)] ConfigMgr policy date [$($Computer.LastPolicyRequest)] is older than [$ArchiveDateString)]" -Type 1 -LogFile $Logfile
                        Write-Log -Message "[$($Computer.ComputerName)] Found as computer flagged for deletion" -Type 1 -LogFile $SystemRemove
                        If (($ComputerEnabled -eq $true) -or ($ComputerOrgUnit -ne $ExcludeCleanupOU)) {
                            #Deleting AD
                            If ($CleanupAD) {
                                Invoke-PWADDisableAndMoveComputer -ComputerName $Computer.ComputerName -DeleteOU 'OU=DeviceCleanup,OU=VSTO-Computers,DC=VSTO,DC=VistaOutdoor,DC=com' -LogFile $Logfile
                            }
                            "$($Computer.ComputerName),$($Computer.OperatingSystem),$($Computer.PasswordLastSet),$($Computer.LastLogon),$($Computer.LastPolicyRequest)">>$DeleteCsv
                        }
                        #Deleting CM
                        If ($CleanupCM) {
                            Invoke-PWCMRemoveComputer -ComputerName $Computer.ComputerName -CMSite $CMSite -LogFile $Logfile
                        }
                    }
                    Else{
                        Write-Log -Message "[$($Computer.ComputerName)] ConfigMgr policy date [$($Computer.LastPolicyRequest)] is newer than [$ArchiveDateString)]" -Type 2 -LogFile $Logfile
                        Write-Log -Message "[$($Computer.ComputerName)] AD dates [$($Computer.PasswordLastSet)] and [$($Computer.LastLogon)] ConfigMgr policy date [$($Computer.LastPolicyRequest)] need review to [$ArchiveDateString)]" -Type 1 -LogFile $SystemReview
                    }
                }
                elseif (($PasswordLastSetDate -gt $ArchiveDate) -and ($LastLogonDate -gt $ArchiveDate)) {
                    Write-Log -Message "[$($Computer.ComputerName)] AD dates [$($Computer.PasswordLastSet)] and [$($Computer.LastLogon)] are newer than [$ArchiveDateString)]" -Type 1 -LogFile $Logfile
                    IF (($Computer.InConfigMgr -eq $true) -and ($Computer.CMClient -eq $true)) {
                        Write-Log -Message "[$($Computer.ComputerName)] In ConfigMgr and has a client" -Type 1 -LogFile $Logfile
                        If ($LastPolicyRequestDate -ge $ArchiveDate) {
                            Write-Log -Message "[$($Computer.ComputerName)] ConfigMgr policy date [$($Computer.LastPolicyRequest)] is newer than [$ArchiveDateString)]" -Type 1 -LogFile $Logfile
                            Write-Log -Message "[$($Computer.ComputerName)] Checks Complete. No changes." -Type 1 -LogFile $Logfile
                        }
                        else {
                            Write-Log -Message "[$($Computer.ComputerName)] ConfigMgr policy date [$($Computer.LastPolicyRequest)] is older than [$ArchiveDateString)]" -Type 2 -LogFile $Logfile
                            Write-Log -Message "[$($Computer.ComputerName)] AD dates [$($Computer.PasswordLastSet)] and [$($Computer.LastLogon)] newer than and ConfigMgr policy date [$($Computer.LastPolicyRequest)] older than [$ArchiveDateString)]" -Type 2 -LogFile $SystemReview
                        }
                    }
                }
                else {
                    Write-Log -Message "[$($Computer.ComputerName)] AD dates [$($Computer.PasswordLastSet)] and [$($Computer.LastLogon)] ConfigMgr policy date [$($Computer.LastPolicyRequest)] need review to [$ArchiveDateString)]" -Type 2 -LogFile $Logfile
                    Write-Log -Message "[$($Computer.ComputerName)] AD dates [$($Computer.PasswordLastSet)] and [$($Computer.LastLogon)] ConfigMgr policy date [$($Computer.LastPolicyRequest)] need review to [$ArchiveDateString)]" -Type 1 -LogFile $SystemReview
                }
            }
            Catch {
                Write-Log -Message "[$($Computer.ComputerName)] Error when searching AD" -Component 'Get-ADComputer' -Type 3 -LogFile $Logfile
                Write-Log -Message "[$($Computer.ComputerName)] Error when searching AD" -Component 'Get-ADComputer' -Type 3 -LogFile $SystemReview
                Write-Log -Message "Failed to find computer [$ComputerName].  Exception: $($_.Exception.Message) Reason: $($_.CategoryInfo.Reason)" -Component 'Get-ADComputer' -Type 2 -LogFile $Logfile
            }
        } else {
            Write-Log -Message "[$($Computer.ComputerName)] Skipping evaluation, not Workstation OS.  Operating System [$($Computer.OperatingSystem)]" -Component 'Get-ADComputer' -Type 1 -LogFile $Logfile
        }
    }
}
