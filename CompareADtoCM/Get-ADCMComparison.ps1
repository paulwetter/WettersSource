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
        Get-WmiObject -Namespace "ROOT\SMS\site_$CMSite" -Query "select distinct SMS_R_System.Name, SMS_R_System.Client, SMS_G_System_CH_ClientSummary.LastPolicyRequest from  SMS_R_System left join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceID = SMS_R_System.ResourceId" -ComputerName $SiteServer -Credential $Credential | select -Property @{Name='Name'; Expression={$_.SMS_R_System.Name}},@{Name='Client'; Expression={$_.SMS_R_System.Client}},@{Name='LastPolicyRequest'; Expression={[Management.ManagementDateTimeConverter]::ToDateTime($_.SMS_G_System_CH_ClientSummary.LastPolicyRequest)}}
    }
    else {
        Get-WmiObject -Namespace "ROOT\SMS\site_$CMSite" -Query "select distinct SMS_R_System.Name, SMS_R_System.Client, SMS_G_System_CH_ClientSummary.LastPolicyRequest from  SMS_R_System left join SMS_G_System_CH_ClientSummary on SMS_G_System_CH_ClientSummary.ResourceID = SMS_R_System.ResourceId" -ComputerName $SiteServer | select -Property @{Name='Name'; Expression={$_.SMS_R_System.Name}},@{Name='Client'; Expression={$_.SMS_R_System.Client}},@{Name='LastPolicyRequest'; Expression={[Management.ManagementDateTimeConverter]::ToDateTime($_.SMS_G_System_CH_ClientSummary.LastPolicyRequest)}}
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
            'ComputerName'    = "$($Comp.ComputerName)"
            'OperatingSystem' = "$($Comp.OperatingSystem)"
            'LastLogon'       = "$($Comp.LastLogon)"
            'PasswordLastSet' = "$($Comp.PasswordLastSet)"
            'CanonicalName'   = "$($Comp.CanonicalName)"
            'OrgUnit'         = "$($Comp.OrgUnit)"
            'InConfigMgr'     = "$InCM"
            'CMClient'        = "$CMClient"
            'LastPolicyRequest'="$CMPolicyRequest"
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
        [System.Management.Automation.PSCredential]$Credential
    )
    $adc = Get-ComputersFromAD
    if ($Credential) {
        $cmc = Get-ComputersFromCM -SiteServer $SiteServer -CMSite $CMSite -Credential $Credential
    }
    else {
        $cmc = Get-ComputersFromCM -SiteServer $SiteServer -CMSite $CMSite
    }
    Get-ADWithCMComputers -AdComputers $adc -CmComputers $cmc
}

Function Export-ADCMComparison {
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
        # File you want to export your CSV of computers to
        [Parameter(Mandatory = $false)]
        [ValidateScript( {
                if ($_ | Test-Path) {
                    throw "File or folder already exists!"
                }
                return $true
            })]
        [System.IO.FileInfo]
        $CSVPath = ".\CMADComputerComparison$(Get-Date -Format 'yyyyMMdd-hhmmss').csv"
    )
    Write-Host "Exporting computer list to: $CSVPath"
    $adc = Get-ComputersFromAD
    if ($Credential) {
        $cmc = Get-ComputersFromCM -SiteServer $SiteServer -CMSite $CMSite -Credential $Credential
    }
    else {
        $cmc = Get-ComputersFromCM -SiteServer $SiteServer -CMSite $CMSite
    }
    Get-ADWithCMComputers -AdComputers $adc -CmComputers $cmc | Export-Csv -Path $CSVPath -NoTypeInformation
}
