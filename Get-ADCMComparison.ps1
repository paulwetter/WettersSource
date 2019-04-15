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
        [securestring]$Credential
    )
    if ($Credential) {
        Get-WmiObject -Class SMS_R_System -Namespace "ROOT\SMS\site_$CMSite" -Property Name, Client -ComputerName $SiteServer -Credential $Credential | Select-Object Name, Client
    }
    else {
        Get-WmiObject -Class SMS_R_System -Namespace "ROOT\SMS\site_$CMSite" -Property Name, Client -ComputerName $SiteServer | Select-Object Name, Client
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
            $CMClient = $CmComputers | Where-Object { $_.Name -like $Comp.ComputerName } | Select-Object -ExpandProperty Client
            if ($CMClient -eq 1) { $CMClient = 'True' }else { $CMClient = 'False' }
        }
        else {
            $InCM = 'False'
            $CMClient = 'False'
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
        }
    }
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
        [securestring]$Credential,
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
    $adc = Get-ComputersFromAD
    if ($Credential) {
        $cmc = Get-ComputersFromCM -SiteServer $SiteServer -CMSite $CMSite -Credential $Credential
    }
    else {
        $cmc = Get-ComputersFromCM -SiteServer $SiteServer -CMSite $CMSite
    }
    Get-ADWithCMComputers -AdComputers $adc -CmComputers $cmc | Export-Csv -Path $CSVPath -NoTypeInformation
}