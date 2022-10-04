Function Get-InstalledSoftware {
    <#
    .SYNOPSIS
    Attempts to get all installed software on a system and exports them to a list
    
    .DESCRIPTION
    This script will attempt to search all the selected Uninstall registry keys for software installed on the computer and will return
    
    .PARAMETER Architecture
    Choose if you want to search for only 32 or 64 apps [x86|x64].  Default is both 
    
    .PARAMETER RegHives
    Choose if you want to search both the machine (HKLM) and the user (HKCU - that the process is running as) hives [HKLM|HKCU].  default is machine only.
    
    .EXAMPLE
    Get-InstalledSoftware
    
    .NOTES
    #>
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('x86', 'x64')]
        [string[]]$Architecture = @('x86', 'x64'),
        [Parameter(Mandatory = $false)]
        [ValidateSet('HKLM', 'HKCU')]
        [string[]]$RegHives = 'HKLM',
        [Parameter(Mandatory = $false)]
        [switch]$ShowAll
    )

    $RegHivesHash = @{
        'HKLM' = 'registry::HKEY_LOCAL_MACHINE\'
        'HKCU' = 'registry::HKEY_CURRENT_USER\'
    }

    $UninstallKeys = New-Object Collections.Generic.List[string]
    #IntPtr will be 4 on a 32 bit process and then there is only one uninstall key.
    if (([IntPtr]::Size -eq 4)) {
        $UninstallKeys.Add('Software\Microsoft\Windows\CurrentVersion\Uninstall\*')
    }
    else {
        If ($Architecture.Contains('x86')){
            $UninstallKeys.Add('Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        }
        If ($Architecture.Contains('x64')){
            $UninstallKeys.Add('Software\Microsoft\Windows\CurrentVersion\Uninstall\*')
        }
    }
    
    $FullKeyPaths = New-Object Collections.Generic.List[string]
    foreach ($Hive in $RegHives){
        foreach ($Key in $UninstallKeys){
            $FullKeyPaths.Add("$($RegHivesHash.$Hive)$Key")
        }
    }
    $Properties = 'DisplayName', 'DisplayVersion', 'PSChildName', 'Publisher', 'UninstallString'

    $AllUninstalls = Get-ItemProperty -Path $FullKeyPaths -Name $Properties -ErrorAction SilentlyContinue

    If ($PSBoundParameters.ContainsKey('ShowAll')){
        $AllUninstalls | Select-Object -Property $Properties
    }
    else {
        foreach ($Uninstall in $AllUninstalls) {
            if (-not [string]::IsNullOrEmpty($Uninstall.DisplayName)) {
                $Uninstall | Select-Object -Property $Properties
            }
        }
    }
}