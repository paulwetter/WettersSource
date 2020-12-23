
#region Helper methods

Function BoolToString() {
    param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$True)] [bool] $value
    )

    Process {
        return $value.ToString().ToLower()
    }
}

#endregion

#region App-based authentication
Function Connect-MSGraphApp
{
<#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Intune module using app-based authentication.
 
.DESCRIPTION
The Connect-MSGraphApp cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Intune module. It leverages an Azure AD app ID and app secret for authentication. See https://oofhours.com/2019/11/29/app-based-authentication-with-intune/ for more information.
 
.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.
 
.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.
 
.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.
 
.EXAMPLE
Connect-MSGraphApp -TenantId $tenantID -AppId $app -AppSecret $secret
 
-#>
[cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)] [string]$Tenant,
        [Parameter(Mandatory=$false)] [string]$AppId,
        [Parameter(Mandatory=$false)] [string]$AppSecret
    )

    Process {
        Import-Module Microsoft.Graph.Intune
        $authority = "https://login.windows.net/$Tenant"
        Update-MSGraphEnvironment -AppId $AppId -Quiet
        Update-MSGraphEnvironment -AuthUrl $authority -Quiet
        Connect-MSGraph -ClientSecret $AppSecret -Quiet
    }
}

#region Core methods

Function Get-AutopilotDevice(){
<#
.SYNOPSIS
Gets devices currently registered with Windows Autopilot.
 
.DESCRIPTION
The Get-AutopilotDevice cmdlet retrieves either the full list of devices registered with Windows Autopilot for the current Azure AD tenant, or a specific device if the ID of the device is specified.
 
.PARAMETER id
Optionally specifies the ID (GUID) for a specific Windows Autopilot device (which is typically returned after importing a new device)
 
.PARAMETER serial
Optionally specifies the serial number of the specific Windows Autopilot device to retrieve
 
.PARAMETER expand
Expand the properties of the device to include the Autopilot profile information
 
.EXAMPLE
Get a list of all devices registered with Windows Autopilot
 
Get-AutopilotDevice
#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$True)] $id,
        [Parameter(Mandatory=$false)] $serial,
        [Parameter(Mandatory=$false)] [Switch]$expand = $false
    )

    Process {

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
    
        if ($id -and $expand) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$($id)?`$expand=deploymentProfile,intendedDeploymentProfile"
        }
        elseif ($id) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
        }
        elseif ($serial) {
            $encoded = [uri]::EscapeDataString($serial)
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=contains(serialNumber,'$encoded')"
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        }

        Write-Verbose "GET $uri"

        try {
            $response = Invoke-MSGraphRequest -Url $uri -HttpMethod Get
            if ($id) {
                $response
            }
            else {
                $devices = $response.value
                $devicesNextLink = $response."@odata.nextLink"
    
                while ($devicesNextLink -ne $null){
                    $devicesResponse = (Invoke-MSGraphRequest -Url $devicesNextLink -HttpMethod Get)
                    $devicesNextLink = $devicesResponse."@odata.nextLink"
                    $devices += $devicesResponse.value
                }
    
                if ($expand) {
                    $devices | Get-AutopilotDevice -Expand
                }
                else
                {
                    $devices
                }
            }
        }
        catch {
            Write-Error $_.Exception 
            break
        }
    }
}


Function Set-AutopilotDevice(){
<#
.SYNOPSIS
Updates settings on an Autopilot device.
 
.DESCRIPTION
The Set-AutopilotDevice cmdlet can be used to change the updatable properties on a Windows Autopilot device object.
 
.PARAMETER id
The Windows Autopilot device id (mandatory).
 
.PARAMETER userPrincipalName
The user principal name.
 
.PARAMETER addressibleUserName
The name to display during Windows Autopilot enrollment. If specified, the userPrincipalName must also be specified.
 
.PARAMETER displayName
The name (computer name) to be assigned to the device when it is deployed via Windows Autopilot. This is presently only supported with Azure AD Join scenarios. Note that names should not exceed 15 characters. After setting the name, you need to initiate a sync (Invoke-AutopilotSync) in order to see the name in the Intune object.
 
.PARAMETER groupTag
The group tag value to set for the device.
 
.EXAMPLE
Assign a user and a name to display during enrollment to a Windows Autopilot device.
 
Set-AutopilotDevice -id $id -userPrincipalName $userPrincipalName -addressableUserName "John Doe" -displayName "CONTOSO-0001" -groupTag "Testing"
#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)] $id,
        [Parameter(ParameterSetName = "Prop")] $userPrincipalName = $null,
        [Parameter(ParameterSetName = "Prop")] $addressableUserName = $null,
        [Parameter(ParameterSetName = "Prop")][Alias("ComputerName","CN","MachineName")] $displayName = $null,
        [Parameter(ParameterSetName = "Prop")] $groupTag = $null
    )

    Process {
    
        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/UpdateDeviceProperties"

        $json = "{"
        if ($PSBoundParameters.ContainsKey('userPrincipalName'))
        {
            $json = $json + " userPrincipalName: `"$userPrincipalName`","
        }
        if ($PSBoundParameters.ContainsKey('addressableUserName'))
        {
            $json = $json + " addressableUserName: `"$addressableUserName`","
        }
        if ($PSBoundParameters.ContainsKey('displayName'))
        {
            $json = $json + " displayName: `"$displayName`","
        }
        if ($PSBoundParameters.ContainsKey('groupTag'))
        {
            $json = $json + " groupTag: `"$groupTag`""
        }
        else
        {
            $json = $json.Trim(",")
        }
        $json = $json + " }"

        Write-Verbose "POST $uri`n$json"

        try {
            Invoke-MSGraphRequest -Url $uri -HttpMethod POST -Content $json
        }
        catch {
            Write-Error $_.Exception 
            break
        }
    }
}

    
Function Remove-AutopilotDevice(){
<#
.SYNOPSIS
Removes a specific device currently registered with Windows Autopilot.
 
.DESCRIPTION
The Remove-AutopilotDevice cmdlet removes the specified device, identified by its ID, from the list of devices registered with Windows Autopilot for the current Azure AD tenant.
 
.PARAMETER id
Specifies the ID (GUID) for a specific Windows Autopilot device
 
.EXAMPLE
Remove all Windows Autopilot devices from the current Azure AD tenant
 
Get-AutopilotDevice | Remove-AutopilotDevice
#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)] $id,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$True)] $serialNumber
    )

    Begin {
        $bulkList = @()
    }

    Process {

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"

        try {
            Write-Verbose "DELETE $uri"
            Invoke-MSGraphRequest -Url $uri -HttpMethod DELETE
        }
        catch {
            Write-Error $_.Exception 
            break
        }
        
    }
}


Function Get-AutopilotImportedDevice(){
<#
.SYNOPSIS
Gets information about devices being imported into Windows Autopilot.
 
.DESCRIPTION
The Get-AutopilotImportedDevice cmdlet retrieves either the full list of devices being imported into Windows Autopilot for the current Azure AD tenant, or information for a specific device if the ID of the device is specified. Once the import is complete, the information instance is expected to be deleted.
 
.PARAMETER id
Optionally specifies the ID (GUID) for a specific Windows Autopilot device being imported.
 
.EXAMPLE
Get a list of all devices being imported into Windows Autopilot for the current Azure AD tenant.
 
Get-AutopilotImportedDevice
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$false)] $id = $null
)

    # Defining Variables
    $graphApiVersion = "beta"
    if ($id) {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/importedWindowsAutopilotDeviceIdentities/$id"
    }
    else {
        $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/importedWindowsAutopilotDeviceIdentities"
    }

    Write-Verbose "GET $uri"

    try {
        $response = Invoke-MSGraphRequest -Url $uri -HttpMethod Get
        if ($id) {
            $response
        }
        else {
            $devices = $response.value
    
            $devicesNextLink = $response."@odata.nextLink"
    
            while ($devicesNextLink -ne $null){
                $devicesResponse = (Invoke-MSGraphRequest -Url $devicesNextLink -HttpMethod Get)
                $devicesNextLink = $devicesResponse."@odata.nextLink"
                $devices += $devicesResponse.value
            }
    
            $devices
        }
    }
    catch {
            Write-Error $_.Exception 
            break
    }

}


<#
.SYNOPSIS
Adds a new device to Windows Autopilot.
 
.DESCRIPTION
The Add-AutopilotImportedDevice cmdlet adds the specified device to Windows Autopilot for the current Azure AD tenant. Note that a status object is returned when this cmdlet completes; the actual import process is performed as a background batch process by the Microsoft Intune service.
 
.PARAMETER serialNumber
The hardware serial number of the device being added (mandatory).
 
.PARAMETER hardwareIdentifier
The hardware hash (4K string) that uniquely identifies the device.
 
.PARAMETER groupTag
An optional identifier or tag that can be associated with this device, useful for grouping devices using Azure AD dynamic groups.
 
.PARAMETER displayName
The optional name (computer name) to be assigned to the device when it is deployed via Windows Autopilot. This is presently only supported with Azure AD Join scenarios. Note that names should not exceed 15 characters. After setting the name, you need to initiate a sync (Invoke-AutopilotSync) in order to see the name in the Intune object.
 
.PARAMETER assignedUser
The optional user UPN to be assigned to the device. Note that no validation is done on the UPN specified.
 
.EXAMPLE
Add a new device to Windows Autopilot for the current Azure AD tenant.
 
Add-AutopilotImportedDevice -serialNumber $serial -hardwareIdentifier $hash -groupTag "Kiosk" -assignedUser "anna@contoso.com"
#>
Function Add-AutopilotImportedDevice(){
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)] $serialNumber,
        [Parameter(Mandatory=$true)] $hardwareIdentifier,
        [Parameter(Mandatory=$false)] [Alias("orderIdentifier")] $groupTag = "",
        [Parameter(ParameterSetName = "Prop2")][Alias("UPN")] $assignedUser = ""
    )

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/importedWindowsAutopilotDeviceIdentities"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $json = @"
{
    "@odata.type": "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
    "orderIdentifier": "$groupTag",
    "serialNumber": "$serialNumber",
    "productKey": "",
    "hardwareIdentifier": "$hardwareIdentifier",
    "assignedUserPrincipalName": "$assignedUser",
    "state": {
        "@odata.type": "microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
        "deviceImportStatus": "pending",
        "deviceRegistrationId": "",
        "deviceErrorCode": 0,
        "deviceErrorName": ""
    }
}
"@

        Write-Verbose "POST $uri`n$json"

        try {
            Invoke-MSGraphRequest -Url $uri -HttpMethod Post -Content $json
        }
        catch {
            Write-Error $_.Exception 
            break
        }
    
}

    
Function Remove-AutopilotImportedDevice(){
<#
.SYNOPSIS
Removes the status information for a device being imported into Windows Autopilot.
 
.DESCRIPTION
The Remove-AutopilotImportedDevice cmdlet cleans up the status information about a new device being imported into Windows Autopilot. This should be done regardless of whether the import was successful or not.
 
.PARAMETER id
The ID (GUID) of the imported device status information to be removed (mandatory).
 
.EXAMPLE
Remove the status information for a specified device.
 
Remove-AutopilotImportedDevice -id $id
#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)] $id
    )

    Process {

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/importedWindowsAutopilotDeviceIdentities"    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"

        try {
            Write-Verbose "DELETE $uri"
            Invoke-MSGraphRequest -Url $uri -HttpMethod DELETE
        }
        catch {
            Write-Error $_.Exception 
            break
        }

    }
        
}


Function Get-AutopilotProfile(){
<#
.SYNOPSIS
Gets Windows Autopilot profile details.
 
.DESCRIPTION
The Get-AutopilotProfile cmdlet returns either a list of all Windows Autopilot profiles for the current Azure AD tenant, or information for the specific profile specified by its ID.
 
.PARAMETER id
Optionally, the ID (GUID) of the profile to be retrieved.
 
.EXAMPLE
Get a list of all Windows Autopilot profiles.
 
Get-AutopilotProfile
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$false)] $id
)

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"

    if ($id) {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"
    }
    else {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    }

    Write-Verbose "GET $uri"

    try {
        $response = Invoke-MSGraphRequest -Url $uri -HttpMethod Get
        if ($id) {
            $response
        }
        else {
            $devices = $response.value
    
            $devicesNextLink = $response."@odata.nextLink"
    
            while ($devicesNextLink -ne $null){
                $devicesResponse = (Invoke-MSGraphRequest -Url $devicesNextLink -HttpMethod Get)
                $devicesNextLink = $devicesResponse."@odata.nextLink"
                $devices += $devicesResponse.value
            }
    
            $devices
        }
    }
    catch {
        Write-Error $_.Exception 
        break
    }

}


Function Get-AutopilotProfileAssignedDevice(){
<#
.SYNOPSIS
Gets the list of devices that are assigned to the specified Windows Autopilot profile.
 
.DESCRIPTION
The Get-AutopilotProfileAssignedDevice cmdlet returns the list of Autopilot devices that have been assigned the specified Windows Autopilot profile.
 
.PARAMETER id
The ID (GUID) of the profile to be retrieved.
 
.EXAMPLE
Get a list of all Windows Autopilot profiles.
 
Get-AutopilotProfileAssignedDevices -id $id
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$True)] $id
)

    Process {

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assignedDevices"

        Write-Verbose "GET $uri"

        try {
            $response = Invoke-MSGraphRequest -Url $uri -HttpMethod Get
            $response.Value
        }
        catch {
            Write-Error $_.Exception 
            break
        }
    }
}



Function ConvertTo-AutopilotConfigurationJSON(){
<#
.SYNOPSIS
Converts the specified Windows Autopilot profile into a JSON format.
 
.DESCRIPTION
The ConvertTo-AutopilotConfigurationJSON cmdlet converts the specified Windows Autopilot profile, as represented by a Microsoft Graph API object, into a JSON format.
 
.PARAMETER profile
A Windows Autopilot profile object, typically returned by Get-AutopilotProfile
 
.EXAMPLE
Get the JSON representation of each Windows Autopilot profile in the current Azure AD tenant.
 
Get-AutopilotProfile | ConvertTo-AutopilotConfigurationJSON
#>
[cmdletbinding()]
param
(
        [Parameter(Mandatory=$true,ValueFromPipeline=$True)]
        [Object] $profile
)

  Begin {

    # Set the org-related info
    $script:TenantOrg = Get-Organization
    foreach ($domain in $script:TenantOrg.VerifiedDomains) {
        if ($domain.isDefault) {
            $script:TenantDomain = $domain.name
        }
    }
  }

  Process {

    $oobeSettings = $profile.outOfBoxExperienceSettings

    # Build up properties
    $json = @{}
    $json.Add("Comment_File", "Profile $($_.displayName)")
    $json.Add("Version", 2049)
    $json.Add("ZtdCorrelationId", $_.id)
    if ($profile."@odata.type" -eq "#microsoft.graph.activeDirectoryWindowsAutopilotDeploymentProfile")
    {
        $json.Add("CloudAssignedDomainJoinMethod", 1)
    }
    else
    {
        $json.Add("CloudAssignedDomainJoinMethod", 0)
    }
    if ($profile.deviceNameTemplate)
    {
        $json.Add("CloudAssignedDeviceName", $_.deviceNameTemplate)
    }

    # Figure out config value
    $oobeConfig = 8 + 256
    if ($oobeSettings.userType -eq 'standard') {
        $oobeConfig += 2
    }
    if ($oobeSettings.hidePrivacySettings -eq $true) {
        $oobeConfig += 4
    }
    if ($oobeSettings.hideEULA -eq $true) {
        $oobeConfig += 16
    }
    if ($oobeSettings.skipKeyboardSelectionPage -eq $true) {
        $oobeConfig += 1024
    if ($_.language) {
            $json.Add("CloudAssignedLanguage", $_.language)
        }
    }
    if ($oobeSettings.deviceUsageType -eq 'shared') {
        $oobeConfig += 32 + 64
    }
    $json.Add("CloudAssignedOobeConfig", $oobeConfig)

    # Set the forced enrollment setting
    if ($oobeSettings.hideEscapeLink -eq $true) {
        $json.Add("CloudAssignedForcedEnrollment", 1)
    }
    else {
        $json.Add("CloudAssignedForcedEnrollment", 0)
    }

    $json.Add("CloudAssignedTenantId", $script:TenantOrg.id)
    $json.Add("CloudAssignedTenantDomain", $script:TenantDomain)
    $embedded = @{}
    $embedded.Add("CloudAssignedTenantDomain", $script:TenantDomain)
    $embedded.Add("CloudAssignedTenantUpn", "")
    if ($oobeSettings.hideEscapeLink -eq $true) {
        $embedded.Add("ForcedEnrollment", 1)
    }
    else
    {
        $embedded.Add("ForcedEnrollment", 0)
    }
    $ztc = @{}
    $ztc.Add("ZeroTouchConfig", $embedded)
    $json.Add("CloudAssignedAadServerData", (ConvertTo-JSON $ztc -Compress))

    # Skip connectivity check
    if ($profile.hybridAzureADJoinSkipConnectivityCheck -eq $true) {
        $json.Add("HybridJoinSkipDCConnectivityCheck", 1)
    }

    # Hard-code properties not represented in Intune
    $json.Add("CloudAssignedAutopilotUpdateDisabled", 1)
    $json.Add("CloudAssignedAutopilotUpdateTimeout", 1800000)

    # Return the JSON
    ConvertTo-JSON $json
  }

}


Function Set-AutopilotProfile(){
<#
.SYNOPSIS
Sets Windows Autopilot profile properties on an existing Autopilot profile.
 
.DESCRIPTION
The Set-AutopilotProfile cmdlet sets properties on an existing Autopilot profile.
 
.PARAMETER id
The GUID of the profile to be updated.
 
.PARAMETER displayName
The name of the Windows Autopilot profile to create. (This value cannot contain spaces.)
 
.PARAMETER description
The description to be configured in the profile. (This value cannot contain dashes.)
 
.PARAMETER ConvertDeviceToAutopilot
Configure the value "Convert all targeted devices to Autopilot"
 
.PARAMETER AllEnabled
Enable everything that can be enabled
 
.PARAMETER AllDisabled
Disable everything that can be disabled
 
.PARAMETER OOBE_HideEULA
Configure the OOBE option to hide or not the EULA
 
.PARAMETER OOBE_EnableWhiteGlove
Configure the OOBE option to allow or not White Glove OOBE
 
.PARAMETER OOBE_HidePrivacySettings
Configure the OOBE option to hide or not the privacy settings
 
.PARAMETER OOBE_HideChangeAccountOpts
Configure the OOBE option to hide or not the change account options
 
.PARAMETER OOBE_UserTypeAdmin
Configure the user account type as administrator.
 
.PARAMETER OOBE_NameTemplate
Configure the OOBE option to apply a device name template
 
.PARAMETER OOBE_language
The language identifier (e.g. "en-us") to be configured in the profile
 
.PARAMETER OOBE_SkipKeyboard
Configure the OOBE option to skip or not the keyboard selection page
 
.PARAMETER OOBE_HideChangeAccountOpts
Configure the OOBE option to hide or not the change account options
 
.PARAMETER OOBE_SkipConnectivityCheck
Specify whether to skip Active Directory connectivity check (UserDrivenAAD only)
 
.EXAMPLE
Update an existing Autopilot profile to specify a language:
 
Set-AutopilotProfile -ID <guid> -Language "en-us"
 
.EXAMPLE
Update an existing Autopilot profile to set multiple properties:
 
Set-AutopilotProfile -ID <guid> -Language "en-us" -displayname "My testing profile" -Description "Description of my profile" -OOBE_HideEULA $True -OOBE_hidePrivacySettings $True
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)] $id,
    [Parameter(ParameterSetName='notAll')][string] $displayName,
    [Parameter(ParameterSetName='notAll')][string] $description,
    [Parameter(ParameterSetName='notAll')][Switch] $ConvertDeviceToAutopilot,
    [Parameter(ParameterSetName='notAll')][string] $OOBE_language,
    [Parameter(ParameterSetName='notAll')][Switch] $OOBE_skipKeyboard,
    [Parameter(ParameterSetName='notAll')][string] $OOBE_NameTemplate,
    [Parameter(ParameterSetName='notAll')][Switch] $OOBE_EnableWhiteGlove,
    [Parameter(ParameterSetName='notAll')][Switch] $OOBE_UserTypeAdmin,
    [Parameter(ParameterSetName='AllEnabled',Mandatory=$true)][Switch] $AllEnabled, 
    [Parameter(ParameterSetName='AllDisabled',Mandatory=$true)][Switch] $AllDisabled, 
    [Parameter(ParameterSetName='notAll')][Switch] $OOBE_HideEULA,
    [Parameter(ParameterSetName='notAll')][Switch] $OOBE_hidePrivacySettings,
    [Parameter(ParameterSetName='notAll')][Switch] $OOBE_HideChangeAccountOpts,
    [Parameter(ParameterSetName='notAll')][Switch] $OOBE_SkipConnectivityCheck
)

    # Get the current values
    $current = Get-AutopilotProfile -id $id

    # If this is a Hybrid AADJ profile, make sure it has the needed property
    if ($current.'@odata.type' -eq "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile") {
        if (-not ($current.PSObject.Properties | where { $_.Name -eq "hybridAzureADJoinSkipConnectivityCheck"})) {
            $current | Add-Member -NotePropertyName hybridAzureADJoinSkipConnectivityCheck -NotePropertyValue $false
        }
    }

    # For parameters that were specified, update that object in place
    if ($PSBoundParameters.ContainsKey('displayName')) { $current.displayName = $displayName }
    if ($PSBoundParameters.ContainsKey('description')) { $current.description = $description }
    if ($PSBoundParameters.ContainsKey('ConvertDeviceToAutopilot')) { $current.extractHardwareHash = [bool]$ConvertDeviceToAutopilot }
    if ($PSBoundParameters.ContainsKey('OOBE_language')) { $current.language = $OOBE_language }
    if ($PSBoundParameters.ContainsKey('OOBE_skipKeyboard')) { $current.outOfBoxExperienceSettings.skipKeyboardSelectionPage = [bool]$OOBE_skipKeyboard }
    if ($PSBoundParameters.ContainsKey('OOBE_NameTemplate')) { $current.deviceNameTemplate = $OOBE_NameTemplate }
    if ($PSBoundParameters.ContainsKey('OOBE_EnableWhiteGlove')) { $current.enableWhiteGlove = [bool]$OOBE_EnableWhiteGlove }
    if ($PSBoundParameters.ContainsKey('OOBE_UserTypeAdmin')) {
        if ($OOBE_UserTypeAdmin) {
            $current.outOfBoxExperienceSettings.userType = "administrator"
        }
        else {
            $current.outOfBoxExperienceSettings.userType = "standard"
        }
    }
    if ($PSBoundParameters.ContainsKey('OOBE_HideEULA')) { $current.outOfBoxExperienceSettings.hideEULA = [bool]$OOBE_HideEULA }
    if ($PSBoundParameters.ContainsKey('OOBE_HidePrivacySettings')) { $current.outOfBoxExperienceSettings.hidePrivacySettings = [bool]$OOBE_HidePrivacySettings }
    if ($PSBoundParameters.ContainsKey('OOBE_HideChangeAccountOpts')) { $current.outOfBoxExperienceSettings.hideEscapeLink = [bool]$OOBE_HideChangeAccountOpts }
    if ($PSBoundParameters.ContainsKey('OOBE_SkipConnectivityCheck')) { $current.hybridAzureADJoinSkipConnectivityCheck = [bool]$OOBE_SkipConnectivityCheck }

    if ($AllEnabled) {
        $current.extractHardwareHash = $true
        $current.outOfBoxExperienceSettings.hidePrivacySettings = $true
        $current.outOfBoxExperienceSettings.hideEscapeLink = $true
        $current.hybridAzureADJoinSkipConnectivityCheck = $true
        $current.EnableWhiteGlove = $true
        $current.outOfBoxExperienceSettings.hideEULA = $true 
        $current.outOfBoxExperienceSettings.hidePrivacySettings = $true
        $current.outOfBoxExperienceSettings.hideEscapeLink = $true
        $current.outOfBoxExperienceSettings.skipKeyboardSelectionPage = $true
        $current.outOfBoxExperienceSettings.userType = "administrator"
    }
    elseif ($AllDisabled) {
        $current.extractHardwareHash = $false
        $current.outOfBoxExperienceSettings.hidePrivacySettings = $false
        $current.outOfBoxExperienceSettings.hideEscapeLink = $false
        $current.hybridAzureADJoinSkipConnectivityCheck = $false
        $current.EnableWhiteGlove = $false
        $current.outOfBoxExperienceSettings.hideEULA = $false
        $current.outOfBoxExperienceSettings.hidePrivacySettings = $false
        $current.outOfBoxExperienceSettings.hideEscapeLink = $false
        $current.outOfBoxExperienceSettings.skipKeyboardSelectionPage = $false
        $current.outOfBoxExperienceSettings.userType = "standard"
    }

    # Clean up unneeded properties
    $current.PSObject.Properties.Remove("lastModifiedDateTime")
    $current.PSObject.Properties.Remove("createdDateTime") 
    $current.PSObject.Properties.Remove("@odata.context")
    $current.PSObject.Properties.Remove("id")
    $current.PSObject.Properties.Remove("roleScopeTagIds")

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"
    $json = ($current | ConvertTo-JSON).ToString()
    
    Write-Verbose "PATCH $uri`n$json"

    try {
        Invoke-MSGraphRequest -Url $uri -HttpMethod PATCH -Content $json
    }
    catch {
        Write-Error $_.Exception 
        break
    }

}


Function New-AutopilotProfile(){
<#
.SYNOPSIS
Creates a new Autopilot profile.
 
.DESCRIPTION
The New-AutopilotProfile creates a new Autopilot profile.
 
.PARAMETER displayName
The name of the Windows Autopilot profile to create. (This value cannot contain spaces.)
 
.PARAMETER mode
The type of Autopilot profile to create. Choices are "UserDrivenAAD", "UserDrivenAD", and "SelfDeployingAAD".
 
.PARAMETER description
The description to be configured in the profile. (This value cannot contain dashes.)
     
.PARAMETER ConvertDeviceToAutopilot
Configure the value "Convert all targeted devices to Autopilot"
 
.PARAMETER OOBE_HideEULA
Configure the OOBE option to hide or not the EULA
 
.PARAMETER OOBE_EnableWhiteGlove
Configure the OOBE option to allow or not White Glove OOBE
 
.PARAMETER OOBE_HidePrivacySettings
Configure the OOBE option to hide or not the privacy settings
 
.PARAMETER OOBE_HideChangeAccountOpts
Configure the OOBE option to hide or not the change account options
 
.PARAMETER OOBE_UserTypeAdmin
Configure the user account type as administrator.
 
.PARAMETER OOBE_NameTemplate
Configure the OOBE option to apply a device name template
 
.PARAMETER OOBE_language
The language identifier (e.g. "en-us") to be configured in the profile
 
.PARAMETER OOBE_SkipKeyboard
Configure the OOBE option to skip or not the keyboard selection page
 
.PARAMETER OOBE_HideChangeAccountOpts
Configure the OOBE option to hide or not the change account options
 
.PARAMETER OOBE_SkipConnectivityCheck
Specify whether to skip Active Directory connectivity checks (UserDrivenAAD only)
 
.EXAMPLE
Create profiles of different types:
 
New-AutopilotProfile -mode UserDrivenAAD -displayName "My AAD profile" -description "My user-driven AAD profile" -OOBE_Quiet
New-AutopilotProfile -mode UserDrivenAD -displayName "My AD profile" -description "My user-driven AD profile" -OOBE_Quiet
New-AutopilotProfile -mode SelfDeployingAAD -displayName "My Self Deploying profile" -description "My self-deploying profile" -OOBE_Quiet
 
.EXAMPLE
Create a user-driven AAD profile:
 
New-AutopilotProfile -mode UserDrivenAAD -displayName "My testing profile" -Description "Description of my profile" -OOBE_Language "en-us" -OOBE_HideEULA -OOBE_HidePrivacySettings
 
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$true)][string] $displayName,
    [Parameter(Mandatory=$true)][ValidateSet('UserDrivenAAD','UserDrivenAD','SelfDeployingAAD')][string] $mode, 
    [string] $description,
    [Switch] $ConvertDeviceToAutopilot,
    [string] $OOBE_language,
    [Switch] $OOBE_skipKeyboard,
    [string] $OOBE_NameTemplate,
    [Switch] $OOBE_EnableWhiteGlove,
    [Switch] $OOBE_UserTypeAdmin,
    [Switch] $OOBE_HideEULA,
    [Switch] $OOBE_hidePrivacySettings,
    [Switch] $OOBE_HideChangeAccountOpts,
    [Switch] $OOBE_SkipConnectivityCheck
)

    # Adjust values as needed
    switch ($mode) {
        "UserDrivenAAD" { $odataType = "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile"; $usage = "singleUser" }
        "SelfDeployingAAD" { $odataType = "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile"; $usage = "shared" }
        "UserDrivenAD" { $odataType = "#microsoft.graph.activeDirectoryWindowsAutopilotDeploymentProfile"; $usage = "singleUser" }
    }

    if ($OOBE_UserTypeAdmin)
    {        
        $OOBE_userType = "administrator"
    }
    else 
    {        
        $OOBE_userType = "standard"
    }        

    if ($OOBE_EnableWhiteGlove)
    {        
        $OOBE_HideChangeAccountOpts = $True
    }        
        
    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    if ($mode -eq "UserDrivenAD")
    {
        $json = @"
{
    "@odata.type": "$odataType",
    "displayName": "$displayname",
    "description": "$description",
    "language": "$OOBE_language",
    "extractHardwareHash": $(BoolToString($ConvertDeviceToAutopilot)),
    "deviceNameTemplate": "$OOBE_NameTemplate",
    "deviceType": "windowsPc",
    "enableWhiteGlove": $(BoolToString($OOBE_EnableWhiteGlove)),
    "hybridAzureADJoinSkipConnectivityCheck": $(BoolToString($OOBE_SkipConnectivityChecks)),
    "outOfBoxExperienceSettings": {
        "hidePrivacySettings": $(BoolToString($OOBE_hidePrivacySettings)),
        "hideEULA": $(BoolToString($OOBE_HideEULA)),
        "userType": "$OOBE_userType",
        "deviceUsageType": "$usage",
        "skipKeyboardSelectionPage": $(BoolToString($OOBE_skipKeyboard)),
        "hideEscapeLink": $(BoolToString($OOBE_HideChangeAccountOpts))
    }
}
"@
    }
    else
    {
        $json = @"
{
    "@odata.type": "$odataType",
    "displayName": "$displayname",
    "description": "$description",
    "language": "$OOBE_language",
    "extractHardwareHash": $(BoolToString($ConvertDeviceToAutopilot)),
    "deviceNameTemplate": "$OOBE_NameTemplate",
    "deviceType": "windowsPc",
    "enableWhiteGlove": $(BoolToString($OOBE_EnableWhiteGlove)),
    "outOfBoxExperienceSettings": {
        "hidePrivacySettings": $(BoolToString($OOBE_hidePrivacySettings)),
        "hideEULA": $(BoolToString($OOBE_HideEULA)),
        "userType": "$OOBE_userType",
        "deviceUsageType": "$usage",
        "skipKeyboardSelectionPage": $(BoolToString($OOBE_skipKeyboard)),
        "hideEscapeLink": $(BoolToString($OOBE_HideChangeAccountOpts))
    }
}
"@
    }

    Write-Verbose "POST $uri`n$json"

    try {
        Invoke-MSGraphRequest -Url $uri -HttpMethod POST -Content $json
    }
    catch {
        Write-Error $_.Exception 
        break
    }

}


Function Remove-AutopilotProfile(){
<#
.SYNOPSIS
Remove a Deployment Profile
.DESCRIPTION
The Remove-AutopilotProfile allows you to remove a specific deployment profile
.PARAMETER id
Mandatory, the ID (GUID) of the profile to be removed.
.EXAMPLE
Remove-AutopilotProfile -id $id
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)] $id
)

    Process {
        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"

        Write-Verbose "DELETE $uri"

        Try 
        {
            Invoke-MSGraphRequest -Url $uri -HttpMethod DELETE
        }
        catch 
        {
            Write-Error $_.Exception 
            break
        }
    }
}


Function Get-AutopilotProfileAssignments(){
<#
.SYNOPSIS
List all assigned devices for a specific profile ID
.DESCRIPTION
The Get-AutopilotProfileAssignments cmdlet returns the list of groups that ae assigned to a spcific deployment profile
.PARAMETER id
Type: Integer - Mandatory, the ID (GUID) of the profile to be retrieved.
.EXAMPLE
Get-AutopilotProfileAssignments -id $id
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)] $id
)

    Process {

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assignments"

        Write-Verbose "GET $uri"

        try {
            $response = Invoke-MSGraphRequest -Url $uri -HttpMethod Get
            $Group_ID = $response.Value.target.groupId
            ForEach($Group in $Group_ID)
            {
                Try {
                    Get-AzureADGroup | where {$_.ObjectId -like $Group}
                }
                Catch {
                    $Group
                }            
            }
        }
        catch {
            Write-Error $_.Exception 
            break
        }

    }

}


Function Remove-AutopilotProfileAssignments(){
<#
.SYNOPSIS
Removes a specific group assigntion for a specifc deployment profile
.DESCRIPTION
The Remove-AutopilotProfileAssignments cmdlet allows you to remove a group assignation for a deployment profile
.PARAMETER id
Type: Integer - Mandatory, the ID (GUID) of the profile
.PARAMETER groupid
Type: Integer - Mandatory, the ID of the group
.EXAMPLE
Remove-AutopilotProfileAssignments -id $id
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$true)]$id,
    [Parameter(Mandatory=$true)]$groupid
)
    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
    
    $full_assignment_id = $id + "_" + $groupid + "_0"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assignments/$full_assignment_id"

    Write-Verbose "DELETE $uri"

    try {
        Invoke-MSGraphRequest -Url $uri -HttpMethod DELETE
    }
    catch {
        Write-Error $_.Exception 
        break
    }

}


Function Set-AutopilotProfileAssignedGroup(){
<#
.SYNOPSIS
Assigns a group to a Windows Autopilot profile.
.DESCRIPTION
The Set-AutopilotProfileAssignedGroup cmdlet allows you to assign a specific group to a specific deployment profile
.PARAMETER id
Type: Integer - Mandatory, the ID (GUID) of the profile
.PARAMETER groupid
Type: Integer - Mandatory, the ID of the group
.EXAMPLE
Set-AutopilotProfileAssignedGroup -id $id -groupid $groupid
#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]$id,
        [Parameter(Mandatory=$true)]$groupid
    )
        $full_assignment_id = $id + "_" + $groupid + "_0"  
  
        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assignments"        

$json = @"
{
    "id": "$full_assignment_id",
    "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$groupid"
    }
}
"@

        Write-Verbose "POST $uri`n$json"

        try {
            Invoke-MSGraphRequest -Url $uri -HttpMethod Post -Content $json
        }
        catch {
            Write-Error $_.Exception 
            break
        }
}


Function Get-EnrollmentStatusPage(){
<#
.SYNOPSIS
List enrollment status page
.DESCRIPTION
The Get-EnrollmentStatusPage cmdlet returns available enrollment status page with their options
.PARAMETER id
The ID (GUID) of the status page (optional)
.EXAMPLE
Get-EnrollmentStatusPage
#>

[cmdletbinding()]
param
(
    [Parameter()] $id
)

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceEnrollmentConfigurations"

    if ($id) {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"
    }
    else {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    }

    Write-Verbose "GET $uri"

    try {
        $response = Invoke-MSGraphRequest -Url $uri -HttpMethod Get
        if ($id) {
            $response
        }
        else {
            $response.Value | ? { $_.'@odata.type' -eq "#microsoft.graph.windows10EnrollmentCompletionPageConfiguration" }
        }
    }
    catch {
        Write-Error $_.Exception 
        break
    }

}


Function Add-EnrollmentStatusPage(){
<#
.SYNOPSIS
Adds a new Windows Autopilot Enrollment Status Page.
.DESCRIPTION
The Add-EnrollmentStatusPage cmdlet sets properties on an existing Autopilot profile.
.PARAMETER DisplayName
Type: String - Configure the display name of the enrollment status page
.PARAMETER description
Type: String - Configure the description of the enrollment status page
.PARAMETER HideProgress
Type: Boolean - Configure the option: Show app and profile installation progress
.PARAMETER AllowCollectLogs
Type: Boolean - Configure the option: Allow users to collect logs about installation errors
.PARAMETER Message
Type: String - Configure the option: Show custom message when an error occurs
.PARAMETER AllowUseOnFailure
Type: Boolean - Configure the option: Allow users to use device if installation error occurs
.PARAMETER AllowResetOnError
Type: Boolean - Configure the option: Allow users to reset device if installation error occurs
.PARAMETER BlockDeviceUntilComplete
Type: Boolean - Configure the option: Block device use until all apps and profiles are installed
.PARAMETER TimeoutInMinutes
Type: Integer - Configure the option: Show error when installation takes longer than specified number of minutes
.EXAMPLE
Add-EnrollmentStatusPage -Message "Oops an error occured, please contact your support" -HideProgress $True -AllowResetOnError $True
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$True)][string]$DisplayName,
    [string]$Description,        
    [bool]$HideProgress,    
    [bool]$AllowCollectLogs,
    [bool]$blockDeviceSetupRetryByUser,    
    [string]$Message,    
    [bool]$AllowUseOnFailure,
    [bool]$AllowResetOnError,    
    [bool]$BlockDeviceUntilComplete,                
    [Int]$TimeoutInMinutes        
)

    If($HideProgress -eq $False)
        {
            $blockDeviceSetupRetryByUser = $true
        }

    If(($Description -eq $null))
        {
            $Description = $EnrollmentPage_Description
        }        

    If(($DisplayName -eq $null))
        {
            $DisplayName = ""
        }    

    If(($TimeoutInMinutes -eq ""))
        {
            $TimeoutInMinutes = "60"
        }                

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceEnrollmentConfigurations"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $json = @"
{
    "@odata.type": "#microsoft.graph.windows10EnrollmentCompletionPageConfiguration",
    "displayName": "$DisplayName",
    "description": "$description",
    "showInstallationProgress": "$hideprogress",
    "blockDeviceSetupRetryByUser": "$blockDeviceSetupRetryByUser",
    "allowDeviceResetOnInstallFailure": "$AllowResetOnError",
    "allowLogCollectionOnInstallFailure": "$AllowCollectLogs",
    "customErrorMessage": "$Message",
    "installProgressTimeoutInMinutes": "$TimeoutInMinutes",
    "allowDeviceUseOnInstallFailure": "$AllowUseOnFailure",
}
"@

    Write-Verbose "POST $uri`n$json"

    try {
        Invoke-MSGraphRequest -Url $uri -HttpMethod Post -Content $json
    }
    catch {
        Write-Error $_.Exception 
        break
    }

}


Function Set-EnrollmentStatusPage(){
<#
.SYNOPSIS
Sets Windows Autopilot Enrollment Status Page properties.
.DESCRIPTION
The Set-EnrollmentStatusPage cmdlet sets properties on an existing Autopilot profile.
.PARAMETER id
The ID (GUID) of the profile to be updated.
.PARAMETER DisplayName
Type: String - Configure the display name of the enrollment status page
.PARAMETER description
Type: String - Configure the description of the enrollment status page
.PARAMETER HideProgress
Type: Boolean - Configure the option: Show app and profile installation progress
.PARAMETER AllowCollectLogs
Type: Boolean - Configure the option: Allow users to collect logs about installation errors
.PARAMETER Message
Type: String - Configure the option: Show custom message when an error occurs
.PARAMETER AllowUseOnFailure
Type: Boolean - Configure the option: Allow users to use device if installation error occurs
.PARAMETER AllowResetOnError
Type: Boolean - Configure the option: Allow users to reset device if installation error occurs
.PARAMETER BlockDeviceUntilComplete
Type: Boolean - Configure the option: Block device use until all apps and profiles are installed
.PARAMETER TimeoutInMinutes
Type: Integer - Configure the option: Show error when installation takes longer than specified number of minutes
.EXAMPLE
Set-EnrollmentStatusPage -id $id -Message "Oops an error occured, please contact your support" -HideProgress $True -AllowResetOnError $True
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)] $id,
    [string]$DisplayName,    
    [string]$Description,        
    [bool]$HideProgress,
    [bool]$AllowCollectLogs,
    [string]$Message,    
    [bool]$AllowUseOnFailure,
    [bool]$AllowResetOnError,    
    [bool]$AllowUseOnError,    
    [bool]$BlockDeviceUntilComplete,                
    [Int]$TimeoutInMinutes        
)

    Process {

        # LIST EXISTING VALUES FOR THE SELECTING STAUS PAGE
        # Default profile values
        $EnrollmentPage_Values = Get-EnrollmentStatusPage -ID $id
        $EnrollmentPage_DisplayName = $EnrollmentPage_Values.displayName
        $EnrollmentPage_Description = $EnrollmentPage_Values.description
        $EnrollmentPage_showInstallationProgress = $EnrollmentPage_Values.showInstallationProgress
        $EnrollmentPage_blockDeviceSetupRetryByUser = $EnrollmentPage_Values.blockDeviceSetupRetryByUser
        $EnrollmentPage_allowDeviceResetOnInstallFailure = $EnrollmentPage_Values.allowDeviceResetOnInstallFailure
        $EnrollmentPage_allowLogCollectionOnInstallFailure = $EnrollmentPage_Values.allowLogCollectionOnInstallFailure
        $EnrollmentPage_customErrorMessage = $EnrollmentPage_Values.customErrorMessage
        $EnrollmentPage_installProgressTimeoutInMinutes = $EnrollmentPage_Values.installProgressTimeoutInMinutes
        $EnrollmentPage_allowDeviceUseOnInstallFailure = $EnrollmentPage_Values.allowDeviceUseOnInstallFailure

        If(!($HideProgress))
        {
            $HideProgress = $EnrollmentPage_showInstallationProgress
        }    
    
        If(!($BlockDeviceUntilComplete))    
        {
            $BlockDeviceUntilComplete = $EnrollmentPage_blockDeviceSetupRetryByUser
        }        
        
        If(!($AllowCollectLogs))    
        {
            $AllowCollectLogs = $EnrollmentPage_allowLogCollectionOnInstallFailure
        }            
    
        If(!($AllowUseOnFailure))    
        {
            $AllowUseOnFailure = $EnrollmentPage_allowDeviceUseOnInstallFailure
        }    

        If(($Message -eq ""))
        {
            $Message = $EnrollmentPage_customErrorMessage
        }        
        
        If(($Description -eq $null))
        {
            $Description = $EnrollmentPage_Description
        }        

        If(($DisplayName -eq $null))
        {
            $DisplayName = $EnrollmentPage_DisplayName
        }    

        If(!($AllowResetOnError))    
        {
            $AllowResetOnError = $EnrollmentPage_allowDeviceResetOnInstallFailure
        }    

        If(($TimeoutInMinutes -eq ""))
        {
            $TimeoutInMinutes = $EnrollmentPage_installProgressTimeoutInMinutes
        }                

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/deviceEnrollmentConfigurations"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"
        $json = @"
{
    "@odata.type": "#microsoft.graph.windows10EnrollmentCompletionPageConfiguration",
    "displayName": "$DisplayName",
    "description": "$description",
    "showInstallationProgress": "$HideProgress",
    "blockDeviceSetupRetryByUser": "$BlockDeviceUntilComplete",
    "allowDeviceResetOnInstallFailure": "$AllowResetOnError",
    "allowLogCollectionOnInstallFailure": "$AllowCollectLogs",
    "customErrorMessage": "$Message",
    "installProgressTimeoutInMinutes": "$TimeoutInMinutes",
    "allowDeviceUseOnInstallFailure": "$AllowUseOnFailure"
}
"@

        Write-Verbose "PATCH $uri`n$json"

        try {
            Invoke-MSGraphRequest -Url $uri -HttpMethod PATCH -Content $json
        }
        catch {
            Write-Error $_.Exception 
            break
        }

    }

}


Function Remove-EnrollmentStatusPage(){
<#
.SYNOPSIS
Remove a specific enrollment status page
.DESCRIPTION
The Remove-EnrollmentStatusPage allows you to remove a specific enrollment status page
.PARAMETER id
Mandatory, the ID (GUID) of the profile to be retrieved.
.EXAMPLE
Remove-EnrollmentStatusPage -id $id
#>
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)] $id
)

    Process {

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/deviceEnrollmentConfigurations"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"

        Write-Verbose "DELETE $uri"

        try {
            Invoke-MSGraphRequest -Url $uri -HttpMethod DELETE
        }
        catch {
            Write-Error $_.Exception 
            break
        }

    }

}


Function Invoke-AutopilotSync(){
<#
.SYNOPSIS
Initiates a synchronization of Windows Autopilot devices between the Autopilot deployment service and Intune.
 
.DESCRIPTION
The Invoke-AutopilotSync cmdlet initiates a synchronization between the Autopilot deployment service and Intune.
This can be done after importing new devices, to ensure that they appear in Intune in the list of registered
Autopilot devices. See https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/api/intune_enrollment_windowsautopilotsettings_sync
for more information.
 
.EXAMPLE
Initiate a synchronization.
 
Invoke-AutopilotSync
#>
[cmdletbinding()]
param
(
)
    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotSettings/sync"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

    Write-Verbose "POST $uri"

    try {
        Invoke-MSGraphRequest -Url $uri -HttpMethod Post
    }
    catch {
        Write-Error $_.Exception 
        break
    }

}

Function Get-AutopilotSyncInfo(){
    <#
    .SYNOPSIS
    Returns details about the last Autopilot sync.
     
    .DESCRIPTION
    The Get-AutopilotSyncInfo cmdlet retrieves details about the sync status between Intune and the Autopilot service.
    See https://docs.microsoft.com/en-us/graph/api/resources/intune-enrollment-windowsautopilotsettings?view=graph-rest-beta
    for more information.
     
    .EXAMPLE
    Get-AutopilotSyncInfo
    #>
    [cmdletbinding()]
    param
    (
    )
        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotSettings"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    
        Write-Verbose "GET $uri"
    
        try {
            Invoke-MSGraphRequest -Url $uri -HttpMethod Get
        }
        catch {
            Write-Error $_.Exception 
            break
        }
    
    }
    
#endregion


Function Import-AutopilotCSV(){
<#
.SYNOPSIS
Adds a batch of new devices into Windows Autopilot.
 
.DESCRIPTION
The Import-AutopilotCSV cmdlet processes a list of new devices (contained in a CSV file) using a several of the other cmdlets included in this module. It is a convenient wrapper to handle the details. After the devices have been added, the cmdlet will continue to check the status of the import process. Once all devices have been processed (successfully or not) the cmdlet will complete. This can take several minutes, as the devices are processed by Intune as a background batch process.
 
.PARAMETER csvFile
The file containing the list of devices to be added.
 
.PARAMETER groupTag
An optional identifier or tag that can be associated with this device, useful for grouping devices using Azure AD dynamic groups. This value overrides an Group Tag value specified in the CSV file.
 
.EXAMPLE
Add a batch of devices to Windows Autopilot for the current Azure AD tenant.
 
Import-AutopilotCSV -csvFile C:\Devices.csv
#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)] $csvFile,
        [Parameter(Mandatory=$false)] [Alias("orderIdentifier")] $groupTag = ""
    )
    
        # Read CSV and process each device
        $devices = Import-CSV $csvFile
        $importedDevices = @()
        foreach ($device in $devices) {
            if ($groupTag -ne "")
            {
                $o = $groupTag
            }
            elseif ($device.'Group Tag' -ne "")
            {
                $o = $device.'Group Tag'
            }
            else
            {
                $o = $device.'OrderID'
            }
            Add-AutopilotImportedDevice -serialNumber $device.'Device Serial Number' -hardwareIdentifier $device.'Hardware Hash' -groupTag $o -assignedUser $device.'Assigned User'
        }

        # While we could keep a list of all the IDs that we added and then check each one, it is
        # easier to just loop through all of them
        $processingCount = 1
        while ($processingCount -gt 0)
        {
            $deviceStatuses = @(Get-AutopilotImportedDevice)
            $deviceCount = $deviceStatuses.Length

            # Check to see if any devices are still processing
            $processingCount = 0
            foreach ($device in $deviceStatuses){
                if ($device.state.deviceImportStatus -eq "unknown") {
                    $processingCount = $processingCount + 1
                }
            }
            Write-Host "Waiting for $processingCount of $deviceCount"

            # Still processing? Sleep before trying again.
            if ($processingCount -gt 0){
                Start-Sleep 15
            }
        }

        # Display the statuses
        $deviceStatuses | ForEach-Object {
            Write-Host "Serial number $($_.serialNumber): $($_.state.deviceImportStatus) $($_.state.deviceErrorCode) $($_.state.deviceErrorName)"
        }

        # Cleanup the imported device records
        $deviceStatuses | ForEach-Object {
            Remove-AutopilotImportedDevice -id $_.id
        }
}


Function Get-AutopilotEvent(){
<#
.SYNOPSIS
Gets Windows Autopilot deployment events.
 
.DESCRIPTION
The Get-AutopilotEvent cmdlet retrieves the list of deployment events (the data that you would see in the "Autopilot deployments" report in the Intune portal).
 
.EXAMPLE
Get a list of all Windows Autopilot events
 
Get-AutopilotEvent
#>
    [cmdletbinding()]
    param
    (
    )

    Process {

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/autopilotEvents"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        try {
            $response = Invoke-MSGraphRequest -Url $uri -HttpMethod Get
            $devices = $response.value
            $devicesNextLink = $response."@odata.nextLink"
    
            while ($devicesNextLink -ne $null){
                $devicesResponse = (Invoke-MSGraphRequest -Url $devicesNextLink -HttpMethod Get)
                $devicesNextLink = $devicesResponse."@odata.nextLink"
                $devices += $devicesResponse.value
            }
    
            $devices
        }
        catch {
            Write-Error $_.Exception 
            break
        }
    }
}
