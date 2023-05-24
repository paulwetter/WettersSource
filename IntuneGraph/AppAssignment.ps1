[CmdletBinding(DefaultParameterSetName="GroupID")]
param (
    [Parameter(ParameterSetName="GroupID", Mandatory=$true)]
    [guid]
    $GroupID,
    [Parameter(ParameterSetName="AllDevice", Mandatory=$false)]
    [switch]
    $AllDevice,
    [Parameter(ParameterSetName="AllDevice", Mandatory=$false)]
    [Parameter(ParameterSetName="GroupID", Mandatory=$false)]
    [ValidateSet("showReboot","hideAll","showAll")]
    [string]
    $Notification = "showReboot",
    [Parameter(ParameterSetName="AllDevice", Mandatory=$false)]
    [Parameter(ParameterSetName="GroupID", Mandatory=$false)]
    [string]
    $AppFilter
)


function New-PWRequiredAppAssignment {
    [CmdletBinding()]
    param (
        [guid]
        $GroupID,
        [ValidateSet("showReboot","hideAll","showAll")]
        [string]
        $Notification = "showReboot",
        [switch]
        $AllDevice,
        $ExistingAssignments
    )
    $assignment = [pscustomobject]@{
        "mobileAppAssignments" = [System.Collections.Generic.List[pscustomobject]](
            [pscustomobject]@{
                '@odata.type' = '#microsoft.graph.mobileAppAssignment'
                intent = 'Required'
                target = [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    'groupId' = $GroupID
                }
                settings = [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.win32LobAppAssignmentSettings'
                    'notifications' = $Notification
                    'restartSettings' = $null
                    'installTimeSettings' = $null
                    'deliveryOptimizationPriority' = 'notConfigured'
                }
            }
        )
    }
    if ($AllDevice){
        $assignment.mobileAppAssignments[0].target = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'
        }
    }
    if ($ExistingAssignments) {
        foreach ($OldAssignment in $ExistingAssignments){
            $assignment.mobileAppAssignments.Add(
                [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.mobileAppAssignment'
                    intent = $OldAssignment.intent
                    target = $OldAssignment.target
                    settings = $OldAssignment.settings
                }
            )    
        }
    }
    return $assignment|ConvertTo-Json -Depth 99 -Compress
}

function New-PWLobAppAssignment {
    [CmdletBinding()]
    param (
        [guid]
        $AppID,
        [string]
        $Assignment
    )
    
    $AssignSplat = @{
        'HttpMethod'  = "POST"
        'Url' = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$AppID/assign"
        'Content' =  "$Assignment"
    }
    Invoke-MSGraphRequest @AssignSplat
}

function Get-PWLobApps {
    [CmdletBinding()]
    param (
        [string]
        $AppNameFilter
    )
    $LOBApps =  (Invoke-MSGraphRequest -HttpMethod GET -Url https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/).value|Where {$_.'@odata.type' -like '#microsoft.graph.win32LobApp'}
    If (!([string]::IsNullOrEmpty($AppNameFilter))){
        $Apps = $LOBApps | Where-Object {$_.displayName -like "*$AppNameFilter*"}
    } else {
        $Apps = $LOBApps
    }
    return $Apps
}


function Get-PWLobAppAssignment {
    [CmdletBinding()]
    param (
        [guid]
        $AppID
    )
    
    $AssignSplat = @{
        'HttpMethod'  = "GET"
        'Url' = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$AppID/assignments"
        ErrorAction = 'Stop'
    }
    $assignments = Invoke-MSGraphRequest @AssignSplat
    $assignments.value
}

Write-Host "Connecting to Graph.."
try {Connect-MSGraph -ErrorAction Stop}
Catch {throw "Failed to connect to gragh. error: $_"}
Write-Host "Getting all LOB apps..."
try {
    if ($AppFilter){
        $Apps = @(Get-PWLobApps -AppNameFilter $AppFilter -ErrorAction Stop)
    } else {
        $Apps = @(Get-PWLobApps -ErrorAction Stop)
    }
}
Catch {throw "Failed to get apps. error: $_"}
write-host "Found [$($Apps.count)] apps."
$SelectedApps = @($Apps|Out-GridView -Title "Select Apps to Deploy to" -PassThru)
write-host "Select [$($SelectedApps.count)] apps for deployment."
foreach ($SelectedApp in $SelectedApps) {
    Write-Host "Creating deployment for app [$($SelectedApp.displayName)]"
    $ExistingAssignments = Get-PWLobAppAssignment -AppID $SelectedApp.id
    $AddAssignmentSplat = @{}
    if ($ExistingAssignments){
        $AddAssignmentSplat.Add('ExistingAssignments', $ExistingAssignments)
        $AddAssignmentSplat.Add('ErrorAction',"Stop")
    }
    if ($GroupID){
        $AddAssignmentSplat.Add('GroupID',"$GroupID")
    }
    if ($AllDevice){
        $AddAssignmentSplat.Add('AllDevice', $true)
    }
    try {
        $assignments = New-PWRequiredAppAssignment @AddAssignmentSplat
    }
    catch {
        Write-Warning "failed to create assignment json for app [$($SelectedApp.displayName)]"
        continue
    }
    try {
        New-PWLobAppAssignment -AppID $SelectedApp.id -Assignment $assignments -ErrorAction Stop
        Write-Host "Assigned Group to application successfully."
    }
    catch {
        Write-Warning "Failed to assign group [$groupid] to application [$($SelectedApp.displayName)]"
    }
}
