Function Get-IntuneDeviceNotes{
    <#
    .SYNOPSIS
    Gets the notes of a device in intune.
    
    .DESCRIPTION
    Gets the notes property on a device in intune using the beta Graph api
    
    .PARAMETER DeviceName
    The name of the device that you want to get the notes field from as it appears in intune.
    
    .EXAMPLE
    Get-IntuneDeviceNotes -DeviceName TestDevice01
    
    .NOTES
    Must connect to the graph api first with Connect-MSGraph.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $DeviceName
    )
    Try {
        $DeviceID = (Get-IntuneManagedDevice -filter "deviceName eq '$DeviceName'" -ErrorAction Stop).id
    }
    Catch {
        Write-Error $_.Exception.Message
        break
    }
    $deviceId = (Get-IntuneManagedDevice -Filter "deviceName eq 'BeesKnees'").id
    $Resource = "deviceManagement/managedDevices('$deviceId')"
    $properties = 'notes'
    $uri = "https://graph.microsoft.com/beta/$($Resource)?select=$properties"
    Try{
        (Invoke-MSGraphRequest -HttpMethod GET -Url $uri -ErrorAction Stop).notes
    }
    Catch{
        Write-Error $_.Exception.Message
        break
    }
}
