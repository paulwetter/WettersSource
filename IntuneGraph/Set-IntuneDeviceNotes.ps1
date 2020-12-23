Function Set-IntuneDeviceNotes{
    <#
    .SYNOPSIS
    Sets the notes on a device in intune.
    
    .DESCRIPTION
    Sets the notes property on a device in intune using the beta api
    
    .PARAMETER DeviceName
    The name of the device as it appears in intune.
    
    .PARAMETER Notes
    A string of the notes that you would like recorded in the notes field in intune.
    
    .EXAMPLE
    Set-IntuneDeviceNotes -DeviceName TestDevice01 -Notes "This is a note on the stuff and things for this device."
    
    .NOTES
    Must connect to the graph api first with Connect-MSGraph.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $DeviceName,
        [Parameter(Mandatory=$false)]
        [String]
        $Notes
    )
    Try {
        $DeviceID = (Get-IntuneManagedDevice -filter "deviceName eq '$DeviceName'" -ErrorAction Stop).id
    }
    Catch{
        Write-Host 'Failed to query device' -f Red
        Write-Host $_.Exception.Message -f Red
        Write-Host $_.Exception.ItemName -f Red
        break        
    }
    If (![string]::IsNullOrEmpty($DeviceID)){
        $Resource = "deviceManagement/managedDevices('$DeviceID')"
        $GraphApiVersion = "Beta"
        $URI = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
        $JSONPayload = @"
{
notes:"$Notes"
}
"@
        Try{
            Write-Verbose "$URI"
            Write-Verbose "$JSONPayload"
            Invoke-MSGraphRequest -HttpMethod PATCH -Url $uri -Content $JSONPayload -Verbose -ErrorAction Stop
        }
        Catch{
            Write-Host 'Failed to update device' -f Red
            Write-Host $_.Exception.Message -f Red
            Write-Host $_.Exception.ItemName -f Red
            break        
        }
    }
}
