function Get-pwListDifferences {
    <#
    .SYNOPSIS
    Gets a hashtable that contains 2 lists. Removal and Addition.
    
    .DESCRIPTION
    Gets a hashtable that contains 2 lists. Removal and Addition.
    Removal is a list of items that should be removed from the destination table/list.  These items no longer exist in the source but still exist in the destination.
    Addition is a list of items that should be added to the destination table/list.  These items exist in the source but do not exist in the destination.
    
    .PARAMETER Source
    The source list of items as a hashtable.
    
    .PARAMETER Destination
    The destination list of items as a hashtable.
    
    .PARAMETER Fields
    A hashtable that has the field mapping of the destination to the source.
    
    .EXAMPLE
    $FieldMap = @{'Name' = 'Title'; 'Age' = 'AgeInYears'}
    $List = @{1 = [pscustomobject]@{Name='Bob';Age=27};2 = [pscustomobject]@{Name='Dave';Age=55};}
    $Dest = @{1 = [pscustomobject]@{Name='Bob';Age=29};2 = [pscustomobject]@{Name='Dave';Age=55};}
    Get-pwListDifferences -Source $list -Destination $dest -FieldMap $FieldMap
    
    .NOTES
    General notes
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]
        $Source,
        [Parameter(Mandatory=$true)]
        [hashtable]
        $Destination,
        [Parameter(Mandatory=$true)]
        [string[]]
        $Fields
    )
    # initialize the results as an hash of 2 empty lists
    $results = @{
        'Addition' = New-Object System.Collections.Generic.List[Object]
        'Removal'  = New-Object System.Collections.Generic.List[Object]
    }
    
    #region Make sure the hash tables are sequential.
    $FreshSource = @{}
    $FreshDestination = @{}
    [int]$Ctr = 0
    foreach($SV in $Source.Values) {
        $Ctr++
        $FreshSource.Add($Ctr, $SV)
    }
    [int]$Ctr = 0
    foreach($DV in $Destination.Values) {
        $Ctr++
        $FreshDestination.Add($Ctr, $DV)
    }
    #endregion

    #clone the hashtables to use for self eliminating lists.
    $AddToList = $FreshSource.Clone()
    $RemoveFromList = $FreshDestination.Clone()

    # For loop to find items to add
    for ($i = 1; $i -le $FreshSource.Count; $i++) {
        Write-Verbose "Checking for additions: $i"
        $row = $FreshSource.$i
        $match = $false
        foreach ($j in $FreshDestination.Values){
            foreach ($p in $Fields){
                if ($p -eq "id") {Continue}
                if ($j.$p -eq $row.$p){
                    $match = $true
                } else {
                    $match = $false
                    break
                }
            }
            If ($match -eq $true){
                Write-Verbose "Match $i : $($row.$p)"
                $AddToList.Remove($i)
            }
        }
    }

    # For loop to find items to remove
    for ($i = 1; $i -le $FreshDestination.Count; $i++) {
        Write-Verbose "Checking for Removals: $i"
        $row = $FreshDestination.$i
        $match = $false
        foreach ($j in $FreshSource.Values){
            foreach ($p in $Fields){
                if ($p -eq "id") {Continue}
                if ($j.$p -eq $row.$p){
                    $match = $true
                } else {
                    $match = $false
                    break
                }
            }
            If ($match -eq $true){
                Write-Verbose "Match $i : $($row.$p)"
                $RemoveFromList.Remove($i)
            }
        }
    }
    foreach($AddTo in $AddToList.Values) {
        $results.Addition.Add($AddTo)
    }
    foreach($RemoveFrom in $RemoveFromList.Values) {
        $results.Removal.Add($RemoveFrom)
    }
    return $results
}
