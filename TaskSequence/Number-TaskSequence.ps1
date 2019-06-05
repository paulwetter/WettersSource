Function Set-PWSequenceStepNumbers {
    [CmdletBinding()]
    param ($Sequence, $GroupName, $StepCounter = 0)
    Write-Verbose "Starting Run: $StepCounter"
    foreach ($node in $Sequence.ChildNodes) {
        switch ($node.localname) {
            'step' {
                $StepCounter++
                Write-Verbose "$StepCounter --- STEP --- $($Node.Name)"
                if ($GroupName) {
                    $newname = "$($Node.name)" -replace '[0-9]*\. ', ''
                    $Node.name = Set-MaxLength -Str "$($StepCounter). $newname" -Length 50
                    $TSStep = New-Object -TypeName psobject -Property @{'StepNumber' = $StepCounter; 'GroupName' = "$GroupName"; 'StepName' = "$($node.Name)" }
                }
                else {
                    $newname = "$($Node.name)" -replace '[0-9]*\. ', ''
                    $Node.name = Set-MaxLength -Str "$($StepCounter). $newname" -Length 50
                    $TSStep = New-Object -TypeName psobject -Property @{'StepNumber' = $StepCounter; 'GroupName' = "N/A"; 'StepName' = "$($node.Name)" }
                }
                $TSStep
            }
            'subtasksequence' {
                if ([string]::IsNullOrEmpty($node.disable)) {
                    if ((Get-IsParentGroupDisabled -TSXml $node) -ne $true) {
                        $StepCounter++
                        Write-Verbose "$StepCounter --- SUBTS --- $($Node.Name)"
                        $SubTSPackageID = $(foreach ($var in $Node.defaultVarList.variable) { if ($Var.property -like 'TsPackageID') { $var.'#text' } })
                        $SubSequence = Get-PWTSXml -TSPackageID "$SubTSPackageID"
                        $SubTaskSequenceXML = Set-PWSequenceStepNumbers -Sequence $SubSequence
                        $SubTSFinalStepNumber = ($SubTaskSequenceXML.stepnumber | Measure-Object -Maximum).Maximum
                        if ($GroupName) {
                            $newname = "$($Node.name)" -replace '[0-9]*\. ', ''
                            $Node.name = Set-MaxLength -Str "$($StepCounter). $newname" -Length 50
                            $StepCounter = $StepCounter + $SubTSFinalStepNumber
                            $TSStep = New-Object -TypeName psobject -Property @{'StepNumber' = $StepCounter; 'GroupName' = "$GroupName"; 'StepName' = "$($node.Name)" }
                        }
                        else {
                            $newname = "$($Node.name)" -replace '[0-9]*\. ', ''
                            $Node.name = Set-MaxLength -Str "$($StepCounter). $newname" -Length 50
                            $StepCounter = $StepCounter + $SubTSFinalStepNumber
                            $TSStep = New-Object -TypeName psobject -Property @{'StepNumber' = $StepCounter; 'GroupName' = "N/A"; 'StepName' = "$($node.Name)" }
                        }
                        $TSStep
                    }
                    else {
                        $StepCounter--
                    }
                }
                else {
                    $StepCounter--
                }
            }
            'group' {
                $StepCounter++
                Write-Verbose "$StepCounter --- GROUP --- $($Node.Name) --- Start"
                $newname = "$($Node.name)" -replace '[0-9]*\. ', ''
                $Node.name = Set-MaxLength -Str "$($StepCounter). $newname" -Length 50
                $TSStep = New-Object -TypeName psobject -Property @{'StepNumber' = $StepCounter; 'GroupName' = "$($node.Name)"; 'StepName' = "N/A" }
                #$TSStep
                $NextSteps = Set-PWSequenceStepNumbers -Sequence $node -GroupName "$($node.Name)" -StepCounter $StepCounter
                If ($NextSteps) {
                    foreach ($NextStep in $NextSteps) { Write-Verbose $NextStep.StepNumber }
                    $StepCounter = ($NextSteps.StepNumber | Measure-Object -Maximum).Maximum
                }
                Write-Verbose "$StepCounter --- GROUP --- $($Node.Name) --- BeforeINC"
                $StepCounter++
                Write-Verbose "$StepCounter --- GROUP --- $($Node.Name) --- END"
                $TSStep = New-Object -TypeName psobject -Property @{'StepNumber' = $StepCounter; 'GroupName' = "$($node.Name)"; 'StepName' = "N/A" }
                $TSStep
            }
            'sequence' {
                if ($StepCounter -ne 0) { $StepCounter++ }
                Write-Verbose "$StepCounter --- SEQU --- $($Node.Name)"
                $NextSteps = Set-PWSequenceStepNumbers -Sequence $node -GroupName "$($node.Name)" -StepCounter $StepCounter
                $NextSteps
                if ($StepCounter -ne 0) {
                    $StepCounter = ($NextSteps.StepNumber | Measure-Object -Maximum).Maximum
                    $StepCounter++
                }
                Write-Verbose "$StepCounter --- SEQU --- $($Node.Name) --- END"
            }
            default { }
        }
    }
    Write-Verbose "Ending Run: $StepCounter"
}

function Set-MaxLength {
    param (
        [parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [string] $Str,
        [parameter(Mandatory = $True, Position = 1)]
        [int] $Length
    )
    $Str[0..($Length - 1)] -join ""
}

Function Get-PWTSXml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TSPackageID,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$SiteServer = 'localhost',
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$SiteCode = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM\CcmEval -Name LastSiteCode -ErrorAction SilentlyContinue).LastSiteCode
    )

    # Get SMS_TaskSequencePackage WMI object
    $TaskSequencePackage = Get-WmiObject -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Filter "PackageID like `'$TSPackageID`'"
    $TaskSequencePackage.Get()
    # Get SMS_TaskSequence WMI object from TaskSequencePackage
    $TaskSequence = Invoke-WmiMethod -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Name "GetSequence" -ArgumentList $TaskSequencePackage
    # Convert WMI object to XML
    $TaskSequenceResult = Invoke-WmiMethod -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequence -ComputerName $SiteServer -Name "SaveToXml" -ArgumentList $TaskSequence.TaskSequence
    $TaskSequenceXML = $TaskSequenceResult.ReturnValue
    [xml]$TaskSequenceXML
}

Function Set-PWTSXml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TSPackageID,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [xml]$TSXml,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$SiteServer = 'localhost',
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$SiteCode = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM\CcmEval -Name LastSiteCode -ErrorAction SilentlyContinue).LastSiteCode
    )
    # Get SMS_TaskSequencePackage WMI object
    $TaskSequencePackage = Get-WmiObject -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Filter "PackageID like `'$TSPackageID`'"
    $TaskSequencePackage.Get()
    # Convert XML back to SMS_TaskSequencePackage WMI object
    $XMLString = $TSXml.OuterXml
    Write-Verbose "Invoke-WmiMethod -Namespace `"root\SMS\site_$($SiteCode)`" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Name `"ImportSequence`" -ArgumentList `"$XMLString`""
    $TaskSequenceResult = Invoke-WmiMethod -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Name "ImportSequence" -ArgumentList "$XMLString"

    # Update SMS_TaskSequencePackage WMI object
    Write-Verbose "Invoke-WmiMethod -Namespace `"root\SMS\site_$($SiteCode)`" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Name `"SetSequence`" -ArgumentList @($($TaskSequenceResult.TaskSequence), $TaskSequencePackage)"
    Invoke-WmiMethod -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Name "SetSequence" -ArgumentList @($TaskSequenceResult.TaskSequence, $TaskSequencePackage)
}

Function Get-IsParentGroupDisabled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $TSXml
    )
    Write-Verbose "Checking the elements parent: $($tsxml.Name)"
    IF ($null -ne $tsxml.ParentNode) {
        Write-Verbose "Is disabled: $($tsxml.ParentNode.Disable)"
        If ($tsxml.ParentNode.Disable -eq "true") {
            Return $true
        }
        else {
            Write-Verbose "Checking into this parent: $($tsxml.ParentNode.Name)"
            Get-IsParentGroupDisabled -TSXml $tsxml.ParentNode
        }
    }
}


$Sequence = Get-PWTSXml -TSPackageID "MMS00019"

$NewTaskSequenceXML = Set-PWSequenceStepNumbers -Sequence $Sequence

Set-PWTSXml -TSPackageID "MMS00019" -TSXml $Sequence





$Sequence = Get-PWTSXml -TSPackageID "MMS00016"

$NewTaskSequenceXML = Set-PWSequenceStepNumbers -Sequence $Sequence

Set-PWTSXml -TSPackageID "MMS00016" -TSXml $Sequence





<# 
$SiteServer = "localhost"
$SiteCode = "MMS"
$PackageID = "MMS00016"

# Get SMS_TaskSequencePackage WMI object
$TaskSequencePackage = Get-WmiObject -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Filter "PackageID like `'$PackageID`'"
$TaskSequencePackage.Get()
 
# Get SMS_TaskSequence WMI object from TaskSequencePackage
$TaskSequence = Invoke-WmiMethod -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Name "GetSequence" -ArgumentList $TaskSequencePackage
 
# Convert WMI object to XML
$TaskSequenceResult = Invoke-WmiMethod -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequence -ComputerName $SiteServer -Name "SaveToXml" -ArgumentList $TaskSequence.TaskSequence
$TaskSequenceXML = $TaskSequenceResult.ReturnValue
$Sequence = [xml]$TaskSequenceXML
$NewTaskSequenceXML = Set-PWSequenceStepNumbers -Sequence $Sequence

# Convert XML back to SMS_TaskSequencePackage WMI object
$TaskSequenceResult = Invoke-WmiMethod -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Name "ImportSequence" -ArgumentList $Sequence.OuterXml
 
# Update SMS_TaskSequencePackage WMI object
Invoke-WmiMethod -Namespace "root\SMS\site_$($SiteCode)" -Class SMS_TaskSequencePackage -ComputerName $SiteServer -Name "SetSequence" -ArgumentList @($TaskSequenceResult.TaskSequence, $TaskSequencePackage)
 #>