[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PackageID,
	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
    [string]$SiteCode = (New-Object -ComObject Microsoft.SMS.Client -Strict).GetAssignedSite(),
	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
    [string]$PrimarySiteServer='localhost'
)

# Get the XML from a Task Sequence
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
        [string]$SiteCode = (New-Object -ComObject Microsoft.SMS.Client -Strict).GetAssignedSite()
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

# Get all of the Variables used in the conditions of a step and return only the variable name.
function Get-ConditionVariables{
    param ($condition)
    If($condition.osConditionGroup){
        # Don't care about this condition type. Just collecting variables.
    }
    If($condition.expression){
        foreach ($expression in $condition.expression){
            #$expression
            switch ($expression.type){
                'SMS_TaskSequence_VariableConditionExpression'{
                    foreach ($pair in $expression.variable){
                        # There are three name/value pairs: Operator, Value, Variable
                        # We only care about the Variable pair as this contains the name of the variable.
                        if ($pair.name -eq 'Variable'){
                            $pair.'#text'
                        }
                    }
                    # Remove-Variable ExpVariable -ErrorAction Ignore
                }
                'SMS_TaskSequence_WMIConditionExpression' {
                    # Don't care about this condition type. Just collecting variables.
                }
                'SMS_TaskSequence_FileConditionExpression'{
                    # Don't care about this condition type. Just collecting variables.
                }
                'SMS_TaskSequence_FolderConditionExpression'{
                    # Don't care about this condition type. Just collecting variables.
                }
                'SMS_TaskSequence_RegistryConditionExpression'{
                    # Don't care about this condition type. Just collecting variables.
                }
                'SMS_TaskSequence_SoftwareConditionExpression'{
                    # Don't care about this condition type. Just collecting variables.
                }
            }
        }
    }
    If($condition.operator){
        Get-ConditionVariables -condition $condition.operator
    }
}

##Recursively processes through all the steps in a task sequence
Function Find-TSStepConditionVars{
    param ($Sequence,$GroupName)
    foreach ($node in $Sequence.ChildNodes){
        switch($node.localname) {
            'step'{
                if ($node.condition){
                    Get-ConditionVariables -condition $node.condition
                }
            }
            'subtasksequence'{
                if ($node.condition){
                    Get-ConditionVariables -condition $node.condition
                }
            }
            'group'{
                if ($node.condition){
                    Get-ConditionVariables -condition $node.condition
                }
                Find-TSStepConditionVars -Sequence $node -GroupName "$($node.Name)"
            }
            default{}
        }
    }
}


function Convert-UTCtoLocal{
    param(
        [parameter(Mandatory=$true)]
        [String]$UTCTimeString,
        [parameter(Mandatory=$false)]
        [Switch]$IgnoreDST
    )
    $UTCTime = ($UTCTimeString.Split('.'))[0]
    $dt = ([datetime]::ParseExact($UTCTime,'yyyyMMddhhmmss',$null))
    if ($IgnoreDST){
        $dt+([System.TimeZoneInfo]::Local).BaseUtcOffset
    }else{
        $strCurrentTimeZone = (Get-WmiObject win32_timezone).StandardName
        $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
        [System.TimeZoneInfo]::ConvertTimeFromUtc($dt, $TZ)
    }
}

function Process-TSConditions{
    param ($condition,$Level = 0)
    $prefix = ""
    for ($x=0; $x -lt $Level; $x++){$prefix="--TAB--" + $prefix}
    If($condition.osConditionGroup){
        $OSCondition = $condition.osConditionGroup.osExpressionGroup.name -join ", $($condition.osConditionGroup.type) "
        "$($prefix)Operating System Equals: $OSCondition"
        Remove-Variable OSCondition -ErrorAction Ignore
    }
    If($condition.expression){
        $expressions = $condition.expression
        foreach ($expression in $expressions){
            #$expression
            switch ($expression.type){
                'SMS_TaskSequence_WMIConditionExpression' {
                    foreach ($pair in $expression.variable){
                        if ($pair.name -eq 'Query'){
                            if ($pair.'#text' -like 'SELECT OsLanguage FROM Win32_OperatingSystem WHERE OsLanguage*'){
                                $lang=[int](($pair.'#text').Split('='))[1].Trim("`'")
                                "$($prefix)Operating System Language: $(([System.Globalization.Cultureinfo]::GetCultureInfo($lang)).DisplayName) ($lang)"
                            }else{
                                "$($prefix)WMI Query: " + $pair.'#text'
                            }
                        }
                    }
                }
                'SMS_TaskSequence_VariableConditionExpression'{
                    foreach ($pair in $expression.variable){
                        if ($pair.name -eq 'Operator'){
                            $ExpOperator = $pair.'#text'
                        }
                        if ($pair.name -eq 'Value'){
                            $ExpValue = $pair.'#text'
                        }
                        if ($pair.name -eq 'Variable'){
                            $ExpVariable = $pair.'#text'
                        }
                    }
                    "$($prefix)Task Sequence Variable: $ExpVariable $ExpOperator $ExpValue"
                    Remove-Variable ExpVariable,ExpOperator,ExpValue -ErrorAction Ignore
                }
                'SMS_TaskSequence_FileConditionExpression'{
                    If(('Path' -in ($expression.variable).name) -and ('DateTimeOperator' -notin ($expression.variable).name) -and ('VersionOperator' -notin ($expression.variable).name)){
                        "$($prefix)File Exists: " + ($expression.variable).'#text'
                    }else{
                        foreach ($pair in $expression.variable){
                            switch ($pair.name){
                                'DateTime'{$FileDate = Convert-UTCtoLocal($pair.'#text')}
                                'DateTimeOperator'{$FileDateOperator = $pair.'#text'}
                                'Path'{$FilePath = $pair.'#text'}
                                'Version'{$FileVersion = $pair.'#text'}
                                'VersionOperator'{$FileVersionOperator = $pair.'#text'}
                            }
                        }
                        #'DateTimeOperator' -in ($expression.variable).name
                        #'VersionOperator' -in ($expression.variable).name
                        "$($prefix)File: $FilePath     File Version: $FileVersionOperator $FileVersion     File Date: $FileDateOperator $FileDate"
                        Remove-Variable FileDate,FileDateOperator,FilePath,FileVersion,FileVersionOperator -ErrorAction Ignore
                    }
                }
                'SMS_TaskSequence_FolderConditionExpression'{
                    If(('Path' -in ($expression.variable).name) -and ('DateTimeOperator' -notin ($expression.variable).name)){
                        "$($prefix)Folder Exists: " + ($expression.variable).'#text'
                    }else{
                        foreach ($pair in $expression.variable){
                            switch ($pair.name){
                                'DateTime'{$FolderDate = Convert-UTCtoLocal($pair.'#text')}
                                'DateTimeOperator'{$FolderDateOperator = $pair.'#text'}
                                'Path'{$FolderPath = $pair.'#text'}
                            }
                        }
                        #'DateTimeOperator' -in ($expression.variable).name
                        #'VersionOperator' -in ($expression.variable).name
                        "$($prefix)Folder: $FolderPath     Folder Date: $FolderDateOperator $FolderDate"
                        Remove-Variable FolderPath,FolderDateOperator,FolderDate -ErrorAction Ignore
                    }
                }
                'SMS_TaskSequence_RegistryConditionExpression'{
                    foreach ($pair in $expression.variable){
                        Switch ($pair.name){
                            'Operator'{$RegOperator = $pair.'#text'}
                            'KeyPath'{$RegKeyPath = $pair.'#text'}
                            'Data'{$RegData = $pair.'#text'}
                            'Value'{$RegValue = $pair.'#text'}
                            'Type'{$RegType = $pair.'#text'}
                        }
                    }
                    "$($prefix)Registry Value: $RegKeyPath $RegValue ($RegType) $RegOperator $RegData"
                    Remove-Variable RegKeyPath,RegValue,RegType,RegOperator,RegData -ErrorAction Ignore
                }
                'SMS_TaskSequence_SoftwareConditionExpression'{
                    foreach ($pair in $expression.variable){
                        Switch ($pair.name){
                            'Operator'{$AppOperator = $pair.'#text'}
                            'ProductCode'{$AppProductCode = $pair.'#text'}
                            'ProductName'{$AppProductName = $pair.'#text'}
                            #'UpgradeCode'{$AppUpgradeCode = $pair.'#text'}
                            'Version'{$AppVersion = $pair.'#text'}
                        }
                    }
                    If ($AppOperator -eq 'AnyVersion'){
                        "$($prefix)Installed Software: Any Version of `"$AppProductName`""
                    }else{
                        "$($prefix)Installed Software: Exact Version of `"$AppProductName`", Version: $AppVersion, Product Code: $AppProductCode"
                    }
                    Remove-Variable AppOperator,AppProductCode,AppProductName,AppUpgradeCode,AppVersion -ErrorAction Ignore
                }
            }
        }
    }
    If($condition.operator){
        Switch($condition.operator.type){
        'or'{"$($prefix)-If any of these conditions are true"}
        'and'{"$($prefix)-If all of these conditions are true"}
        'not'{"$($prefix)-If none of these conditions are true"}
        }
        $Level = $Level + 1
        Process-TSConditions -condition $condition.operator -Level $Level
    }
}

Function Get-IsParentGroupDisabled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        #[ValidateNotNullOrEmpty()]
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

Function Get-TSStepType {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $TypeName
    )
    switch ($TypeName) {
        'SMS_TaskSequence_RunCommandLineAction' {'Run Command Line'}
        'SMS_TaskSequence_RunPowerShellScriptAction' {'Run PowerShell Script'}
        'SMS_TaskSequence_SetDynamicVariablesAction' {'Set Dynamic Variables'}
        'SMS_TaskSequence_JoinDomainWorkgroupAction' {'Join Domain or Workgroup'}
        'SMS_TaskSequence_ConnectNetworkFolderAction' {'Connect to Network Folder'}
        'SMS_TaskSequence_RebootAction' {'Restart Computer'}
        'SMS_TaskSequence_SetVariableAction' {'Set Task Sequence Variable'}
        'SMS_TaskSequence_PrestartCheckAction' {'Check Readiness'}
        'SMS_TaskSequence_SubTasksequence' {'Sub Task Sequence'}
        'SMS_TaskSequence_InstallApplicationAction' {'Install Application'}
        'SMS_TaskSequence_InstallSoftwareAction' {'Install Package'}
        'SMS_TaskSequence_InstallUpdateAction' {'Install Software Updates'}
        'SMS_TaskSequence_DownloadPackageContentAction' {'Download Package Content'}
        'SMS_TaskSequence_PartitionDiskAction' {'Format and Partition Disk'}
        'SMS_TaskSequence_ConvertDiskAction' {'Convert Disk to Dynamic'}
        'SMS_TaskSequence_EnableBitLockerAction' {'Enable BitLocker'}
        'SMS_TaskSequence_DisableBitLockerAction' {'Disable BitLocker'}
        'SMS_TaskSequence_OfflineEnableBitLockerAction' {'Pre-provision BitLocker'}
        'SMS_TaskSequence_RequestStateStoreAction' {'Request State Store'}
        'SMS_TaskSequence_CaptureUserStateAction' {'Capture User State'}
        'SMS_TaskSequence_RestoreUserStateAction' {'Restore User State'}
        'SMS_TaskSequence_ReleaseStateStoreAction' {'Release State Store'}
        'SMS_TaskSequence_ApplyOperatingSystemAction' {'Apply Operating System Image'}
        'SMS_TaskSequence_ApplyDataImageAction' {'Apply Data Image'}
        'SMS_TaskSequence_SetupWindowsAndSMSAction' {'Setup Windows and ConfigMgr'}
        'SMS_TaskSequence_UpgradeOperatingSystemAction' {'Upgrade Operating System'}
        'SMS_TaskSequence_InstallDeployToolsAction' {'Install Deployment Tools'}
        'SMS_TaskSequence_PrepareSMSClientAction' {'Prepare ConfigMgr Client for Capture'}
        'SMS_TaskSequence_PrepareOSAction' {'Prepare Windows for Capture'}
        'SMS_TaskSequence_CaptureSystemImageAction' {'Capture Operating System Image'}
        'SMS_TaskSequence_AutoApplyAction' {'Auto Apply Drivers'}
        'SMS_TaskSequence_ApplyDriverPackageAction' {'Apply Driver Package'}
        'SMS_TaskSequence_CaptureNetworkSettingsAction' {'Capture Network Settings'}
        'SMS_TaskSequence_CaptureWindowsSettingsAction' {'Capture Windows Settings'}
        'SMS_TaskSequence_ApplyNetworkSettingsAction' {'Apply Network Settings'}
        'SMS_TaskSequence_ApplyWindowsSettingsAction' {'Apply Windows Settings'}
        Default {'Unknown'}
    }
}

Function Step-TaskSequence {
    [CmdletBinding()]
    param ($Sequence, $GroupName, [int]$StepCounter = 0)
    Write-Verbose "Starting Run: $StepCounter"
    foreach ($node in $Sequence.ChildNodes) {
        switch ($node.localname) {
            'step' {
                $StepCounter++
                if (($StepCounter -eq 1) -and ($FirstStep -ne 0)){$StepCounter = 0;$FirstStep = 0}
                Write-Verbose "$StepCounter --- STEP --- $($Node.Name)"
                if (!($GroupName)) {
                    $GroupName = "N/A"
                }
                ## Object
                if ($node.continueOnError -eq "true"){
                    $continueOnError = "True"
                } else {
                    $continueOnError = "False"
                }
                if ($node.condition){
                    $Conditions = (Process-TSConditions -condition $node.condition) -join "`n"
                } else {
                    $Conditions = 'None'
                }
                if ($node.successCodeList){
                    $successCodeList = @(($node.successCodeList).split(' '))
                } else {
                    $successCodeList = @(0)
                }
                if ($node.disable -eq "true"){
                    $StepDisabled = "True"
                } else {
                    $StepDisabled = "False"
                }
                if ($null -eq $node){
                    $ParentDisabled = 'False'
                } elseif ((Get-IsParentGroupDisabled -TSXml $node) -eq $true){
                    $ParentDisabled = 'True'
                } else {
                    $ParentDisabled = 'False'
                }
                [pscustomobject]@{
                    'StepNumber' = $StepCounter
                    'GroupName' = "$GroupName"
                    'StepName' = "$($node.Name)"
                    'StepType' = Get-TSStepType "$($node.Type)"
                    'GroupPosition' = ''
                    'Disabled' = $StepDisabled
                    'ParentDisabled' = $ParentDisabled
                    'ContinueOnError' = $continueOnError
                    'SuccessCodeList' = $successCodeList
                    'SuccessCodeText' = $successCodeList -join ', '
                    'Conditions' = "$Conditions"
                    'Status' = "0"
                }
                ## Object
        }
            'subtasksequence' {
                if ([string]::IsNullOrEmpty($node.disable)) {
                    if ((Get-IsParentGroupDisabled -TSXml $node -ErrorAction SilentlyContinue) -ne $true) {
                        $StepCounter++
                        if (($StepCounter -eq 1) -and ($FirstStep -ne 0)){$StepCounter = 0;$FirstStep = 0}
                        Write-Verbose "$StepCounter --- SUBTS --- $($Node.Name)"
                        $SubTSPackageID = $(foreach ($var in $Node.defaultVarList.variable) { if ($Var.property -like 'TsPackageID') { $var.'#text' } })
                        $SubSequence = Get-PWTSXml -TSPackageID "$SubTSPackageID" -SiteServer $PrimarySiteServer -SiteCode $SiteCode
                        $SubTaskSequenceXML = Step-TaskSequence -Sequence $SubSequence
                        $SubTSFinalStepNumber = ($SubTaskSequenceXML.stepnumber | Measure-Object -Maximum).Maximum
                        $StepCounter = $StepCounter + $SubTSFinalStepNumber + 1
                        ## Object
                        if ($node.continueOnError -eq "true"){
                            $continueOnError = "True"
                        } else {
                            $continueOnError = "False"
                        }
                        if ($node.condition){
                            $Conditions = (Process-TSConditions -condition $node.condition) -join "`n"
                        } else {
                            $Conditions = 'None'
                        }
                        if ($node.successCodeList){
                            $successCodeList = @(($node.successCodeList).split(' '))
                        } else {
                            $successCodeList = @(0)
                        }        
                        if ($node.disable -eq "true"){
                            $StepDisabled = "True"
                        } else {
                            $StepDisabled = "False"
                        }
                        if ($null -eq $node.ParentNode){
                            $ParentDisabled = 'False'
                        } elseif ((Get-IsParentGroupDisabled -TSXml $node) -eq $true){
                            $ParentDisabled = 'True'
                        } else {
                            $ParentDisabled = 'False'
                        }
                        [pscustomobject]@{
                            'StepNumber' = $StepCounter
                            'GroupName' = "$GroupName"
                            'StepName' = "$($node.Name)"
                            'StepType' = Get-TSStepType "$($node.Type)"
                            'GroupPosition' = ''
                            'Disabled' = $StepDisabled
                            'ParentDisabled' = $ParentDisabled
                            'ContinueOnError' = $continueOnError
                            'SuccessCodeList' = $successCodeList
                            'SuccessCodeText' = $successCodeList -join ', '
                            'Conditions' = "$Conditions"
                            'Status' = "0"
                        }
                        ## Object
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
                if (($StepCounter -eq 1) -and ($FirstStep -ne 0)){$StepCounter = 0;$FirstStep = 0}
                Write-Verbose "$StepCounter --- GROUP --- $($Node.Name) --- Start"
				$GroupFirstStep = $StepCounter
                ## Object
                if ($node.continueOnError -eq "true"){
                    $continueOnError = "True"
                } else {
                    $continueOnError = "False"
                }
                if ($node.condition){
                    $Conditions = (Process-TSConditions -condition $node.condition) -join "`n"
                } else {
                    $Conditions = 'None'
                }
                if ($node.successCodeList){
                    $successCodeList = @(($node.successCodeList).split(' '))
                } else {
                    $successCodeList = @(0)
                }
                if ($node.disable -eq "true"){
                    $StepDisabled = "True"
                } else {
                    $StepDisabled = "False"
                }
                if ($null -eq $node.ParentNode){
                    $ParentDisabled = 'False'
                } elseif ((Get-IsParentGroupDisabled -TSXml $node) -eq $true){
                    $ParentDisabled = 'True'
                } else {
                    $ParentDisabled = 'False'
                }
                [pscustomobject]@{
                    'StepNumber' = $StepCounter
                    'GroupName' = "$GroupName"
                    'StepName' = "$($node.Name)"
                    'StepType' = "Group"
                    'GroupPosition' = 'In'
                    'Disabled' = $StepDisabled
                    'ParentDisabled' = $ParentDisabled
                    'ContinueOnError' = $continueOnError
                    'SuccessCodeList' = $successCodeList
                    'SuccessCodeText' = $successCodeList -join ', '
                    'Conditions' = "$Conditions"
                    'Status' = "0"
                }
                ## Object
                $NextSteps = Step-TaskSequence -Sequence $node -GroupName "$($node.Name)" -StepCounter $StepCounter
                If ($NextSteps) {
                    foreach ($NextStep in $NextSteps) { 
                        Write-Verbose $NextStep.StepNumber 
                        $NextStep
                    }
                    $StepCounter = ($NextSteps.StepNumber | Measure-Object -Maximum).Maximum
                }
                Write-Verbose "$StepCounter --- GROUP --- $($Node.Name) --- BeforeINC"
                $StepCounter++
                #"$($GroupFirstStep)-$($StepCounter)
                Write-Verbose "$StepCounter --- GROUP --- $($Node.Name) --- END"
                ## Object
                if ($node.continueOnError -eq "true"){
                    $continueOnError = "True"
                } else {
                    $continueOnError = "False"
                }
                if ($node.condition){
                    $Conditions = (Process-TSConditions -condition $node.condition) -join "`n"
                } else {
                    $Conditions = 'None'
                }
                if ($node.successCodeList){
                    $successCodeList = @(($node.successCodeList).split(' '))
                } else {
                    $successCodeList = @(0)
                }
                if ($node.disable -eq "true"){
                    $StepDisabled = "True"
                } else {
                    $StepDisabled = "False"
                }
                if ($null -eq $node.ParentNode){
                    $ParentDisabled = 'False'
                } elseif ((Get-IsParentGroupDisabled -TSXml $node) -eq $true){
                    $ParentDisabled = 'True'
                } else {
                    $ParentDisabled = 'False'
                }
                [pscustomobject]@{
                    'StepNumber' = $StepCounter
                    'GroupName' = "$GroupName"
                    'StepName' = "$($node.Name)"
                    'StepType' = "Group"
                    'GroupPosition' = 'Out'
                    'Disabled' = $StepDisabled
                    'ParentDisabled' = $ParentDisabled
                    'ContinueOnError' = $continueOnError
                    'SuccessCodeList' = $successCodeList
                    'SuccessCodeText' = $successCodeList -join ', '
                    'Conditions' = "$Conditions"
                    'Status' = "0"
                }
                ## Object
            }
            'sequence' {
                if ($StepCounter -ne 0) { $StepCounter++ }
                Write-Verbose "$StepCounter --- SEQU --- $($Node.Name)"
                $NextSteps = Step-TaskSequence -Sequence $node -GroupName "$($node.Name)" -StepCounter $StepCounter
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

function Convert-XAMLtoWindow {
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $XAML
    )
    
    Add-Type -AssemblyName PresentationFramework
    
    $reader = [XML.XMLReader]::Create([IO.StringReader]$XAML)
    $result = [Windows.Markup.XAMLReader]::Load($reader)
    $reader.Close()
    $reader = [XML.XMLReader]::Create([IO.StringReader]$XAML)
    while ($reader.Read())
    {
        $name=$reader.GetAttribute('Name')
        if (!$name) { $name=$reader.GetAttribute('x:Name') }
        if($name)
        {$result | Add-Member NoteProperty -Name $name -Value $result.FindName($name) -Force}
    }
    $reader.Close()
    $result
}

function Show-WPFWindow {
    param
    (
        [Parameter(Mandatory)]
        [Windows.Window]
        $Window
    )
    
    $result = $null
    $null = $window.Dispatcher.InvokeAsync{
        $result = $window.ShowDialog()
        Set-Variable -Name result -Value $result -Scope 1
    }.Wait()
    $result
}

#### FORM
$xaml = @'
<Window
 xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
 xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
 Title='TS Simulation' SizeToContent='WidthAndHeight'>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto" />
                <ColumnDefinition Width="Auto" />
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="40" />
                <RowDefinition Height="300" />
                <RowDefinition Height="150" />
                <RowDefinition Height="28" />
            </Grid.RowDefinitions>
            <TextBlock Margin="5" Grid.ColumnSpan="2">Task Sequence steps that will process:</TextBlock>
            <ListView Grid.Row="1" Name="View1" MinWidth="500">
            <ListView.Resources>
                <Style TargetType="{x:Type ListViewItem}">
                    <Style.Triggers>
                        <DataTrigger Binding="{Binding StepType}" Value="Groups">
                            <Setter Property="Background" Value="#00ff00" />
                        </DataTrigger>
                        <DataTrigger Binding="{Binding Status}" Value="3">
                            <Setter Property="Background" Value="#ff0000" />
                        </DataTrigger>
                        <DataTrigger Binding="{Binding Status}" Value="2">
                            <Setter Property="Background" Value="#85929E" />
                        </DataTrigger>
                        <DataTrigger Binding="{Binding Status}" Value="0">
                            <Setter Property="Background" Value="#FFFFFF" />
                        </DataTrigger>
                        <Trigger Property="IsSelected" Value="True">
                        <Trigger.Setters>
                            <Setter Property="Background" Value="#5DADE2" />
                        </Trigger.Setters>
                      </Trigger>                  
                    </Style.Triggers>
                </Style>
            </ListView.Resources>
                <ListView.View>
                    <GridView>
                        <GridViewColumn Width="25" Header="#" DisplayMemberBinding="{Binding StepNumber}"/>
                        <GridViewColumn Width="100" Header="Group Name" DisplayMemberBinding="{Binding GroupName}"/>
                        <GridViewColumn Width="275" Header="Step Name" DisplayMemberBinding="{Binding StepName}"/>
                        <GridViewColumn Width="125" Header="Step Type" DisplayMemberBinding="{Binding StepType}"/>
                        <GridViewColumn Width="70" Header="Cont on Err" DisplayMemberBinding="{Binding ContinueOnError}"/>
                        <GridViewColumn Width="100" Header="Success Codes" DisplayMemberBinding="{Binding SuccessCodeText}"/>
                        <GridViewColumn Width="350" Header="Conditions">
                            <GridViewColumn.CellTemplate>
                                <DataTemplate>
                                    <TextBlock TextWrapping="Wrap" Text="{Binding Conditions}" Width="350"/>
                                </DataTemplate>
                            </GridViewColumn.CellTemplate>
                        </GridViewColumn>
                    </GridView>
                </ListView.View>
            </ListView>
            <StackPanel Orientation="Vertical" Grid.Row="1" Grid.Column="1">
                <ListView Name="VarView" MinWidth="250">
                    <ListView.View>
                        <GridView>
                            <GridViewColumn Width="125" Header="Variable" DisplayMemberBinding="{Binding Name}"/>
                            <GridViewColumn Width="125" Header="Value" DisplayMemberBinding="{Binding Value}"/>
                        </GridView>
                    </ListView.View>
                </ListView>
                <TextBlock Margin="2" TextAlignment="Center" FontWeight="Bold" Name="SelectedVariable" />
                <TextBox Name="SelectedVarValue" TextAlignment="Center" Width="150"/>
                <Button Name="SetVariable" HorizontalAlignment="Center" Width="100" Margin="3" Content="Set Variable" />
            </StackPanel>
            <ListView Grid.Row="2" Name="LogView" MinWidth="500">
                <ListView.View>
                    <GridView>
                        <GridViewColumn Width="920" Header="Execution Log" DisplayMemberBinding="{Binding LogItem}"/>
                    </GridView>
                </ListView.View>
            </ListView>
            <StackPanel VerticalAlignment="Center" Orientation="Vertical" Grid.Row="2" Grid.Column="1">
                <Button Name="StartSim" HorizontalAlignment="Center" Width="100" Margin="3" FontSize="16" Content="Start Sim" />
                <TextBlock Margin="2" TextAlignment="Center" FontSize="20" FontWeight="Bold" Text="Step Exit Code" />
                <TextBox Name="StepExitCode" TextAlignment="Center" Width="150" FontSize="16" Foreground="Green" Text="0"/>
                <Button Name="ProcessStep" HorizontalAlignment="Center" Width="100" Margin="3" FontSize="16" Content="Process Step" />
            </StackPanel>
            <StackPanel Orientation="Horizontal" Grid.Row="3" Grid.ColumnSpan="2" HorizontalAlignment="Right">
                <Button Name='ClearLog' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Clear Log" />
                <Button Name='ResetSim' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Reset Simulator" />
                <Button Name='CloseWindow' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Exit Simulator" />
            </StackPanel>
        </Grid>
</Window>
'@


#$TSXml = Get-PWTSXml -TSPackageID MMS00026
#$TSXml = Get-PWTSXml -TSPackageID MMS00016
$TSXml = Get-PWTSXml -TSPackageID $PackageID -SiteServer $PrimarySiteServer -SiteCode $SiteCode

$TSVars = foreach ($Var in (Find-TSStepConditionVars -Sequence $TSXml.sequence|Sort-Object -Unique)){
    [pscustomobject]@{Name = $var; Value = ''}
}
$LinearStepOrder = Step-TaskSequence -Sequence $TSXml

$window = Convert-XAMLtoWindow -XAML $xaml

$window.CloseWindow.add_Click{
    $window.DialogResult = $false
}

$window.ClearLog.add_Click{
    $window.LogView.ItemsSource = @()
}

$window.ProcessStep.add_Click{
    $Start = $true
    [int]$Index = $window.View1.SelectedIndex + 1
    [int]$Items = ($window.View1.ItemsSource).count
    #Write-Host $($Items -gt $Index)
    If ($window.View1.SelectedIndex -eq -1){$global:OrderIndex = -1}
    else {$global:OrderIndex = $window.View1.SelectedIndex}
    #write-host "$Index of $Items"
    IF ($Items -gt $Index){
        foreach ($Step in $window.View1.ItemsSource) {
            If ($Step.StepNumber -ge $global:OrderIndex){
                If ($Step.StepType -eq 'Group'){
                    If ($ContinueToGroup -eq $true){
                        Write-Host "Something in this group [$ParentGroup] had an error, looking for end of group."
                        If (($ParentGroup -eq $Step.StepName) -and ($Step.GroupPosition -eq 'Out')){ #Look at the Parent Group of the previous failed step and see if this is the exit point (out) for that group
                            Write-Host "...and we now found the end of the group. process group response to error."
                            $ContinueToGroup = $false
                            Write-Host "Executing Group: $($Step.StepName) --- $($Step.GroupPosition)"
                            If ($Step.ContinueOnError -eq $false){
                                #Group will not allow to continue. Continue to parent group of this group for eval.
                                $ContinueToGroup = $true
                                $ParentGroup = $Step.GroupName
                                Write-Host "Completing Group with continue on error False: $($Step.StepName) --- $($Step.GroupPosition)"
                                $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Completing Group with continue on error False: $($Step.StepName) --- $($Step.GroupPosition)"})
                                $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Continue to parent group of this group for eval."})
                                $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
                                $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))
                                Write-Host "Continue to parent group of this group for eval."
                                $global:OrderIndex++
                                $window.View1.SelectedIndex = $global:OrderIndex
                                $window.View1.ScrollIntoView($window.View1.items.Item($window.View1.SelectedIndex))
                                $window.Dispatcher.Invoke([action]{},"Render")
                                Start-Sleep -Milliseconds 500
                                Continue
                            } else {
                                Remove-Variable ParentGroup -ErrorAction Ignore
                                $window.Dispatcher.Invoke([action]{},"Render")
                                Write-Host "Executing end of group with continue on error True: $($Step.StepName) --- $($Step.GroupPosition)"
                                $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Executing end of group with continue on error True: $($Step.StepName)"})
                                $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
                                $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))
                                $global:OrderIndex++
                                $window.View1.SelectedIndex = $global:OrderIndex
                                $window.View1.ScrollIntoView($window.View1.items.Item($window.View1.SelectedIndex))
                                $ContinueToGroup = $false
                                $window.Dispatcher.Invoke([action]{},"Render")
                                Start-Sleep -Milliseconds 500
                                #Break
                                Write-Host "From end of continue error true Group, Next Type: $($window.View1.items.Item($window.View1.SelectedIndex).StepType)"
                                IF ($window.View1.items.Item($window.View1.SelectedIndex).StepType -ne 'Group'){
                                    Write-Host "From Group, Next Type: $($window.View1.items.Item($window.View1.SelectedIndex).StepType)"
                                    Break
                                }
                            }
                        } else {
                            # not at end of group yet, keep going.
                            Write-Host "Skipping Group cotained in parent group with failed step: $($Step.StepName) --- $($Step.GroupPosition)"
                            $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Skipping Group as it is contained in parent group with failed step: $($Step.StepName) --- $($Step.GroupPosition)"})
#                            $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Continue to parent group of this group for eval."})
                            $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
                            $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))
                            Write-Host "Continue to parent group of this group for eval."
                            $global:OrderIndex++
                            $window.View1.SelectedIndex = $global:OrderIndex
                            $window.View1.ScrollIntoView($window.View1.items.Item($window.View1.SelectedIndex))
                            $window.Dispatcher.Invoke([action]{},"Render")
                            Start-Sleep -Milliseconds 500
                        }
                    } else {
                        # Processing groups normally.
                        $window.Dispatcher.Invoke([action]{},"Render")
                        Start-Sleep -Milliseconds 500
                        $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Executing Group Normally: $($Step.StepName) ($($Step.GroupPosition))"})
                        $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
                        $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1)) #Scroll the log window
                        Write-Host "Executing Group Normally: $($Step.StepName) --- $($Step.GroupPosition)"
                        $global:OrderIndex++
                        $window.View1.SelectedIndex = $global:OrderIndex
                        $window.View1.ScrollIntoView($window.View1.items.Item($window.View1.SelectedIndex))
                        $window.Dispatcher.Invoke([action]{},"Render")
                        IF ($global:OrderIndex -lt $Items -and $window.View1.items.Item($global:OrderIndex).StepType -ne 'Group'){
                            Write-Host "From Group, Next Type: $($window.View1.items.Item($window.View1.SelectedIndex).StepType)"
                            Break
                        }
                        IF ($global:OrderIndex -eq $Items){
                            Write-Host "Task Sequence Execution Complete"
                            $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Task Sequence Execution Complete."})
                            $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
                            $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))
                        }
                    }
                } else { # the step isn't a group.  So, stuffs needs to be evaluated.
                    If (($ContinueToGroup -eq $false) -or ([string]::IsNullOrEmpty($ContinueToGroup))) {
                        #there was no error to force us to go to a group.  So, lets process the step..
                        If ($Start -eq $true){ #not sure if i need the "start"  This may later be replaced with condition assessments....
                            #$Start = $false
                            $ExitCodeField = $Window.FindName('StepExitCode')
                            $ExitCodeVar = $ExitCodeField.text
                            If ($ExitCodeVar -eq '') {
                                $ExitCodeVar = 0
                            }
                            $ExitCodeField.text = 0
                            Write-Host "Review Step: $($Step.StepName) -- Exit Code: $ExitCodeVar"
                            If ($ExitCodeVar -in $Step.SuccessCodeList) {
                                $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Successful Step: $($Step.StepName)"})
                                $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
                                $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))    
                                Write-Host "Successful Step: $($Step.StepName)"
                                $global:OrderIndex++
                                $window.View1.SelectedIndex = $global:OrderIndex
                                $window.View1.ScrollIntoView($window.View1.items.Item($window.View1.SelectedIndex))
                                Write-Host "Next Type: $($window.View1.items.Item($window.View1.SelectedIndex).StepType)"
                                IF ($window.View1.items.Item($window.View1.SelectedIndex).StepType -ne 'Group'){
                                    Write-Host "Next Type: $($window.View1.items.Item($window.View1.SelectedIndex).StepType)"
                                    Break
                                }
                            } else { #Exit code was not in the list of success codes.  processing as failed step.
                                $window.View1.ItemsSource[$($Step.StepNumber)].Status = 3
                                $viewtemp = $window.View1.ItemsSource
                                $window.View1.ItemsSource = ''
                                $window.View1.ItemsSource = $viewtemp
                                $window.View1.SelectedIndex = $global:OrderIndex
                                $window.View1.ScrollIntoView($window.View1.items.Item($window.View1.SelectedIndex))        
                                #$window.View1.ItemsSource = $window.View1.ItemsSource
                                If ($step.ContinueOnError -eq $false) {
                                    $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Failed Step (Continue on Error is False): $($Step.StepName)"})
                                    $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
                                    $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))    
                                    Write-Host "Failed Step (Continue on Error is False): $($Step.StepName)"
                                    $ContinueToGroup = $true
                                    $global:OrderIndex++
                                    $ParentGroup = $Step.GroupName
                                    $window.Dispatcher.Invoke([action]{},"Render")
                                    Start-Sleep -Milliseconds 500
                                } else {
                                    $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Failed Step (Continue on Error is True): $($Step.StepName)"})
                                    $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
                                    $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))    
                                    Write-Host "Failed Step (Continue on Error is True): $($Step.StepName)"
                                    $global:OrderIndex++
                                    $window.View1.SelectedIndex = $global:OrderIndex
                                    $window.View1.ScrollIntoView($window.View1.items.Item($window.View1.SelectedIndex))
                                    #"Continue" #this return code is a success. Keep going.
                                    Break    
                                }
                            }
                        } else {
                            Write-Host "Executing step: $($Step.StepName)"
#                            $SimRetCode = Read-Host -Prompt 'Step Return Code (0):'
                        }
                    } Else {
                        #Cannot process the steps any longer in this group because one had an error.  Finishing out group.
                        $window.View1.ItemsSource[$($Step.StepNumber)].Status = 2
                        $viewtemp = $window.View1.ItemsSource
                        $window.View1.ItemsSource = ''
                        $window.View1.ItemsSource = $viewtemp
                        $window.View1.SelectedIndex = $global:OrderIndex
                        $window.View1.ScrollIntoView($window.View1.items.Item($window.View1.SelectedIndex))
                        #$window.View1.ItemsSource = $window.View1.ItemsSource
                        $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Skipping Step in group because of previous failure: $($Step.StepName)"})
                        $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
                        $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))    
                        Write-Host "Skipping Step in group because of previous failure: $($Step.StepName)"
                        $global:OrderIndex++
                        $window.View1.SelectedIndex = $global:OrderIndex
                        $window.View1.ScrollIntoView($window.View1.items.Item($window.View1.SelectedIndex))
                        $window.Dispatcher.Invoke([action]{},"Render")
                        Start-Sleep -Milliseconds 500
                        Continue
                    }
                }
            }
        }
        if (($global:OrderIndex + 1) -eq $Items){
            Write-Host "Task Sequence Execution Complete"
            $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Task Sequence Execution Complete."})
            $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
            $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))
        }
    } else {
        Write-Host "Task Sequence Execution Complete"
        $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Task Sequence Execution Complete."})
        $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
        $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))
    }
}

$window.StartSim.add_Click{
    $window.LogView.ItemsSource = @()
    $window.View1.SelectedIndex = 0
    $global:OrderIndex = $window.View1.SelectedIndex
    $window.Dispatcher.Invoke([action]{},"Render")
    foreach ($Step in $window.View1.ItemsSource) {
        If ($Step.StepType -eq 'Group') {
            Write-Host "Executing Group at start of Sequence: $($Step.StepName) --- $($Step.GroupPosition)"
            $window.LogView.ItemsSource += @([PSCustomObject]@{ LogItem = "Executing Group at start of Sequence: $($Step.StepName)" })
            $window.LogView.SelectedIndex = ($window.LogView.ItemsSource).count
            $window.LogView.ScrollIntoView($window.LogView.items.Item(($window.LogView.ItemsSource).count - 1))
            $global:OrderIndex++
            $window.View1.SelectedIndex = $global:OrderIndex
            $window.View1.ScrollIntoView($window.View1.items.Item($window.View1.SelectedIndex))
            Start-Sleep -Milliseconds 500
            $window.Dispatcher.Invoke([action]{},"Render")
            Continue
        }
        else {
            Break
        }
    }
}

$window.ResetSim.add_Click{
    $window.View1.ItemsSource = @()
    $LinearStepOrder|foreach {$_.status = 0}
    $window.View1.ItemsSource = $LinearStepOrder
    $window.View1.ScrollIntoView($window.View1.items.Item(0))
    $ExitCodeField = $Window.FindName('StepExitCode')
    $ExitCodeField.text = 0
    $window.VarView.ItemsSource = $TSVars
    $window.LogView.ItemsSource = @()
    $window.View1.SelectedIndex = -1
    $global:OrderIndex = $window.View1.SelectedIndex
    $window.Dispatcher.Invoke([action]{},"Render")
}

$window.SetVariable.add_Click{
    $SetSelectedVariable = $Window.FindName('SelectedVariable')
    $SelectedVar = $SetSelectedVariable.text
    $SetSelectedVarValue = $Window.FindName('SelectedVarValue')
    $NewVarValue = $SetSelectedVarValue.text
    ($TSVars|Where-Object {$_.Name -eq "$SelectedVar"}).Value = "$NewVarValue"
    Write-Host $TSVars
    $window.VarView.ItemsSource = ''
    $window.VarView.ItemsSource = $TSVars
}

$window.View1.ItemsSource = $LinearStepOrder
$window.VarView.ItemsSource = $TSVars

$VarView = $Window.FindName('VarView')
$VarView.Add_SelectionChanged({
    #$PSDrive = (Get-PSDrive $window.VarView.SelectedItems)|ConvertTo-HashTable
    #$window.VarDetails.ItemsSource = $window.VarView.SelectedItems
    #$window.Details.Text = "Name: $($PSDrive.Name) `nProvider: $($Psdrive.Provider) `nRoot: $($PSDrive.Root)"
    $SelectedVariable = $Window.FindName('SelectedVariable')
    $SelectedVariable.text = $window.VarView.SelectedItems.Name
    $SelectedVarValue = $Window.FindName('SelectedVarValue')
    $SelectedVarValue.text = $window.VarView.SelectedItems.Value
})

$null = Show-WPFWindow -Window $window
