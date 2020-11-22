##Run SetupDiag for diagnostics.

$PSDefaultParameterValues["Write-Log:LogFile"] = "C:\Windows\Logs\Software\SetupDiag-Diagnostics.log"
$PSDefaultParameterValues["Write-Log:Verbose"] = $false
$SetupDiagExePath = 'C:\Windows\Temp\SetupDiag.exe'
$SetupDiagWorkingDirectory = [io.path]::GetDirectoryName($SetupDiagExePath)
##Log Function

function Write-Log {
    [CmdletBinding()] 
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
 
        [Parameter(Mandatory = $false)]
        $ErrorMessage,
 
        [Parameter(Mandatory = $false)]
        $Component,
 
        [Parameter(Mandatory = $false, HelpMessage = "1 = Normal, 2 = Warning (yellow), 3 = Error (red)")]
        [ValidateSet(1, 2, 3)]
        [int]$Type,
		
        [Parameter(Mandatory = $false, HelpMessage = "Size in KB")]
        [int]$LogSizeKB = 512,

        [Parameter(Mandatory = $true)]
        $LogFile
    )
    <#
    Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
    #>
    Try{
        IF (!(Test-Path ([System.IO.DirectoryInfo]$LogFile).Parent.FullName)){
            New-Item -ItemType directory -Path ([System.IO.DirectoryInfo]$LogFile).Parent.FullName
        }
    }
    Catch{
        Throw 'Failed to find/set parent directory path'
    }
    $LogLength = $LogSizeKB * 1024
    try {
        $log = Get-Item $LogFile -ErrorAction Stop
        If (($log.length) -gt $LogLength) {
            $Time = Get-Date -Format "HH:mm:ss.ffffff"
            $Date = Get-Date -Format "MM-dd-yyyy"
            $LogMessage = "<![LOG[Closing log and generating new log file" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"1`" thread=`"`" file=`"`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
            Move-Item -Path "$LogFile" -Destination "$($LogFile.TrimEnd('g'))_" -Force
        }
    }
    catch {Write-Verbose "Nothing to move or move failed."}

    $Time = Get-Date -Format "HH:mm:ss.ffffff"
    $Date = Get-Date -Format "MM-dd-yyyy"
 
    if ($ErrorMessage -ne $null) {$Type = 3}
    if ($Component -eq $null) {$Component = " "}
    if ($Type -eq $null) {$Type = 1}
 
    $LogMessage = "<![LOG[$Message $ErrorMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
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
function Convert-XAMLtoWindow{
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

Function ConvertTo-HashTable {

    <#
    .Synopsis
    Convert an object into a hashtable.
    .Description
    This command will take an object and create a hashtable based on its properties.
    You can have the hashtable exclude some properties as well as properties that
    have no value.
    .Parameter Inputobject
    A PowerShell object to convert to a hashtable.
    .Parameter NoEmpty
    Do not include object properties that have no value.
    .Parameter Exclude
    An array of property names to exclude from the hashtable.
    .Example
    PS C:\> get-process -id $pid | select name,id,handles,workingset | ConvertTo-HashTable
    
    Name                           Value                                                      
    ----                           -----                                                      
    WorkingSet                     418377728                                                  
    Name                           powershell_ise                                             
    Id                             3456                                                       
    Handles                        958                                                 
    .Notes
    Version:  2.0
    Updated:  January 17, 2013
    Author :  Jeffery Hicks (http://jdhitsolutions.com/blog)
    .Link
    http://jdhitsolutions.com/blog/2013/01/convert-powershell-object-to-hashtable-revised
    .Link
    About_Hash_Tables
    Get-Member
    .Inputs
    Object
    .Outputs
    hashtable
    #>
    
    [cmdletbinding()]
    
    Param(
    [Parameter(Position=0,Mandatory=$True,
    HelpMessage="Please specify an object",ValueFromPipeline=$True)]
    [ValidateNotNullorEmpty()]
    [object]$InputObject,
    [switch]$NoEmpty,
    [string[]]$Exclude
    )
    
    Process {
        #get type using the [Type] class because deserialized objects won't have
        #a GetType() method which is what we would normally use.
    
        $TypeName = [system.type]::GetTypeArray($InputObject).name
        Write-Verbose "Converting an object of type $TypeName"
        
        #get property names using Get-Member
        $names = $InputObject | Get-Member -MemberType properties | 
        Select-Object -ExpandProperty name 
    
        #define an empty hash table
        $hash = @{}
        
        #go through the list of names and add each property and value to the hash table
        $names | ForEach-Object {
            #only add properties that haven't been excluded
            if ($Exclude -notcontains $_) {
                #only add if -NoEmpty is not called and property has a value
                if ($NoEmpty -AND -Not ($inputobject.$_)) {
                    Write-Verbose "Skipping $_ as empty"
                }
                else {
                    Write-Verbose "Adding property $_"
                    $hash.Add($_,$inputobject.$_)
            }
            } #if exclude notcontains
            else {
                Write-Verbose "Excluding $_"
            }
        } #foreach
            Write-Verbose "Writing the result to the pipeline"
            Write-Output $hash
     }#close process
    
    }

if (Test-Path $SetupDiagExePath){
    Write-Log -Message "Setupdiag already Exists at $SetupDiagExePath. Copying over the file."
    Copy-item -Path '.\SetupDiag.exe' -Destination $SetupDiagExePath -Force
} Else {
    Write-Log -Message "Copying Setupdaig to: $SetupDiagExePath"
    Copy-item -Path '.\SetupDiag.exe' -Destination $SetupDiagExePath
}

try {
    Write-Log -Message "Runnning Setupdiag from $SetupDiagExePath"
    Start-Process -FilePath $SetupDiagExePath -ArgumentList '/AddReg' -WorkingDirectory "$SetupDiagWorkingDirectory" -WindowStyle Hidden -Wait -ErrorAction Stop
    Write-Log -Message "Completed Running Setupdiag from $SetupDiagExePath"
}
catch {
    Write-Log -Message "Error Running SetupDiag from $SetupDiagExePath" -Type 3
    Write-Log -Message "Exception: [$($_.Exception.Message)]" -Type 3
    Write-Log -Message "Exiting Script with exit code 1" -Type 2
    Exit 1
}

If (Test-Path -Path "HKLM:\SYSTEM\Setup\MoSetup\Volatile\SetupDiag"){
    Write-Log -Message "Looks like SetupDiag wrote something to the registry...  Lets take a look!"
    Try {
        $DiagnosticProperties = Get-ItemProperty "HKLM:\SYSTEM\Setup\MoSetup\Volatile\SetupDiag" -ErrorAction Stop | Select-Object -Property * -ExcludeProperty PS*
    }
    Catch {
        Write-Log -Message "Failed to collect diagnostic data from the registry." -Type 2
        Write-Log -Message "Exiting Script with exit code 1" -Type 2
        Exit 1
    }
    $UDHashTable = ConvertTo-HashTable $DiagnosticProperties
    If ($DiagnosticProperties.Remediation -like "null"){
        $Recommendation = "None Available"
    } else {
        $Recommendation = "$($DiagnosticProperties.Remediation)"
    }

$xaml = @"
<Window
 xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
 xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
 Title='SetupDiag Diagnostic data' SizeToContent='WidthAndHeight'>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="200" />
                <ColumnDefinition Width="Auto" />
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="28" />
                <RowDefinition Height="28" />
                <RowDefinition Height="38" />
                <RowDefinition Height="38" />
                <RowDefinition Height="38" />
                <RowDefinition Height="28" />
                <RowDefinition Height="20" />
                <RowDefinition Height="200" />
                <RowDefinition Height="28" />
            </Grid.RowDefinitions>
            <TextBlock Padding="5" Grid.Row="0" Grid.ColumnSpan="2">Below is a summary of the output from the SetupDiag.exe diagnostic tool. Use this information to help troubleshoot failed upgrades:</TextBlock>
            <TextBlock Padding="5" Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="1" Background="Azure">Execution Times:</TextBlock>
            <TextBlock Padding="5" Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="1" Background="Azure">Upgrade Start Time:<LineBreak />     $($DiagnosticProperties.UpgradeStartTime)</TextBlock>
            <TextBlock Padding="5" Grid.Row="3" Grid.Column="0" Grid.ColumnSpan="1" Background="Azure">  Upgrade End Time:<LineBreak />     $($DiagnosticProperties.UpgradeEndTime)</TextBlock>
            <TextBlock Padding="5" Grid.Row="4" Grid.Column="0" Grid.ColumnSpan="1" Background="Azure">Total Elapsed Time:<LineBreak />     $($DiagnosticProperties.UpgradeElapsedTime)</TextBlock>
            <TextBlock Padding="5" Grid.Row="5" Grid.Column="0" Grid.ColumnSpan="1">   </TextBlock>
            <TextBlock Padding="5" Grid.Row="6" Grid.Column="0" Grid.ColumnSpan="1" Background="AntiqueWhite" FontWeight="Bold" TextDecorations="Underline">Recommendation:</TextBlock>
            <TextBlock Padding="5" Grid.Row="7" Grid.Column="0" Grid.ColumnSpan="1" Background="AntiqueWhite" TextWrapping="Wrap">$Recommendation</TextBlock>
            <StackPanel Orientation="Horizontal" Grid.Row="8" Grid.ColumnSpan="2" HorizontalAlignment="Right">
                <Button Name='CopyToClip' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Copy To ClipBoard" />
                <Button Name='CloseWindow' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Close" />
            </StackPanel>
            <ListView Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="1" Grid.RowSpan="7" Name="View1" MinWidth="800">
                <ListView.View>
                    <GridView>
                        <GridViewColumn Width="200" Header="Name">
                            <GridViewColumn.CellTemplate>
                                <DataTemplate>
                                    <TextBlock TextWrapping="Wrap" Text="{Binding Key}" />
                                </DataTemplate>
                            </GridViewColumn.CellTemplate>
                        </GridViewColumn>
                        <GridViewColumn Width="600" Header="Details">
                            <GridViewColumn.CellTemplate>
                                <DataTemplate>
                                    <TextBlock TextWrapping="Wrap" Text="{Binding Value}" />
                                </DataTemplate>
                            </GridViewColumn.CellTemplate>
                        </GridViewColumn>
                    </GridView>
                </ListView.View>
            </ListView>
        </Grid>
</Window>
"@

Try{
    Write-Log -Message "Building diagnostic window...."
    Write-Log -Message "Converting XML..."
    $window = Convert-XAMLtoWindow -XAML $xaml
    Write-Log -Message "Adding Clicks..."
    $window.CloseWindow.add_Click{
        $window.DialogResult = $false
    }
    $window.CopyToClip.add_Click{
        ([pscustomobject]$UDHashTable) | clip
    }
    Write-Log -Message "Displaying Diagnostic Window...."
    $window.View1.ItemsSource = $UDHashTable
    $window.Topmost = $true #Make window display on top.
    $null = Show-WPFWindow -Window $window
}
Catch{
    Write-Log -Message "Failed to display diagnostic window." -Type 3
}
# Get Grid View of all properties:
# $DiagnosticProperties|ConvertTo-Hashtable|Out-GridView
} else {
    Write-Log -Message "Registry key for setupdiag was not found at [HKLM:\SYSTEM\Setup\MoSetup\Volatile\SetupDiag]." -Type 2
}