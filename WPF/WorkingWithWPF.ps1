#Working on WPF
$xaml = @'
<Window
 xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
 xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
 Title='Process Killer' SizeToContent='WidthAndHeight'>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto" />
                <ColumnDefinition Width="Auto" />
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="40" />
                <RowDefinition Height="400" />
                <RowDefinition Height="28" />
            </Grid.RowDefinitions>
            <TextBlock Margin="5" Grid.ColumnSpan="2">Select Processes to terminate:</TextBlock>
            <ListView Grid.Row="1" Name="View1" MinWidth="500">
                <ListView.View>
                    <GridView>
                        <GridViewColumn Width="200" Header="Name" DisplayMemberBinding="{Binding Name}"/>
                        <GridViewColumn Width="400" Header="Window Title" DisplayMemberBinding="{Binding MainWindowTitle}"/>
                        <GridViewColumn Width="150" Header="Description" DisplayMemberBinding="{Binding Description}"/>
                        <GridViewColumn Width="100" Header="Producer" DisplayMemberBinding="{Binding Company}"/>
                    </GridView>
                </ListView.View>
            </ListView>
            <StackPanel Orientation="Vertical" Grid.Row="1" Grid.Column="1">
                <ListView Name="VarView" MinWidth="200">
                    <ListView.View>
                        <GridView>
                            <GridViewColumn Width="200" Header="Variable" DisplayMemberBinding="{Binding Name}"/>
                        </GridView>
                    </ListView.View>
                </ListView>
                <ListView Name="VarDetails" MinWidth="200">
                    <ListView.View>
                        <GridView>
                            <GridViewColumn Width="100" Header="Name" DisplayMemberBinding="{Binding Key}"/>
                            <GridViewColumn Width="100" Header="Value" DisplayMemberBinding="{Binding Value}"/>
                        </GridView>
                    </ListView.View>
                </ListView>
                <TextBlock Margin="1">Area of other stuff</TextBlock>
                <Button Name="CloseWindow2" MinWidth="80" Margin="3" Content="Close" />
            </StackPanel>
            <StackPanel Orientation="Horizontal" Grid.Row="2" Grid.ColumnSpan="2" HorizontalAlignment="Right">
                <Button Name='KillProcess' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Kill Process" />
                <Button Name='CloseWindow' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Close" />
            </StackPanel>
        </Grid>
</Window>
'@

function Convert-XAMLtoWindow
{
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


function Show-WPFWindow
{
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

$window = Convert-XAMLtoWindow -XAML $xaml

$window.KillProcess.add_Click{
    # remove -whatif to actually kill processes:
    $window.View1.SelectedItems | Stop-Process -WhatIf
    $window.View1.ItemsSource = @(Get-Process | Where-Object { $_.MainWindowTitle })
}

$window.CloseWindow.add_Click{
    $window.DialogResult = $false
}

$window.View1.ItemsSource = @(Get-Process | Where-Object { $_.MainWindowTitle })
$window.VarView.ItemsSource = @(Get-PSDrive)

$VarView = $Window.FindName('VarView')
$VarView.Add_SelectionChanged({
    $PSDrive = (Get-PSDrive $window.VarView.SelectedItems)|ConvertTo-HashTable
    $window.VarDetails.ItemsSource = $PSDrive
    #$window.Details.Text = "Name: $($PSDrive.Name) `nProvider: $($Psdrive.Provider) `nRoot: $($PSDrive.Root)"
})


$null = Show-WPFWindow -Window $window