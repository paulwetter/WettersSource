#WPF Return to Parent
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

$xaml1 = @'
<Window
 xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
 xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
 Title='Process Killer' SizeToContent='WidthAndHeight'>
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="40" />
                <RowDefinition Height="400" />
                <RowDefinition Height="28" />
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Margin="5">Select Processes to terminate:</TextBlock>
            <ListView Grid.Row="1" Name="View1">
                <ListView.View>
                    <GridView>
                        <GridViewColumn Width="200" Header="Name" DisplayMemberBinding="{Binding Name}"/>
                        <GridViewColumn Width="400" Header="Window Title" DisplayMemberBinding="{Binding MainWindowTitle}"/>
                        <GridViewColumn Width="150" Header="Description" DisplayMemberBinding="{Binding Description}"/>
                        <GridViewColumn Width="100" Header="Producer" DisplayMemberBinding="{Binding Company}"/>
                    </GridView>
                </ListView.View>
            </ListView>
            <StackPanel Orientation="Horizontal" Grid.Row="2" HorizontalAlignment="Right">
                <Button Name='SelectSources' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Get Sources" />
                <Button Name='KillProcess' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Kill Process" />
                <Button Name='CloseWindow' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Close" />
            </StackPanel>
        </Grid>
    </Window>
'@

function Select-Sources {
[CmdletBinding()]
param ()
$xaml2 = @'
<Window
 xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
 xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
 Title='Process Killer' SizeToContent='WidthAndHeight'>
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="40" />
                <RowDefinition Height="400" />
                <RowDefinition Height="28" />
            </Grid.RowDefinitions>
            <TextBlock Grid.Row="0" Margin="5">Select Processes to terminate:</TextBlock>
            <ListView Grid.Row="1" Name="View2">
                <ListView.View>
                    <GridView>
                        <GridViewColumn Width="200" Header="Name" DisplayMemberBinding="{Binding Name}"/>
                        <GridViewColumn Width="400" Header="Window Title" DisplayMemberBinding="{Binding MainWindowTitle}"/>
                        <GridViewColumn Width="150" Header="Description" DisplayMemberBinding="{Binding Description}"/>
                        <GridViewColumn Width="100" Header="Producer" DisplayMemberBinding="{Binding Company}"/>
                    </GridView>
                </ListView.View>
            </ListView>
            <StackPanel Orientation="Horizontal" Grid.Row="2" HorizontalAlignment="Right">
                <Button Name='SelectedItems' HorizontalAlignment="Left" MinWidth="80" Margin="3" Content="Select These" />
                <Button Name='CloseChild' HorizontalAlignment="Right" MinWidth="80" Margin="3" Content="Cancel" />
            </StackPanel>
        </Grid>
    </Window>
'@
    $window2 = Convert-XAMLtoWindow -XAML $xaml2
    $window2.SelectedItems.add_Click{
        Set-Variable -Scope Script -Name ReturnItems -Value $window2.View2.SelectedItems
        $window2.DialogResult = $false
        #Return $ReturnItems
    }
    $window2.CloseChild.add_Click{
        $window2.DialogResult = $false
    }
    $window2.View2.ItemsSource = @(Get-Process | Where-Object { $_.MainWindowTitle })
    $null = Show-WPFWindow -Window $window2

}

$window = Convert-XAMLtoWindow -XAML $xaml1

$window.KillProcess.add_Click{
    # remove -whatif to actually kill processes:
    $window.View1.SelectedItems | Stop-Process -WhatIf
#    $window.View1.ItemsSource = @(Get-Process | Where-Object { $_.MainWindowTitle })
}

$window.SelectSources.add_Click{
    Select-Sources
    $window.View1.ItemsSource = $ReturnItems
    write-host "green"
    write-host $ReturnItems
    Remove-Variable ReturnItems -ErrorAction Ignore
    write-host "blue"
}

$window.CloseWindow.add_Click{
    $window.DialogResult = $false
}

#$window.View1.ItemsSource = @(Get-Process | Where-Object { $_.MainWindowTitle })
#$window.View1.ItemsSource =

#$global:OrderIndex = 0
$null = Show-WPFWindow -Window $window
