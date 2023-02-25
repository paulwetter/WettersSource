[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string[]]
    $Meat,
    [Parameter(Mandatory=$true)]
    [string]
    $Beverage,
    [Parameter(Mandatory=$false)]
    [string[]]
    $Eggs,
    [Parameter(Mandatory=$false)]
    [string]
    $Toast,
    [Parameter(Mandatory=$false)]
    [string]
    $Pastry,
    [Parameter(Mandatory=$false)]
    [int]
    $Servings = 1
)

Import-Module .\BreakfastModule\Breakfast.psd1

for ($i = 0; $i -lt $Servings; $i++) {
    Add-pwBeverage -Name $Beverage
    foreach ($BreakfastMeat in $Meat) {
        Add-pwBreakfastMeat -Name $BreakfastMeat
    }
    if ($PSBoundParameters.ContainsKey('Eggs')) {
        foreach ($Egg in $Eggs){
            Add-pwEggs -Name $Egg
        }
    }
    if ($PSBoundParameters.ContainsKey('Toast') -and $PSBoundParameters.ContainsKey('Pastry')) {
        Write-Warning "You're overloading on carbs.  We're only giving you a pastry as toast is just boring."
        Add-pwPastry -Name $Pastry
        if ($Pastry -like 'Apple Fritter') {
            Write-Output "You wanted toast and an Apple Fritter. I know we said no overloading on carbs, but you do want the worlds greatest pastery.  So, how about 2 apple fritters."
            Add-pwPastry -Name 'Apple Fritter'
        }
    } else {
        If ($PSBoundParameters.ContainsKey('Pastry')){
            Add-pwPastry -Name $Pastry
        }
        If ($PSBoundParameters.ContainsKey('Toast')){
            Add-pwToast -Name $Toast
        }
    }
}
