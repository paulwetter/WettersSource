#Building an array of 10,000 items in variable $ArrayList using the classic method of adding an index
$ArrayList = @()
foreach ($val in 1..20000) {
$ArrayList += $val}
"The array ArrayList has [$($ArrayList.count)] values"

#Building an array of 10,000 items in variable $Genericlist using the .Net data type
[System.Collections.Generic.List[int]]$Genericlist = @()
foreach ($val in 1..20000) {
$Genericlist.Add($val)}
"The array Genericlist has [$($Genericlist.count)] values"
