$CommandFiles = Get-ChildItem -Path "$PSScriptRoot\Commands" -Filter '*.ps1'
foreach($file in $CommandFiles){
    . $file.FullName
}

$PrivateCommandFiles = Get-ChildItem -Path "$PSScriptRoot\PrivateCommands" -Filter '*.ps1'
foreach($file in $PrivateCommandFiles){
    . $file.FullName
}
