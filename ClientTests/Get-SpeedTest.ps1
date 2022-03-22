#Replace the Download URL to where you've uploaded the ZIP file yourself. We will only download this file once. 
#Latest version can be found at: https://www.speedtest.net/nl/apps/cli
$DownloadURL = "https://install.speedtest.net/app/cli/ookla-speedtest-1.1.1-win64.zip"
$DownloadLocation = "$($Env:Temp)\SpeedtestCLI"
try {
    if (!(Test-Path $DownloadLocation)) {
        new-item $DownloadLocation -ItemType Directory -force
    }
    If (!(Test-Path "$($DownloadLocation)\speedtest.exe")){
        If ((Test-Path "$($DownloadLocation)\speedtest.zip")){
            Remove-Item -Path "$($DownloadLocation)\speedtest.zip" -Force
        }
        Invoke-WebRequest -Uri $DownloadURL -OutFile "$($DownloadLocation)\speedtest.zip"
        Expand-Archive "$($DownloadLocation)\speedtest.zip" -DestinationPath $DownloadLocation -Force
    }
}
catch {  
    write-host "The download and extraction of SpeedtestCLI failed. Error: $($_.Exception.Message)"
    exit 1
}
$SpeedtestResults = & "$($DownloadLocation)\speedtest.exe" --format=json --accept-license --accept-gdpr
$SpeedtestResults = $SpeedtestResults | ConvertFrom-Json
 
#creating object
[PSCustomObject]@{
    downloadspeed = [math]::Round($SpeedtestResults.download.bandwidth / 1000000 * 8, 2)
    uploadspeed   = [math]::Round($SpeedtestResults.upload.bandwidth / 1000000 * 8, 2)
    packetloss    = [math]::Round($SpeedtestResults.packetLoss)
    isp           = $SpeedtestResults.isp
    ExternalIP    = $SpeedtestResults.interface.externalIp
    InternalIP    = $SpeedtestResults.interface.internalIp
    UsedServer    = $SpeedtestResults.server.host
    ResultsURL    = $SpeedtestResults.result.url
    Jitter        = [math]::Round($SpeedtestResults.ping.jitter)
    Latency       = [math]::Round($SpeedtestResults.ping.latency)
}
