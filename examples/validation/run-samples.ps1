param(
    [string]$Gateway = "http://localhost:18081",
    [string]$HostHeader = "example.local"
)

$ErrorActionPreference = "Stop"

function Invoke-Sample {
    param(
        [string]$Name,
        [string]$Expected,
        [string]$Url
    )

    $code = curl.exe -s -o NUL -w "%{http_code}" -H "Host: $HostHeader" $Url
    Write-Host ("{0,-18} expected={1} actual={2}" -f $Name, $Expected, $code)
    if ($code -ne $Expected) {
        throw "Sample '$Name' expected HTTP $Expected but got $code"
    }
}

Invoke-Sample -Name "normal" -Expected "200" -Url "$Gateway/echo"
Invoke-Sample -Name "sqli" -Expected "403" -Url "$Gateway/?q=union%20select"
Invoke-Sample -Name "xss" -Expected "403" -Url "$Gateway/?q=%3Cscript%3Ealert(1)%3C/script%3E"
Invoke-Sample -Name "rce" -Expected "403" -Url "$Gateway/?cmd=%3Bcat%20/etc/passwd"

Write-Host "LiteWaf validation samples passed."
