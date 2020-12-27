<#
.SYNOPSIS
This script is run from the system context to generate a toast notificatio in the logged in users context.

.DESCRIPTION
This script is run from the system context to generate a toast notificatio in the logged in users context.  It uses
portions of the PSADT to discover the logged on user and create a scheduled task that will run in the user's context.
The parameters define the content of the toast.  However, the images are baked into the script and would have to be 
changed in the script.

.PARAMETER HeaderText
The header text is the text next to the logo.  This could be similar to a from tag.

.PARAMETER TitleText
This is the heading first line in the toast notification.  Sort of like the subject line.

.PARAMETER BodyText1
This is the first paragraph in the body of the toast and is a required fielt.

.PARAMETER BodyText2
This is the second paragraph in the body of the toast and is not required.

.PARAMETER AlertTime
This is like the Sent time in an email, just in case the toast is sitting on the computer for hours.

.PARAMETER Expiration
This is the date/time that the toast will no longer display after and is an optional field.  So, if something is very
time sensitive and you don't want it to deliver more than an hour after it has been sent, this can be used to confirm
that will happen.

.PARAMETER Scenario
Possible values are: reminder | short | long
How long displayed:
--Reminder: Until Dismissed
--Short: 5 seconds
--Long: 25 seconds 

.PARAMETER DismissButtonText
This is the text that is displayed in the single button at the bottom of the toast message. Dismiss is the default text.

.EXAMPLE
An example

.NOTES
	NAME: Invoke-ToastAsUser.ps1
	VERSION: 1.0
	AUTHOR: Paul Wetter
        Based on content from the PowerShell App Deployment Toolkit (https://psappdeploytoolkit.com)
	LASTEDIT: December 26, 2020
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [String]
    $HeaderText = 'Important message from IT...',
    [Parameter(Mandatory = $true)]
    [String]
    $TitleText,
    [Parameter(Mandatory = $true)]
    [String]
    $BodyText1,
    [Parameter(Mandatory = $false)]
    [String]
    $BodyText2,
    #Format 'MM/dd/yyyy @ hh:mm tt'
    [Parameter(Mandatory = $false)]
    [String]
    $AlertTime = (Get-Date -Format 'MM/dd/yyyy @ hh:mm tt'),
    #Format 'MM/dd/yyyy @ hh:mm tt'
    [Parameter(Mandatory = $false)]
    [String]
    $Expiration,
    #Scenario Possible values are: reminder | short | long --- How long displayed::: Reminder: Until Dismissed, Short: 5 seconds, Long: 25 seconds 
    [Parameter(Mandatory = $false)]
    [String]
    $Scenario = 'Reminder',
    [Parameter(Mandatory = $false)]
    [String]
    $DismissButtonText = 'Dismiss'
)

#If the Expiration variable has been defined and is a Date/Time, then check if the current time is beyond the exipiration time.
If (![string]::IsNullOrEmpty($Expiration)){
    Try {
        $ExpireDate = Get-Date $Expiration -ErrorAction Stop
        if ($ExpireDate -lt (Get-Date)){
            Exit
        }
    }
    Catch{}
}


Function Invoke-ProcessAsUser {
    <#
    .SYNOPSIS
        Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context.
    .DESCRIPTION
        Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context.
    .PARAMETER UserName
        Logged in Username under which to run the process from. Default is: The active console user. If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user.
    .PARAMETER Path
        Path to the file being executed.
    .PARAMETER Parameters
        Arguments to be passed to the file being executed.
    .PARAMETER SecureParameters
        Hides all parameters passed to the executable from the Toolkit log file.
    .PARAMETER RunLevel
        Specifies the level of user rights that Task Scheduler uses to run the task. The acceptable values for this parameter are:
        - HighestAvailable: Tasks run by using the highest available privileges (Admin privileges for Administrators). Default Value.
        - LeastPrivilege: Tasks run by using the least-privileged user account (LUA) privileges.
    .PARAMETER Wait
        Wait for the process, launched by the scheduled task, to complete execution before accepting more input. Default is $false.
    .PARAMETER PassThru
        Returns the exit code from this function or the process launched by the scheduled task.
    .PARAMETER WorkingDirectory
        Set working directory for the process.
    .PARAMETER ContinueOnError
        Continue if an error is encountered. Default is $true.
    .EXAMPLE
        Execute-ProcessAsUser -UserName 'CONTOSO\User' -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\Test\Script.ps1`"; Exit `$LastExitCode }" -Wait
        Execute process under a user account by specifying a username under which to execute it.
    .EXAMPLE
        Execute-ProcessAsUser -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\Test\Script.ps1`"; Exit `$LastExitCode }" -Wait
        Execute process under a user account by using the default active logged in user that was detected when the toolkit was launched.
    .NOTES
    .LINK
        http://psappdeploytoolkit.com
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false)]
            [ValidateNotNullorEmpty()]
            [string]$UserName = $RunAsActiveUser.NTAccount,
            [Parameter(Mandatory=$true)]
            [ValidateNotNullorEmpty()]
            [string]$Path,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullorEmpty()]
            [string]$Parameters = '',
            [Parameter(Mandatory=$false)]
            [switch]$SecureParameters = $false,
            [Parameter(Mandatory=$false)]
            [ValidateSet('HighestAvailable','LeastPrivilege')]
            [string]$RunLevel = 'HighestAvailable',
            [Parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [switch]$Wait = $false,
            [Parameter(Mandatory=$false)]
            [switch]$PassThru = $false,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [string]$WorkingDirectory,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [boolean]$ContinueOnError = $true
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            [string]$executeAsUserTempPath = Join-Path -Path $dirAppDeployTemp -ChildPath 'ExecuteAsUser'
            [string]$exeSchTasks = Join-Path -Path ${ENV:windir} -ChildPath 'System32\schtasks.exe' # Manages Scheduled Tasks
        }
        Process {
            ## Initialize exit code variable
            [int32]$executeProcessAsUserExitCode = 0

            ## Confirm that the username field is not empty
            If (-not $UserName) {
                [int32]$executeProcessAsUserExitCode = 60009
                Write-Verbose -Message "The function [${CmdletName}] has a -UserName parameter that has an empty default value because no logged in users were detected when the toolkit was launched."
                If (-not $ContinueOnError) {
                    Throw "The function [${CmdletName}] has a -UserName parameter that has an empty default value because no logged in users were detected when the toolkit was launched."
                }
                Return
            }

            ## Confirm if the toolkit is running with administrator privileges
            If (($RunLevel -eq 'HighestAvailable') -and (-not $IsAdmin)) {
                [int32]$executeProcessAsUserExitCode = 60003
                Write-Verbose -Message "The function [${CmdletName}] requires the toolkit to be running with Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'."
                If (-not $ContinueOnError) {
                    Throw "The function [${CmdletName}] requires the toolkit to be running with Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'."
                }
                Return
            }

            ## Check whether the specified Working Directory exists
            If ($WorkingDirectory -and (-not (Test-Path -LiteralPath $WorkingDirectory -PathType 'Container'))) {
                Write-Verbose -Message "The specified working directory does not exist or is not a directory. The scheduled task might not work as expected."
            }

            ## Build the scheduled task XML name
            [string]$schTaskName = "ITAlert-ExecuteAsUser"
    
            ##  Remove and recreate the temporary folder
            If (Test-Path -LiteralPath $executeAsUserTempPath -PathType 'Container') {
                Write-Verbose -Message "Previous [$executeAsUserTempPath] found. Attempting removal."
                Remove-Item -LiteralPath $executeAsUserTempPath -Force -Recurse -ErrorAction 'SilentlyContinue'
            }
            Write-Verbose -Message "Creating [$executeAsUserTempPath]."
            Try {
                $null = New-Item -Path $executeAsUserTempPath -ItemType 'Directory' -ErrorAction 'Stop'
            }
            Catch {
                Write-Verbose -Message "Unable to create [$executeAsUserTempPath]. Possible attempt to gain elevated rights."
            }

            ## If PowerShell.exe is being launched, then create a VBScript to launch PowerShell so that we can suppress the console window that flashes otherwise
            If (((Split-Path -Path $Path -Leaf) -like 'PowerShell*') -or ((Split-Path -Path $Path -Leaf) -like 'cmd*')) {
                If ($SecureParameters) {
                    Write-Verbose -Message "Preparing a vbs script that will start [$Path] (Parameters Hidden) as the logged-on user [$userName] silently..."
                }
                Else {
                    Write-Verbose -Message "Preparing a vbs script that will start [$Path $Parameters] as the logged-on user [$userName] silently..."
                }
                # Permit inclusion of double quotes in parameters
                $QuotesIndex = $Parameters.Length - 1
                If ($QuotesIndex -lt 0) {
                    $QuotesIndex = 0
                }
    
                If ($($Parameters.Substring($QuotesIndex)) -eq '"') {
                    [string]$executeProcessAsUserParametersVBS = 'chr(34) & ' + "`"$($Path)`"" + ' & chr(34) & ' + '" ' + ($Parameters -replace "`r`n", ';' -replace "`n", ';' -replace '"', "`" & chr(34) & `"" -replace ' & chr\(34\) & "$', '') + ' & chr(34)' }
                Else {
                    [string]$executeProcessAsUserParametersVBS = 'chr(34) & ' + "`"$($Path)`"" + ' & chr(34) & ' + '" ' + ($Parameters -replace "`r`n", ';' -replace "`n", ';' -replace '"', "`" & chr(34) & `"" -replace ' & chr\(34\) & "$','') + '"' }
                [string[]]$executeProcessAsUserScript = "strCommand = $executeProcessAsUserParametersVBS"
                $executeProcessAsUserScript += 'set oWShell = CreateObject("WScript.Shell")'
                $executeProcessAsUserScript += 'intReturn = oWShell.Run(strCommand, 0, true)'
                $executeProcessAsUserScript += 'WScript.Quit intReturn'
                $executeProcessAsUserScript | Out-File -FilePath "$executeAsUserTempPath\$($schTaskName).vbs" -Force -Encoding 'default' -ErrorAction 'SilentlyContinue'
                $Path = "${ENV:WinDir}\System32\wscript.exe"
                $Parameters = "`"$executeAsUserTempPath\$($schTaskName).vbs`""
                Start-Sleep -Seconds 5
                try {
                    #Set-ItemPermission -Path "$executeAsUserTempPath\$schTaskName.vbs" -User $UserName -Permission 'Read'
                }
                catch {
                    Write-Verbose -Message "Failed to set read permissions on path [$executeAsUserTempPath\$schTaskName.vbs]. The function might not be able to work correctly."
                }
            }
            ## Prepare working directory insert
            [string]$WorkingDirectoryInsert = ""
            If ($WorkingDirectory) {
                $WorkingDirectoryInsert = "`n	  <WorkingDirectory>$WorkingDirectory</WorkingDirectory>"
            }
            ## Specify the scheduled task configuration in XML format
            [string]$xmlSchTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo />
    <Triggers />
    <Settings>
    <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
        <StopOnIdleEnd>false</StopOnIdleEnd>
        <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
    </Settings>
    <Actions Context="Author">
    <Exec>
        <Command>$Path</Command>
        <Arguments>$Parameters</Arguments>$WorkingDirectoryInsert
    </Exec>
    </Actions>
    <Principals>
    <Principal id="Author">
        <UserId>$UserName</UserId>
        <LogonType>InteractiveToken</LogonType>
        <RunLevel>$RunLevel</RunLevel>
    </Principal>
    </Principals>
</Task>
"@
            ## Export the XML to file
            Try {
                #  Specify the filename to export the XML to
                [string]$xmlSchTaskFilePath = "$dirAppDeployTemp\$schTaskName.xml"
                [string]$xmlSchTask | Out-File -FilePath $xmlSchTaskFilePath -Force -ErrorAction 'Stop'
                #Set-ItemPermission -Path $xmlSchTaskFilePath -User $UserName -Permission 'Read'
            }
            Catch {
                [int32]$executeProcessAsUserExitCode = 60007
                Write-Verbose -Message "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]."
                If (-not $ContinueOnError) {
                    Throw "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]: $($_.Exception.Message)"
                }
                Return
            }
            ## Create Scheduled Task to run the process with a logged-on user account
            If ($Parameters) {
                If ($SecureParameters) {
                    Write-Verbose -Message "Creating scheduled task to run the process [$Path] (Parameters Hidden) as the logged-on user [$userName]..."
                }
                Else {
                    Write-Verbose -Message "Creating scheduled task to run the process [$Path $Parameters] as the logged-on user [$userName]..."
                }
            }
            Else {
                Write-Verbose -Message "Creating scheduled task to run the process [$Path] as the logged-on user [$userName]..."
            }
            $schTaskResult = Start-Process -FilePath $exeSchTasks -ArgumentList "/create /f /tn $schTaskName /xml `"$xmlSchTaskFilePath`"" -WindowStyle Hidden -PassThru
            If ($schTaskResult.ExitCode -ne 0) {
                Write-Verbose -Message 'Try to see if it exists from a query. may not trigger the right one.'
                If ([string]::IsNullOrEmpty((schtasks.exe /query| where {$_ -like "*$schTaskNam*"}))){
                    [int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
                    Write-Verbose -Message "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]. [$($schTaskResult.ExitCode)]"
                    If (-not $ContinueOnError) {
                        Throw "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]."
                    }
                    Return
                } else {
                    Write-Verbose -Message 'Try to see if it exists from a query. may not trigger the right one.'
                }
            }

            ## Trigger the Scheduled Task
            If ($Parameters) {
                If ($SecureParameters) {
                    Write-Verbose -Message "Trigger execution of scheduled task with command [$Path] (Parameters Hidden) as the logged-on user [$userName]..."
                }
                Else {
                    Write-Verbose -Message "Trigger execution of scheduled task with command [$Path $Parameters] as the logged-on user [$userName]..."
                }
            }
            Else {
                Write-Verbose -Message "Trigger execution of scheduled task with command [$Path] as the logged-on user [$userName]..."
            }
            Try {
                Start-ScheduledTask -TaskName $schTaskName -ErrorAction Stop
            }
            Catch {
                Write-Verbose -Message "Failed to trigger scheduled task [$schTaskName]."
                #  Delete Scheduled Task
                Write-Verbose -Message 'Delete the scheduled task which did not trigger.'
                Start-Process -FilePath $exeSchTasks -ArgumentList "/delete /tn $schTaskName /f" -WindowStyle Hidden
                If (-not $ContinueOnError) {
                    Throw "Failed to trigger scheduled task [$schTaskName]."
                }
                Return
            }
    
            ## Wait for the process launched by the scheduled task to complete execution
            If ($Wait) {
                Write-Verbose -Message "Waiting for the process launched by the scheduled task [$schTaskName] to complete execution (this may take some time)..."
                Start-Sleep -Seconds 1
                Try {
                    [__comobject]$ScheduleService = New-Object -ComObject 'Schedule.Service' -ErrorAction Stop
                    $ScheduleService.Connect()
                    $RootFolder = $ScheduleService.GetFolder('\')
                    $Task = $RootFolder.GetTask("$schTaskName")
                    # Task State(Status) 4 = 'Running'
                    While ($Task.State -eq 4) {
                        Start-Sleep -Seconds 5
                    }
                    #  Get the exit code from the process launched by the scheduled task
                    [int32]$executeProcessAsUserExitCode = $Task.LastTaskResult
                }
                Catch {
                    Write-Verbose -Message "Failed to retrieve information from Task Scheduler."
                }
                Finally {
                    Try { $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($ScheduleService) } Catch { }
                }
                Write-Verbose -Message "Exit code from process launched by scheduled task [$executeProcessAsUserExitCode]."
            }
            Else {
                Start-Sleep -Seconds 1
            }

            ## Delete scheduled task
            Try {
                Write-Verbose -Message "Delete scheduled task [$schTaskName]."
                Start-Process -FilePath $exeSchTasks -ArgumentList "/delete /tn $schTaskName /f" -WindowStyle Hidden -ErrorAction 'Stop'
            }
            Catch {
                Write-Verbose -Message "Failed to delete scheduled task [$schTaskName]."
            }

    
            ## Remove the XML scheduled task file
            If (Test-Path -LiteralPath $xmlSchTaskFilePath -PathType 'Leaf') {
                Remove-Item -LiteralPath $xmlSchTaskFilePath -Force -Recurse -ErrorAction 'SilentlyContinue'
            }
    
            ##  Remove the temporary folder
            If (Test-Path -LiteralPath $executeAsUserTempPath -PathType 'Container') {
                Remove-Item -LiteralPath $executeAsUserTempPath -Force -Recurse -ErrorAction 'SilentlyContinue'
            }
        }
        End {
            If ($PassThru) { Write-Output -InputObject $executeProcessAsUserExitCode }
        }
}


Function Get-LoggedOnUser {
<#
.SYNOPSIS
    Get session details for all local and RDP logged on users.
.DESCRIPTION
    Get session details for all local and RDP logged on users using Win32 APIs. Get the following session details:
        NTAccount, SID, UserName, DomainName, SessionId, SessionName, ConnectState, IsCurrentSession, IsConsoleSession, IsUserSession, IsActiveUserSession
        IsRdpSession, IsLocalAdmin, LogonTime, IdleTime, DisconnectTime, ClientName, ClientProtocolType, ClientDirectory, ClientBuildNumber
.EXAMPLE
    Get-LoggedOnUser
.NOTES
    Description of ConnectState property:
    Value		 Description
    -----		 -----------
    Active		 A user is logged on to the session.
    ConnectQuery The session is in the process of connecting to a client.
    Connected	 A client is connected to the session.
    Disconnected The session is active, but the client has disconnected from it.
    Down		 The session is down due to an error.
    Idle		 The session is waiting for a client to connect.
    Initializing The session is initializing.
    Listening 	 The session is listening for connections.
    Reset		 The session is being reset.
    Shadowing	 This session is shadowing another session.

    Description of IsActiveUserSession property:
    If a console user exists, then that will be the active user session.
    If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user that is either 'Active' or 'Connected' is the active user.

    Description of IsRdpSession property:
    Gets a value indicating whether the user is associated with an RDP client session.
.LINK
    http://psappdeploytoolkit.com
#>
    [CmdletBinding()]
    Param (
    )
    Try {
        Write-Output -InputObject ([PSADT.QueryUser]::GetUserSessionInfo("$env:ComputerName"))
    }
    Catch {
    }
}

function Add-PSADTCustom {
    <#
    .SYNOPSIS
        This function adds the custom C# code from the PSADT needed to get the logged on user.
    .DESCRIPTION
        In the PSADT, this code is loaded with other classes used by the toolkit.  I have trimmed 
        the C# down to only the code for the QueryUser class.
        Only load this once per powershell session or you will get errors returned.
    .EXAMPLE
        Add-PSADTCustom
    #>
    [CmdletBinding()]
    param ()
    $signature = @"
    using System;
    using System.Text;
    using System.Collections;
    using System.ComponentModel;
    using System.DirectoryServices;
    using System.Security.Principal;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.Text.RegularExpressions;
    using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;
    
    namespace PSADT
    {
        public class QueryUser
        {
            [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern IntPtr WTSOpenServer(string pServerName);
    
            [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern void WTSCloseServer(IntPtr hServer);
    
            [DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
            public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr pBuffer, out int pBytesReturned);
    
            [DllImport("wtsapi32.dll", CharSet = CharSet.Ansi, SetLastError = false)]
            public static extern int WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr pSessionInfo, out int pCount);
    
            [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern void WTSFreeMemory(IntPtr pMemory);
    
            [DllImport("winsta.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern int WinStationQueryInformation(IntPtr hServer, int sessionId, int information, ref WINSTATIONINFORMATIONW pBuffer, int bufferLength, ref int returnedLength);
    
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern int GetCurrentProcessId();
    
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
            public static extern bool ProcessIdToSessionId(int processId, ref int pSessionId);
    
            public class TerminalSessionData
            {
                public int SessionId;
                public string ConnectionState;
                public string SessionName;
                public bool IsUserSession;
                public TerminalSessionData(int sessionId, string connState, string sessionName, bool isUserSession)
                {
                    SessionId = sessionId;
                    ConnectionState = connState;
                    SessionName = sessionName;
                    IsUserSession = isUserSession;
                }
            }
    
            public class TerminalSessionInfo
            {
                public string NTAccount;
                public string SID;
                public string UserName;
                public string DomainName;
                public int SessionId;
                public string SessionName;
                public string ConnectState;
                public bool IsCurrentSession;
                public bool IsConsoleSession;
                public bool IsActiveUserSession;
                public bool IsUserSession;
                public bool IsRdpSession;
                public bool IsLocalAdmin;
                public DateTime? LogonTime;
                public TimeSpan? IdleTime;
                public DateTime? DisconnectTime;
                public string ClientName;
                public string ClientProtocolType;
                public string ClientDirectory;
                public int ClientBuildNumber;
            }
    
            [StructLayout(LayoutKind.Sequential)]
            private struct WTS_SESSION_INFO
            {
                public Int32 SessionId;
                [MarshalAs(UnmanagedType.LPStr)]
                public string SessionName;
                public WTS_CONNECTSTATE_CLASS State;
            }
    
            [StructLayout(LayoutKind.Sequential)]
            public struct WINSTATIONINFORMATIONW
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 70)]
                private byte[] Reserved1;
                public int SessionId;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
                private byte[] Reserved2;
                public FILETIME ConnectTime;
                public FILETIME DisconnectTime;
                public FILETIME LastInputTime;
                public FILETIME LoginTime;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1096)]
                private byte[] Reserved3;
                public FILETIME CurrentTime;
            }
    
            public enum WINSTATIONINFOCLASS
            {
                WinStationInformation = 8
            }
    
            public enum WTS_CONNECTSTATE_CLASS
            {
                Active,
                Connected,
                ConnectQuery,
                Shadow,
                Disconnected,
                Idle,
                Listen,
                Reset,
                Down,
                Init
            }
    
            public enum WTS_INFO_CLASS
            {
                SessionId=4,
                UserName,
                SessionName,
                DomainName,
                ConnectState,
                ClientBuildNumber,
                ClientName,
                ClientDirectory,
                ClientProtocolType=16
            }
    
            private static IntPtr OpenServer(string Name)
            {
                IntPtr server = WTSOpenServer(Name);
                return server;
            }
    
            private static void CloseServer(IntPtr ServerHandle)
            {
                WTSCloseServer(ServerHandle);
            }
    
            private static IList<T> PtrToStructureList<T>(IntPtr ppList, int count) where T : struct
            {
                List<T> result = new List<T>();
                long pointer = ppList.ToInt64();
                int sizeOf = Marshal.SizeOf(typeof(T));
    
                for (int index = 0; index < count; index++)
                {
                    T item = (T) Marshal.PtrToStructure(new IntPtr(pointer), typeof(T));
                    result.Add(item);
                    pointer += sizeOf;
                }
                return result;
            }
    
            public static DateTime? FileTimeToDateTime(FILETIME ft)
            {
                if (ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0)
                {
                    return null;
                }
                long hFT = (((long) ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
                return DateTime.FromFileTime(hFT);
            }
    
            public static WINSTATIONINFORMATIONW GetWinStationInformation(IntPtr server, int sessionId)
            {
                int retLen = 0;
                WINSTATIONINFORMATIONW wsInfo = new WINSTATIONINFORMATIONW();
                WinStationQueryInformation(server, sessionId, (int) WINSTATIONINFOCLASS.WinStationInformation, ref wsInfo, Marshal.SizeOf(typeof(WINSTATIONINFORMATIONW)), ref retLen);
                return wsInfo;
            }
    
            public static TerminalSessionData[] ListSessions(string ServerName)
            {
                IntPtr server = IntPtr.Zero;
                if (ServerName == "localhost" || ServerName == String.Empty)
                {
                    ServerName = Environment.MachineName;
                }
    
                List<TerminalSessionData> results = new List<TerminalSessionData>();
    
                try
                {
                    server = OpenServer(ServerName);
                    IntPtr ppSessionInfo = IntPtr.Zero;
                    int count;
                    bool _isUserSession = false;
                    IList<WTS_SESSION_INFO> sessionsInfo;
    
                    if (WTSEnumerateSessions(server, 0, 1, out ppSessionInfo, out count) == 0)
                    {
                        throw new Win32Exception();
                    }
    
                    try
                    {
                        sessionsInfo = PtrToStructureList<WTS_SESSION_INFO>(ppSessionInfo, count);
                    }
                    finally
                    {
                        WTSFreeMemory(ppSessionInfo);
                    }
    
                    foreach (WTS_SESSION_INFO sessionInfo in sessionsInfo)
                    {
                        if (sessionInfo.SessionName != "Services" && sessionInfo.SessionName != "RDP-Tcp")
                        {
                            _isUserSession = true;
                        }
                        results.Add(new TerminalSessionData(sessionInfo.SessionId, sessionInfo.State.ToString(), sessionInfo.SessionName, _isUserSession));
                        _isUserSession = false;
                    }
                }
                finally
                {
                    CloseServer(server);
                }
    
                TerminalSessionData[] returnData = results.ToArray();
                return returnData;
            }
    
            public static TerminalSessionInfo GetSessionInfo(string ServerName, int SessionId)
            {
                IntPtr server = IntPtr.Zero;
                IntPtr buffer = IntPtr.Zero;
                int bytesReturned;
                TerminalSessionInfo data = new TerminalSessionInfo();
                bool _IsCurrentSessionId = false;
                bool _IsConsoleSession = false;
                bool _IsUserSession = false;
                int currentSessionID = 0;
                string _NTAccount = String.Empty;
                if (ServerName == "localhost" || ServerName == String.Empty)
                {
                    ServerName = Environment.MachineName;
                }
                if (ProcessIdToSessionId(GetCurrentProcessId(), ref currentSessionID) == false)
                {
                    currentSessionID = -1;
                }
    
                // Get all members of the local administrators group
                bool _IsLocalAdminCheckSuccess = false;
                List<string> localAdminGroupSidsList = new List<string>();
                try
                {
                    DirectoryEntry localMachine = new DirectoryEntry("WinNT://" + ServerName + ",Computer");
                    string localAdminGroupName = new SecurityIdentifier("S-1-5-32-544").Translate(typeof(NTAccount)).Value.Split('\\')[1];
                    DirectoryEntry admGroup = localMachine.Children.Find(localAdminGroupName, "group");
                    object members = admGroup.Invoke("members", null);
                    string validSidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";
                    foreach (object groupMember in (IEnumerable)members)
                    {
                        DirectoryEntry member = new DirectoryEntry(groupMember);
                        if (member.Name != String.Empty)
                        {
                            if (Regex.IsMatch(member.Name, validSidPattern))
                            {
                                localAdminGroupSidsList.Add(member.Name);
                            }
                            else
                            {
                                localAdminGroupSidsList.Add((new NTAccount(member.Name)).Translate(typeof(SecurityIdentifier)).Value);
                            }
                        }
                    }
                    _IsLocalAdminCheckSuccess = true;
                }
                catch { }
    
                try
                {
                    server = OpenServer(ServerName);
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientBuildNumber, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    int lData = Marshal.ReadInt32(buffer);
                    data.ClientBuildNumber = lData;
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientDirectory, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    string strData = Marshal.PtrToStringAnsi(buffer);
                    data.ClientDirectory = strData;
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientName, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    strData = Marshal.PtrToStringAnsi(buffer);
                    data.ClientName = strData;
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ClientProtocolType, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    Int16 intData = Marshal.ReadInt16(buffer);
                    if (intData == 2)
                    {
                        strData = "RDP";
                        data.IsRdpSession = true;
                    }
                    else
                    {
                        strData = "";
                        data.IsRdpSession = false;
                    }
                    data.ClientProtocolType = strData;
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.ConnectState, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    lData = Marshal.ReadInt32(buffer);
                    data.ConnectState = ((WTS_CONNECTSTATE_CLASS) lData).ToString();
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.SessionId, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    lData = Marshal.ReadInt32(buffer);
                    data.SessionId = lData;
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.DomainName, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    strData = Marshal.PtrToStringAnsi(buffer).ToUpper();
                    data.DomainName = strData;
                    if (strData != String.Empty)
                    {
                        _NTAccount = strData;
                    }
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.UserName, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    strData = Marshal.PtrToStringAnsi(buffer);
                    data.UserName = strData;
                    if (strData != String.Empty)
                    {
                        data.NTAccount = _NTAccount + "\\" + strData;
                        string _Sid = (new NTAccount(_NTAccount + "\\" + strData)).Translate(typeof(SecurityIdentifier)).Value;
                        data.SID = _Sid;
                        if (_IsLocalAdminCheckSuccess == true)
                        {
                            foreach (string localAdminGroupSid in localAdminGroupSidsList)
                            {
                                if (localAdminGroupSid == _Sid)
                                {
                                    data.IsLocalAdmin = true;
                                    break;
                                }
                                else
                                {
                                    data.IsLocalAdmin = false;
                                }
                            }
                        }
                    }
    
                    if (WTSQuerySessionInformation(server, SessionId, WTS_INFO_CLASS.SessionName, out buffer, out bytesReturned) == false)
                    {
                        return data;
                    }
                    strData = Marshal.PtrToStringAnsi(buffer);
                    data.SessionName = strData;
                    if (strData != "Services" && strData != "RDP-Tcp" && data.UserName != String.Empty)
                    {
                        _IsUserSession = true;
                    }
                    data.IsUserSession = _IsUserSession;
                    if (strData == "Console")
                    {
                        _IsConsoleSession = true;
                    }
                    data.IsConsoleSession = _IsConsoleSession;
    
                    WINSTATIONINFORMATIONW wsInfo = GetWinStationInformation(server, SessionId);
                    DateTime? _loginTime = FileTimeToDateTime(wsInfo.LoginTime);
                    DateTime? _lastInputTime = FileTimeToDateTime(wsInfo.LastInputTime);
                    DateTime? _disconnectTime = FileTimeToDateTime(wsInfo.DisconnectTime);
                    DateTime? _currentTime = FileTimeToDateTime(wsInfo.CurrentTime);
                    TimeSpan? _idleTime = (_currentTime != null && _lastInputTime != null) ? _currentTime.Value - _lastInputTime.Value : TimeSpan.Zero;
                    data.LogonTime = _loginTime;
                    data.IdleTime = _idleTime;
                    data.DisconnectTime = _disconnectTime;
    
                    if (currentSessionID == SessionId)
                    {
                        _IsCurrentSessionId = true;
                    }
                    data.IsCurrentSession = _IsCurrentSessionId;
                }
                finally
                {
                    WTSFreeMemory(buffer);
                    buffer = IntPtr.Zero;
                    CloseServer(server);
                }
                return data;
            }
    
            public static TerminalSessionInfo[] GetUserSessionInfo(string ServerName)
            {
                if (ServerName == "localhost" || ServerName == String.Empty)
                {
                    ServerName = Environment.MachineName;
                }
    
                // Find and get detailed information for all user sessions
                // Also determine the active user session. If a console user exists, then that will be the active user session.
                // If no console user exists but users are logged in, such as on terminal servers, then select the first logged-in non-console user that is either 'Active' or 'Connected' as the active user.
                TerminalSessionData[] sessions = ListSessions(ServerName);
                TerminalSessionInfo sessionInfo = new TerminalSessionInfo();
                List<TerminalSessionInfo> userSessionsInfo = new List<TerminalSessionInfo>();
                string firstActiveUserNTAccount = String.Empty;
                bool IsActiveUserSessionSet = false;
                foreach (TerminalSessionData session in sessions)
                {
                    if (session.IsUserSession == true)
                    {
                        sessionInfo = GetSessionInfo(ServerName, session.SessionId);
                        if (sessionInfo.IsUserSession == true)
                        {
                            if ((firstActiveUserNTAccount == String.Empty) && (sessionInfo.ConnectState == "Active" || sessionInfo.ConnectState == "Connected"))
                            {
                                firstActiveUserNTAccount = sessionInfo.NTAccount;
                            }
    
                            if (sessionInfo.IsConsoleSession == true)
                            {
                                sessionInfo.IsActiveUserSession = true;
                                IsActiveUserSessionSet = true;
                            }
                            else
                            {
                                sessionInfo.IsActiveUserSession = false;
                            }
    
                            userSessionsInfo.Add(sessionInfo);
                        }
                    }
                }
    
                TerminalSessionInfo[] userSessions = userSessionsInfo.ToArray();
                if (IsActiveUserSessionSet == false)
                {
                    foreach (TerminalSessionInfo userSession in userSessions)
                    {
                        if (userSession.NTAccount == firstActiveUserNTAccount)
                        {
                            userSession.IsActiveUserSession = true;
                            break;
                        }
                    }
                }
    
                return userSessions;
            }
        }
    }
"@
    [string[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
    Add-Type -TypeDefinition $signature -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'        
}

#Region ITAlertScript
# This variable contains the contents of the script that will be written to the script that will generate the toast.
$InvokeITAlertToastContents = @'
$AlertConfig = Get-Content -Path "$PSScriptRoot\alertconfig.json" -ErrorAction Ignore | Out-String
If ([string]::IsNullOrEmpty($AlertConfig)){
    exit 3
}
$Config = ConvertFrom-Json -InputObject $AlertConfig
$Scenario = $Config.Scenario # 'Reminder' #Possible values are: reminder | short | long --- How long displayed::: Reminder: Until Dismissed, Short: 5 seconds, Long: 25 seconds 
$HeaderText = $Config.HeaderText #'Important message from IT...'
$AttributionText = $Config.AttributionText #'Notice Time: ' + (Get-Date -Format 'MM/dd/yyyy @ hh:mm tt')
$TitleText = $Config.TitleText #'IT Mail System Offline'
$BodyText1 = $Config.BodyText1 #"There currently is an outage with Microsoft's cloud services.  This is effecting access to email, MyApps, Sharepoint and various other online services."
$BodyText2 = $Config.BodyText2 #"Currently there is no estimated time to repair.  We will send an update via toast notice in 2 hours or email when repaired."
$DismissButtonContent = $Config.DismissButtonContent #'Dismiss' #'Acknowledged'

$HeroImage = "${Env:Temp}\ToastHeroImage.jpg"
$B64HeroImage = @"
/9j/4QAYRXhpZgAASUkqAAgAAAAAAAAAAAAAAP/sABFEdWNreQABAAQAAABQAAD/4QMXaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLwA8P3hwYWNrZXQgYmVnaW49
Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/PiA8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJBZG9iZSBYTVAgQ29y
ZSA1LjYtYzE0OCA3OS4xNjM4NTgsIDIwMTkvMDMvMDYtMDM6MTg6MzYgICAgICAgICI+IDxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8w
Mi8yMi1yZGYtc3ludGF4LW5zIyI+IDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0v
IiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hh
cC8xLjAvIiB4bXBNTTpEb2N1bWVudElEPSJ4bXAuZGlkOjYzN0Y0MTE4Mzc3RDExRUJBOEU1OEEzMEFGMjI1NEM3IiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOjYz
N0Y0MTE3Mzc3RDExRUJBOEU1OEEzMEFGMjI1NEM3IiB4bXA6Q3JlYXRvclRvb2w9InBhaW50Lm5ldCA0LjIuMTAiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5z
dGFuY2VJRD0idXVpZDpmYWY1YmRkNS1iYTNkLTExZGEtYWQzMS1kMzNkNzUxODJmMWIiIHN0UmVmOmRvY3VtZW50SUQ9IjQxMTM3QUQxQzM2QzJGQzIxRjQzOTk3OUZG
QjY2QkI3Ii8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+/+4ADkFkb2JlAGTAAAAAAf/bAIQAAgIC
AgICAgICAgMCAgIDBAMCAgMEBQQEBAQEBQYFBQUFBQUGBgcHCAcHBgkJCgoJCQwMDAwMDAwMDAwMDAwMDAEDAwMFBAUJBgYJDQsJCw0PDg4ODg8PDAwMDAwPDwwMDAwM
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
"@
[byte[]]$Bytes = [convert]::FromBase64String($B64HeroImage)
[System.IO.File]::WriteAllBytes($HeroImage,$Bytes)

$LogoImage = "${Env:Temp}\ToastLogoImage.jpg"
$B64LogoImage = @"
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
"@
[byte[]]$Bytes = [convert]::FromBase64String($B64LogoImage)
[System.IO.File]::WriteAllBytes($LogoImage,$Bytes)

[xml]$Toast = @"
<toast scenario="$Scenario">
    <visual>
    <binding template="ToastGeneric">
        <image placement="hero" src="$HeroImage"/>
        <image id="1" placement="appLogoOverride" hint-crop="circle" src="$LogoImage"/>
        <text>$HeaderText</text>
        <text placement="attribution">$AttributionText</text>
        <group>
            <subgroup>
                <text hint-style="title" hint-wrap="true" >$TitleText</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style="body" hint-wrap="true" >$BodyText1</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style="body" hint-wrap="true" >$BodyText2</text>
            </subgroup>
        </group>
    </binding>
    </visual>
    <actions>
        <action activationType="system" arguments="dismiss" content="$DismissButtonContent"/>
    </actions>
</toast>
"@

#$App = "Microsoft.SoftwareCenter.DesktopToasts"
$App = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $nul
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $nul

# Load the notification into the required format
$ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
$ToastXml.LoadXml($Toast.OuterXml)

[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($App).Show($ToastXml)
'@
#EndRegion ITAlertScript


Add-PSADTCustom
[Security.Principal.WindowsIdentity]$CurrentProcessToken = [Security.Principal.WindowsIdentity]::GetCurrent()
[boolean]$IsAdmin = [boolean]($CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-32-544')
[psobject]$RunAsActiveUser = Get-LoggedOnUser | Where-Object { $_.IsActiveUserSession }
$dirAppDeployTemp = 'C:\Temp'
$Configs = [PSCustomObject]@{
    Scenario = "$Scenario";
    HeaderText = "$HeaderText";
    AttributionText = "Notice Time: $AlertTime"
    TitleText = "$TitleText";
    BodyText1 = "$BodyText1";
    BodyText2 = "$BodyText2";
    DismissButtonContent = "$DismissButtonText";
    Expiration = $Expiration
}
ConvertTo-Json $Configs > "$dirAppDeployTemp\alertconfig.json"
$InvokeITAlertToastContents > $dirAppDeployTemp\Invoke-ITAlertToast.ps1

Invoke-ProcessAsUser -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Parameters "-ExecutionPolicy Bypass -NoProfile -File $dirAppDeployTemp\Invoke-ITAlertToast.ps1"


Start-Sleep -Seconds 10
Remove-Item -Path "$dirAppDeployTemp\Invoke-ITAlertToast.ps1"
Remove-Item -Path "$dirAppDeployTemp\alertconfig.json"