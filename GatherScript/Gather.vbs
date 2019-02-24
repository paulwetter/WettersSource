
'These are the arrays of all of the know chassis types:
arrDesktopChassisTypes = array("3","4","5","6","7","15","16","35","36")
arrLatopChassisTypes = array("8","9","10","11","12","14","18","21","30","31","32")
arrServerChassisTypes = array("23","28")

'This way if it hangs up on one query, you don't lose them all.  More like what a powershell script would do.
On Error Resume Next


'This function will create and write a variable to the task sequence environment.
Function WriteTSVar(VarName,VarValue)
	On Error Resume Next
	Set env = CreateObject("Microsoft.SMS.TSEnvironment")
	error_returned = Err.Number
	error_description = Err.Description
	'on error goto 0
	if (error_returned <> 0) then 
		wscript.echo "TS not running, would have set [" & VarName & "] to value [" & VarValue & "] (Error: " & error_returned & ")."
	else
		Err.Clear
		If VarValue = "" Then
			env(VarName) = ""
		Else
			env(VarName) = VarValue
		End If
	End If
End Function

'This function will attempt to get the value of a variable in the TS environment.
Function GetTSVar(VarName)
	On Error Resume Next
	Set env = CreateObject("Microsoft.SMS.TSEnvironment")
	error_returned = Err.Number
	error_description = Err.Description
	'on error goto 0
	if (error_returned <> 0) then 
		wscript.echo "TS not running, GetTSVar could not find value for [" & VarName & "]."
	else
		Err.Clear
		GetTSVar = env(varName)
	End If
End Function

'This function will checked if a value (needle) is in an array (haystack).  It will return a boolean True or False
Function In_Array(needle, haystack)
	findings = False
	needle = trim(needle)
	For Each hay in haystack
		If trim(hay) = needle Then
			findings = True
			Exit For
		End If
	Next
	In_Array = findings
End Function

'Get the CPU architecture: X86, X64
strArch = "X86"
Set wshShell = CreateObject( "WScript.Shell" )
IF wshShell.ExpandEnvironmentStrings( "%PROCESSOR_ARCHITECTURE%" ) = "AMD64" then
	strArch = "X64"
End If
'wshShell = Nothing
WriteTSVar "Architecture", strArch

'Detects if the system is on a battery: True or False
strIsOnBattery = "False"
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM win32_Battery where BatteryStatus != 2",,32)
for each objItem in colItems
	strIsOnBattery = "True"
next
WriteTSVar "IsOnBattery", strIsOnBattery

'Gets information on the make and model of the computer
IsVM = "False"
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_ComputerSystemProduct",,32)
for each objItem in colItems
    If (objItem.Vendor = "LENOVO") And (UseOldLenovoName <> "true") Then
        tempModel = objItem.Version
    Else
        tempModel = objItem.Name
    End If
	WriteTSVar "Model", tempModel
	WriteTSVar "UUID", ObjItem.UUID
	WriteTSVar "Vendor", ObjItem.Vendor
	WriteTSVar "Make", ObjItem.Vendor
	
'Checks if this computer is a Virtual Machine: True or False
'Then also detects the virtual platform: Hyper-V, VMware, VirtualBox, or Xen
	Select Case tempModel
		Case "Virtual Machine"
			IsVM = "True"
			VMPlatform = "Hyper-V"
		Case "VMware Virtual Platform"
			IsVM = "True"
			VMPlatform = "VMware"
		Case "VMware7,1"
			IsVM = "True"
			VMPlatform = "VMware"
		Case "VirtualBox"
			IsVM = "True"
			VMPlatform = "VirtualBox"
		Case "Xen"
			IsVM = "True"
			VMPlatform = "Xen"
	End Select
	
	WriteTSVar "IsVM", IsVM
	WriteTSVar "VMPlatform", VMPlatform
	
Next

'Get the total memory installed
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_ComputerSystem",,32)
for each objItem in colItems
	strMemory = objItem.TotalPhysicalMemory/1024/1024
	arrMemory = Split(strMemory,".")
	strMemory = arrMemory(0)
	WriteTSVar "Memory", strMemory
Next

'Gets the product for the machine.  Most useful with Lenovo and HP
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_BaseBoard",,32)
for each objItem in colItems
	WriteTSVar "Product", objItem.Product
Next

'Gets the serial number and other bios info
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_BIOS",,32)
for each objItem in colItems
	WriteTSVar "SerialNumber", Trim(objItem.SerialNumber)
	WriteTSVar "BIOSVersion", objItem.SMBIOSBIOSVersion
	WriteTSVar "BIOSReleaseDate", objItem.ReleaseDate
Next

'Gets the OS version and build of the system.  If in PE, this will be the PE version info
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_OperatingSystem",,32)
for each objItem in colItems
	WriteTSVar "OSCurrentVersion", objItem.Version
	WriteTSVar "OSCurrentBuild", objItem.BuildNumber
Next

'Will detect if it is a Desktop, Laptop, or Server, based on the ChassisTypes
IsDesktop = "False"
IsLaptop = "False"
IsServer = "False"
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_SystemEnclosure",,32)
for each objItem in colItems
	WriteTSVar "AssetTag", objItem.SMBIOSAssetTag
	For each CT in objItem.ChassisTypes
		If In_Array(CT,arrDesktopChassisTypes) Then
			IsDesktop = "True"
		End If
		If In_Array(CT,arrLatopChassisTypes) Then
			IsLaptop = "True"
		End If
		If In_Array(CT,arrServerChassisTypes) Then
			IsServer = "True"
		End If
	Next
	WriteTSVar "IsDesktop", IsDesktop
	WriteTSVar "IsLaptop", IsLaptop
	WriteTSVar "IsServer", IsServer
Next

'Returns a boolean true if the gateway value exists
Function GatewayDefined(obj)
    Success = false
    On Error Resume Next
        intType = vartype(obj)
        if Err.Number = 0 Then
			If intType > 1 Then
				Success = true
			End If
		End if
		'On Error Goto 0
    GatewayDefined = Success
End Function  

'This gets network information like IP Address and Gateway
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration where IPEnabled = 1",,32)
for each objItem in colItems
	for each IpAddr in objItem.IPAddress
		strCurrentIPs = GetTSVar("IPAddress")
		if IpAddr <> "" Then
			SplitIP = Split (IpAddr, ".")
			If (InStr(IpAddr,".") > 0) Then
				If (((SplitIP(0) = "169") And (SplitIP(1) = "254")) Or (IpAddr = "0.0.0.0")) Then
					'Not a good IP
				else
					If strCurrentIPs <> "" Then
						WriteTSVar "IPAddress", strCurrentIPs & "," & IpAddr
					Else
						WriteTSVar "IPAddress", IpAddr
					End If
				End If
			End If
		End If
	Next
	If (GatewayDefined(ObjItem.DefaultIPGateway) = true) Then
		for each DefaultGW in objItem.DefaultIPGateway
			strCurrentGW = GetTSVar("DefaultGateway")
			if DefaultGW <> "" Then
				SplitGW = Split (DefaultGW, ".")
				If (InStr(DefaultGW,".") > 0) Then
					If (DefaultGW = "0.0.0.0") Then
						'Not a good IP
					else
						If strCurrentGW <> "" Then
							WriteTSVar "DefaultGateway", strCurrentGW & "," & DefaultGW
						Else
							WriteTSVar "DefaultGateway", DefaultGW
						End If
					End If
				End If
			End If
		Next
	End If
Next

'Gets the Mac Address off of the network adapter
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_NetworkAdapter where NetConnectionStatus = 2",,32)
for each objItem in colItems
	MacAddress = objItem.MACAddress
Next
WriteTSVar "MacAddress", MacAddress

'Gets the max clock speed off of the CPU
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_Processor",,32)
for each objItem in colItems
	WriteTSVar "ProcessorSpeed", objItem.MaxClockSpeed
Next

'Gets Bitlocker information.
IsBDE = "False"
BitlockerEncryptionType = "N/A"
BitlockerEncryptionMethod = "N/A"
set objWMIService = GetObject("winmgmts:\\.\root\cimv2\Security\MicrosoftVolumeEncryption") 
set colItems = objWMIService.ExecQuery("Select * from Win32_EncryptableVolume where ProtectionStatus != 0",,32)
for each objItem in colItems
	IsBDE = "True"
	Select Case objItem.EncryptionMethod
		Case 0
			strEncMethod = "None"
		Case 1
			strEncMethod = "AES_128_WITH_DIFFUSER"
		Case 2
			strEncMethod = "AES_256_WITH_DIFFUSER"
		Case 3
			strEncMethod = "AES_128"
		Case 4
			strEncMethod = "AES_256"
		Case 5
			strEncMethod = "HARDWARE_ENCRYPTION"
		Case 6
			strEncMethod = "XTS_AES_128"
		Case 7
			strEncMethod = "XTS_AES_256"
	End Select
Next
WriteTSVar "IsBDE", IsBDE
WriteTSVar "BitlockerEncryptionMethod", strEncMethod
'Set objBde = objWMIService.Get("Win32_EncryptableVolume")

'UEFI And Secureboot: True or False
strSecureBoot = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled"
strUEFI = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State\"
Set objShell = WScript.CreateObject("WScript.Shell")
'On Error Resume Next
boolUEFI = objShell.RegRead(strUEFI)
error_returned = Err.Number
error_description = Err.Description
'on error goto 0
If (error_returned <> 0) then 
	IsUEFI = "False"
Else
	Err.Clear
	IsUEFI = "True"
End If
WriteTSVar "IsUEFI", IsUEFI
'On Error Resume Next
intSecureBoot = objShell.RegRead(strSecureBoot)
error_returned = Err.Number
error_description = Err.Description
'on error goto 0
If (error_returned <> 0) then 
	SecureBootEnabled = "False"
Else
	Err.Clear
	If (intSecureBoot = 1) Then
		SecureBootEnabled = "True"
	End If
End If
WriteTSVar "SecureBootEnabled", SecureBootEnabled

'Checks if the boot disk is AHCI: True or False
'Optionally, we can be more specific and have a third option of "Probably" or "Likely"
IsAHCI = "False"
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_IDEController where Name LIKE ""%AHCI%""",,32)
for each objItem in colItems
	IsAHCI = "True"
Next
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_DiskDrive WHERE InterfaceType LIKE ""IDE"" AND MediaType Like ""Fixed hard disk media""",,32)
for each objItem in colItems
	HasIDEDrives = "True"
Next
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_IDEController where Name LIKE ""%AHCI%""",,32)
for each objItem in colItems
	IsAHCI = "True"
Next

'Find any SCSI controller, excluding the Microsoft storage spaces controller
HasSCSI = "False"
set objWMIService = GetObject("winmgmts:\\.\root\cimv2") 
set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_SCSIController WHERE DriverName != ""spaceport""",,32)
for each objItem in colItems
	HasSCSI = "True"
Next

If ((isAHCI = "True") And (HasIDEDrives = "True") And (HasSCSI = "False")) Then
	IsAHCI = "True"
ElseIf ((isAHCI = "True") And (HasIDEDrives = "True")) Then
	'This section is most likely that it is using AHCI.  Because, if it has scsi, it may be using a scsi boot instead of AHCI.
	IsAHCI = "True"
Else
	IsAHCI = "False"
End If
WriteTSVar "IsAHCI", IsAHCI
