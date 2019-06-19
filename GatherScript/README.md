Gather.vbs
=========

This VBScript attempts to gather all the same variables that the MDT gather step would collect.  VBScript has the advantage over PowerShell because you don't have to add PowerShell to the boot image.

See Blog Post here: https://wetterssource.com/gather-script-replace-mdt

Execute
=========
Must execute from elevated command prompt.  Should be run with cscript to output to command line.

```cscript.exe //nologo gather.vbs```

Output Variables
=========
Sample of the variables and values that it would output.

```Architecture = X64
IsOnBattery = True
Model = Surface Book 2
UUID = 0FFFFFFF-DFFF-7777-0999-5E4FACEB00C5
Vendor = Microsoft Corporation
Make = Microsoft Corporation
IsVM = False
VMPlatform = 
Memory = 16308
Product = Surface Book 2
SerialNumber = 002123456789
BIOSVersion = 389.2370.769
BIOSReleaseDate = 20181002000000.000000+000
OSCurrentVersion = 10.0.17134
OSCurrentBuild = 17134
AssetTag = 
IsDesktop = False
IsLaptop = True
IsServer = False
IPAddress = 192.168.99.122
DefaultGateway = 192.168.99.1
MacAddress = 62:45:BB:22:AD:33
ProcessorSpeed = 2112
IsBDE = True
BitlockerEncryptionMethod = XTS_AES_128
IsUEFI = True
SecureBootEnabled = True
IsAHCI = False```
