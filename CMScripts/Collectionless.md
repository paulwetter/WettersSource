

<div class="mermaid">
            graph TD
            ExistingApp[Existing Application w/ \n proper deployment \n for Collectionless]
            Request[[Request for Application]] --> ACME[Engine Request]
            ACME --> ExAp{Existing Approval for \n app on Machine?}
            ExAp -->|No| NewApprove
            ExistingApp --> NewApprove[WMI Approval Created]
            ExAp -->|Yes| UpdateApprove[Update approval to Approved]
            NewApprove --> SM[Status Message ID 30804 created]
            UpdateApprove --> SM
            SM --> CP1[Sends client push machine policy] 
            CP1 --> Client[Machine Policy Refresh]
            Client --> NPI[New Policy installs Software]
            NPI --> STME[State Message sent back]
            STME --> MON[Monitor vAppDeploymentAssetDetails]
</div>


```powershell
$AppName = "Test App 1"

$Deployment = New-CMApplicationDeployment -CollectionName "Windows Workstation" -Name "$AppName" -DeployAction Install -DeployPurpose Available -ApprovalRequired $true

$application = Get-CMApplication -Name "$AppName"

$machine = Get-WmiObject -Namespace 'root\sms\site_XXL' -Query "SELECT * FROM SMS_R_SYSTEM WHERE Name = 'Win10-1'"

$machinename = $machine.Name

$clientGuid = $machine.SMSUniqueIdentifier
$appid = $Application.ModelName
$autoInstall = "true"
$comments = "Software Marketplace Approved"

Invoke-WmiMethod `
          -Path "SMS_ApplicationRequest" `
          -Namespace 'root\sms\site_XXL' `
          -Name CreateApprovedRequest `
          -ArgumentList @($appid, $autoInstall, $clientGuid, $comments)
		  
		  
$reqObj = Get-WmiObject -Namespace 'root\sms\site_XXL' -Class SMS_UserApplicationRequest | `
    Where {$_.ModelName -eq $appid -and $_.RequestedMachine -eq $machinename }
$reqObj.Approve('Approved', 6)


$reqObj = Get-WmiObject -Namespace 'root\sms\site_XXL' -Query "select * from SMS_UserApplicationRequest where ModelName='$appid' and RequestedMachine='$machinename'"
$reqObj.Deny('Not for you', 6)


$reqObj.RetryInstall("Again",20)

Denial does not Uninstall the app.


Not seeing any notification of success/failure.
All the approval sends throug the BGB channel is a machine policy refresh.




Approval of app install:
Starting to send push task (PushID: 1039 TaskID: 1024 TaskGUID: 5F5734C6-2B0A-4998-86B0-F0CF6D7B778E TaskType: 1 TaskParam: ) to 1 clients with throttling (strategy: 1 param: 42)
* Task Type 1 : Request Machine Policy

Status Message in CM for:
	System: Unknown Machine
	Component: Unkonwn Application
	Type: Audit
	Message ID: 30804
	Message:  Administrative user SOUP\cmboss approved request of application ScopeId_5D76BDE2-98FC-4855-B205-4DF992B18F54/Application_508a00b2-bc40-42c6-af5b-db400224ad2a for device WIN10-1.

Status Message in CM for:
	System: Unknown Machine
	Component: Unkonwn Application
	Type: Audit
	Message ID: 30803
	Message:  Administrative user SOUP\cmboss denied request of application Test App for user None for device WIN10-1.

Status Message in CM for:
	System: Unknown Machine
	Component: Unkonwn Application
	Type: Audit
	Message ID: 30809
	Message:  Administrative user SOUP\cmboss retried installation of application Test App 1 for device WIN10-1.


Sending a script:
Starting to send push task (PushID: 1040 TaskID: 1025 TaskGUID: C600F7C7-17A6-4F4F-A83D-52A89D34EF90 TaskType: 15 TaskParam: PFNjcmlwdENvbnRlbnQgU2NyaXB0R3VpZD0nOEVEQjQyN0MtQzA0OS00MzZDLUEyNEQtMjE2RjJDNzZEOTU1Jz48U2NyaXB0VmVyc2lvbj4xPC9TY3JpcHRWZXJzaW9uPjxTY3JpcHRUeXBlPjA8L1NjcmlwdFR5cGU+PFNjcmlwdEhhc2ggU2NyaXB0SGFzaEFsZz0nU0hBMjU2Jz4zMTFDMTJDOTU3MDcxNTUwMkQxMEYyNzlDQUQwQ0M5NTEyNUY5MDlBQzIwM0Q0MjgwNERCMERFMUY4RkQzRjc4PC9TY3JpcHRIYXNoPjxTY3JpcHRQYXJhbWV0ZXJzPjwvU2NyaXB0UGFyYW1ldGVycz48UGFyYW1ldGVyR3JvdXBIYXNoIFBhcmFtZXRlckhhc2hBbGc9J1NIQTI1Nic+PC9QYXJhbWV0ZXJHcm91cEhhc2g+PC9TY3JpcHRDb250ZW50Pg==) to 1 clients with throttling (strategy: 1 param: 42)

* Task Type 15: Request Script Execution




Status of App installs.  No immediate status found.  Best bet State Messaging.


[vAppDeploymentAssetDetails]



#BGB machine policy refresh
$ServerName = ""
$SiteCode = ""
$NameSpace = "root\SMS\Site_{0}" -f $SiteCode
$ClassName = "SMS_ClientOperation"
$MethodName = "InitiateClientOperation"
[string]$TargetCollectionID = "SMS00001"
[uint32]$Type = 1 #Machine Policy
[uint32]$RandomizationWindow = 1
[uint32[]]$TargetResourceIDs = 16777325

#Using CIM
$Args = @{
    TargetCollectionID = $TargetCollectionID
    Type = $Type
    RandomizationWindow = $RandomizationWindow
    TargetResourceIDs = $TargetResourceIDs
}
Invoke-CimMethod -Namespace $NameSpace -ClassName $ClassName -MethodName $MethodName -Arguments $Args

```

App Requests go away when app is deleted it seems.