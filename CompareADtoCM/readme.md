# Usage

Set of functions that compares computers in Active Directory or Azure Active Directory to computers in SCCM.  Useful in seeing what in AD/AAD and CM are stale records.

Load the fuctions into memory:

``` powershell
. Get-DirectoryCMComparison.ps1
```

## For AD

Then execute with something similar to this for an AD comparison to CM:

``` powershell
Export-ADCMComparison -SiteServer CM01.domain.com -CMSite SS1 -CSVPath C:\Shared\Computers.csv
```

Or, Add a Date to the file name you export:

``` powershell
Export-ADCMComparison -SiteServer CM01.domain.com -CMSite SS1 -CSVPath C:\Shared\Computers_$(get-date -Format yyyyMMdd).csv
```

## For Azure AD

For AAD to CM comparison:
First, you may have to install the Microsoft Graph Intune module first to get access to the needed cmdlts.

`Install-Module -Name Microsoft.Graph.Intune`

If it is already installed, then connect to Graph and then run the export.

``` powershell
Connect-MSGraph
Export-AADCMComparison -SiteServer CM01.domain.com -CMSite SS1 -CSVPath C:\Shared\Computers.csv
```

**NOTE:** By default the above will only export Azure natively joined computers.  Use the 'Type' swith to get native and hybrid joined computers, with something like this:

``` powershell
Export-AADCMComparison -SiteServer CM01.domain.com -CMSite SS1 -Type AzureNative,HybridJoined -CSVPath C:\Shared\Computers.csv
```

Or if you only want Hybrid joined, then this:

``` powershell
Export-AADCMComparison -SiteServer CM01.domain.com -CMSite SS1 -Type HybridJoined -CSVPath C:\Shared\Computers.csv
```
