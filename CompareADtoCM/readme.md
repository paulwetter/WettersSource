Set of functions that compares computers in Active Directory or Azure Active Directory to computers in SCCM.  Useful in seeing what in AD/AAD and CM are stale records.

Load the fuctions into memory:

`. Get-DirectoryCMComparison.ps1`

Then execute with something similar to this for an AD comparison to CM:

`Export-ADCMComparison -SiteServer CM01.domain.com -CMSite SS1 -CSVPath C:\Shared\Computers.csv`

Or, Add a Date to the file name you export:

`Export-ADCMComparison -SiteServer CM01.domain.com -CMSite SS1 -CSVPath C:\Shared\Computers_$(get-date -Format yyyyMMdd).csv`

Or, for AAD to CM comparison:
First, you may have to install the Microsoft Graph Intune module first to get access to the needed cmdlts.

`Install-Module -Name Microsoft.Graph.Intune`

If it is already installed, then connect to Graph and then run the export.
```
Connect-MSGraph
Export-AADCMComparison -SiteServer CM01.domain.com -CMSite SS1 -CSVPath C:\Shared\Computers.csv
```
