Script that compares computers in active directory to computers in SCCM.  Useful in seeind what in ad and CM are stale records.

Load the fuctions into memory:
`. Get-ADCMComparison.ps1`

Then execute with something similar to this:
`Export-ADCMComparison -SiteServer CM01.domain.com -CMSite SS1 -CSVPath C:\Shared\Computers.csv`
