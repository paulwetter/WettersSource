This is an attempt to emulate the logic of a task sequence before running it on hardware.

This initial version will handle exit codes only and process them against the Continue on error true/false.

To install the extension, copy the files here and run the following command line:

```
.\Invoke-ToolInstallation.ps1 -SiteServer CM01.domain.com -Method Install -Path C:\Scripts -Verbose
```

(more detailed instructions to follow)
