BeforeAll -Scriptblock {
    Import-Module "$PSScriptRoot..\..\pwBitmapper" -Force
}
Describe -Name 'Save-pwBitmapFile' -Fixture {
    BeforeAll -Scriptblock {
        $RandomName = '{0}\{1}.bmp' -f $env:Temp, (New-Guid).Guid
        $bmp = [System.Drawing.Bitmap]::new(2, 2)
        $bmp.SetPixel(0,0,[System.Drawing.Color]::FromArgb(255, 255, 255))
        $bmp.SetPixel(1,1,[System.Drawing.Color]::FromArgb(255, 255, 254))
    }
    Context -Name 'When given a bitmap object to save to file' -Fixture {
        It -Name 'Should not throw' -Test {
            {Save-pwBitmapFile -Bitmap $bmp -File $RandomName} | Should -Not -Throw
        }
        It -Name 'Should have saved to a file' -Test {
            Test-Path -Path $RandomName | Should -BeTrue
        }
    }
    AfterAll -Scriptblock {
        Remove-Item -Path $RandomName -Force
    }
}
