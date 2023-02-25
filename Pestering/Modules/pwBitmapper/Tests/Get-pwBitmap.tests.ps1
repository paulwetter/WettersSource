BeforeAll -Scriptblock {
    Import-Module "$PSScriptRoot..\..\pwBitmapper" -Force
}
Describe -Name "Get-pwBitmap" -Fixture {
    Context -Name "When getting file" -Fixture {
        BeforeAll -Scriptblock {
            $RandomName = '{0}\{1}.bmp' -f $env:Temp, (New-Guid).Guid
            $bmp = [System.Drawing.Bitmap]::new(2, 2)
            $bmp.SetPixel(0,0,[System.Drawing.Color]::FromArgb(255, 255, 255))
            $bmp.SetPixel(1,1,[System.Drawing.Color]::FromArgb(255, 255, 254))
            $bmp.Save("$RandomName")        
        }
        It -Name "Should not throw" -Test {
            {Get-pwBitmap -File $RandomName} | Should -Not -Throw
        }
        It -Name "Should return a bitmap object" -Test {
            $Return = Get-pwBitmap -File $RandomName
            $Return | Should -BeOfType 'System.Drawing.Bitmap'
        }
        AfterAll -Scriptblock {
            Remove-Item -Path $RandomName -Force -ErrorAction SilentlyContinue
        }
    }
}
