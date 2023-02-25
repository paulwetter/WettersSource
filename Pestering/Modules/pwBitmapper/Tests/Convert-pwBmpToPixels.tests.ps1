BeforeAll -Scriptblock {
    Import-Module "$PSScriptRoot..\..\pwBitmapper" -Force

    $bmp = [System.Drawing.Bitmap]::new(2, 2)
    $bmp.SetPixel(0,0,[System.Drawing.Color]::FromArgb(255, 255, 255))
    $bmp.SetPixel(1,1,[System.Drawing.Color]::FromArgb(255, 255, 254))

}
Describe -Name 'Convert-pwBmpToPixels' -Fixture {

    BeforeAll -Scriptblock {
        InModuleScope -ModuleName 'pwBitmapper' -ScriptBlock {
            Mock -CommandName 'Get-pwBitmap' -MockWith {
                $bmp = [System.Drawing.Bitmap]::new(2, 2)
                $bmp.SetPixel(0,0,[System.Drawing.Color]::FromArgb(255, 255, 255))
                $bmp.SetPixel(1,1,[System.Drawing.Color]::FromArgb(255, 255, 254))
                return $bmp 
            } -Verifiable
        }
    }
    Context -Name 'When converting a bmp file to pixel hashtable' -Fixture {
        It -Name 'Should not Throw' -Test {
            {Convert-pwBmpToPixels -File "${ENV:TEMP}\test.bmp"}| Should -Not -Throw
        }
        It -Name 'Should open a file' -Test {
            Convert-pwBmpToPixels -File "${ENV:TEMP}\test.bmp"
            Should -Invoke -CommandName 'Get-pwBitmap' -Times 1 -Exactly -ModuleName 'pwBitmapper'
        }
        It -Name 'Should return a hashtable with correct values' -Test {
            $Return = Convert-pwBmpToPixels -File "${ENV:TEMP}\test.bmp"
            $Return."0,0" | Should -Be '255,255,255'
            $Return."1,1" | Should -Be '255,255,254'
        }
    }
    Context -Name 'When converting a bmp object to pixel hashtable' -Fixture {
        It -Name 'Should not Throw' -Test {
            {Convert-pwBmpToPixels -Bitmap $bmp} | Should -Not -Throw
        }
        It -Name 'Should not open a file' -Test {
            Convert-pwBmpToPixels -Bitmap $bmp
            Should -Invoke -CommandName 'Get-pwBitmap' -Times 0 -Exactly -ModuleName 'pwBitmapper'
        }
        It -Name 'Should return a hashtable with correct values' -Test {
            $Return = Convert-pwBmpToPixels -Bitmap $bmp
            $Return."0,0" | Should -Be '255,255,255'
            $Return."1,1" | Should -Be '255,255,254'
        }
    }
}