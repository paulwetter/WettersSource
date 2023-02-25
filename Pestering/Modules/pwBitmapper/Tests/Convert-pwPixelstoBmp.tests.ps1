BeforeAll -Scriptblock {
    Import-Module "$PSScriptRoot..\..\pwBitmapper" -Force

    $pixels = @{
        '0,0' = '255,255,255'
        '0,1' = '255,255,255'
        '1,0' = '255,255,255'
        '1,1' = '255,255,254'
    }
}
Describe -Name 'Convert-pwPixelstoBmp' -Fixture {
    BeforeAll -Scriptblock {
        InModuleScope -ModuleName 'pwBitmapper' -ScriptBlock {
            Mock -CommandName 'Get-pwPixelMax' -MockWith {@{xMax = 2; yMax = 2}} -Verifiable
            Mock -CommandName 'New-pwEmptyBitmap' -MockWith {
                [System.Drawing.Bitmap]::new(2, 2)
            } -Verifiable
            Mock -CommandName 'Set-pwBmpPixels' -MockWith { 
                $bmp = [System.Drawing.Bitmap]::new(2, 2)
                $bmp.SetPixel(0,0,[System.Drawing.Color]::FromArgb(255, 255, 255))
                $bmp.SetPixel(1,1,[System.Drawing.Color]::FromArgb(255, 255, 254))
                return $bmp
            } -Verifiable
        }
    }
    Context -Name 'When converting a bmp file to pixel hashtable' -Fixture {
        It -Name 'Should not Throw' -Test {
            {Convert-pwPixelstoBmp -Pixels $pixels}| Should -Not -Throw
        }
        It -Name 'Should return a Bitmap Object with correct pixels' -Test {
            $Return = Convert-pwPixelstoBmp -Pixels $pixels
            $Return | Should -BeOfType 'System.Drawing.Bitmap'
            $Return.GetPixel(0,0).b | Should -Be '255'
            $Return.GetPixel(1,1).b | Should -Be '254'
        }
    }
}