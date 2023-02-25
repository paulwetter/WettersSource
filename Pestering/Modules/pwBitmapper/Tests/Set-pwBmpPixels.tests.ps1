

BeforeAll -Scriptblock {
    Import-Module "$PSScriptRoot..\..\pwBitmapper" -Force
}

Describe -Name 'Set-pwBmpPixels' -Fixture {
    BeforeAll -Scriptblock {
        $pixels = @{
            '0,0' = '255,255,251'
            '0,1' = '255,255,252'
            '1,0' = '255,255,253'
            '1,1' = '255,255,254'
        }
        $bmp = [System.Drawing.Bitmap]::new(2, 2)

    }
    Context -Name 'When given a 2x2 pixel array' -Fixture {
        It -Name 'Should not throw' -Test {
            {Set-pwBmpPixels -Pixels $pixels -Bitmap $bmp} | Should -Not -Throw
        }
        It -Name 'Should return a 2x2 bitmap' -Test {
            $result = Set-pwBmpPixels -Pixels $pixels -Bitmap $bmp
            $result | Should -BeOfType 'System.Drawing.Bitmap'
            $result.Height | Should -Be 2
            $result.Width | Should -Be 2
        }
        It -Name 'Should set colors that match the pixel input' -Test {
            $result = Set-pwBmpPixels -Pixels $pixels -Bitmap $bmp
            $result.GetPixel(0,0).B | Should -Be 251
            $result.GetPixel(0,1).B | Should -Be 252
            $result.GetPixel(1,0).B | Should -Be 253
            $result.GetPixel(1,1).B | Should -Be 254
        }
    }
}