BeforeAll -Scriptblock {
    Import-Module ..\..\pwBitmapper -Force
    
    $bmp = [System.Drawing.Bitmap]::new(10, 10)
    $pixels = @{
        '0,0' = '255,255,255'
        '0,1' = '255,255,255'
        '1,0' = '255,255,255'
        '1,1' = '255,255,255'
    }
}
Describe -Name 'Update-pwBmpFileFromPixels' -Fixture {
    BeforeAll -Scriptblock {
        InModuleScope -ModuleName 'pwBitmapper' -ScriptBlock {
            Mock -CommandName 'Copy-pwBitmapImage' -MockWith {
                [System.Drawing.Bitmap]::new(10, 10)
            } -Verifiable
            Mock -CommandName 'Get-pwPixelMax' -MockWith {@{xMax = 10; yMax = 10}} -Verifiable
            Mock -CommandName 'Move-pwPixels' -MockWith {
                @{
                    '0,0' = '255,255,255'
                    '0,1' = '255,255,255'
                    '1,0' = '255,255,255'
                    '1,1' = '255,255,255'
                }
            } -Verifiable
            Mock -CommandName 'Set-pwBmpPixels' -MockWith {
                [System.Drawing.Bitmap]::new(10, 10)
            } -Verifiable
            Mock -CommandName 'Save-pwBitmapFile' -MockWith { } -Verifiable
        }
    }
    Context -Name 'When a set of pixels are passed to update the bitmap' -Fixture {
        It 'Should not throw' -Test {
            {Update-pwBmpFileFromPixels -NewPixels $pixels -File "${ENV:TEMP}\test.bmp"} | Should -Not -Throw
        }
        It 'Should update and save the bmp' -Test {
            Should -InvokeVerifiable
        }
    }
}