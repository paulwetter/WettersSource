BeforeAll -Scriptblock {
    Import-Module "$PSScriptRoot..\..\pwBitmapper" -Force
}
Describe -Name 'New-pwBmpFileFromPixels' -Fixture {
    BeforeAll -Scriptblock {
        $pixels = @{
            '0,0' = '255,255,255'
            '0,1' = '255,255,255'
            '1,0' = '255,255,255'
            '1,1' = '255,255,255'
        }
        InModuleScope -ModuleName 'pwBitmapper' -ScriptBlock {
            Mock -CommandName 'Convert-pwPixelstoBmp' -MockWith {
                return [System.Drawing.Bitmap]::new(2, 2)
            } -Verifiable
        }
    }
    Context -Name 'When given an array of pixels and path' -Fixture {
        BeforeEach -Scriptblock {
            New-pwBmpFileFromPixels -Pixels $Pixels -File "${ENV:TEMP}\test.bmp"
        }
        It -Name 'Should not throw' -Test {
            {New-pwBmpFileFromPixels -Pixels $Pixels -File "${ENV:TEMP}\test.bmp"} | Should -Not -Throw
        }
        It -Name 'Should create the bitmap file' -Test {
            Should -InvokeVerifiable
        }
    }    
}