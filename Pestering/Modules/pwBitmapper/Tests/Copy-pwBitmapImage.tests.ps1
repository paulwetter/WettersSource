BeforeAll -Scriptblock {
    Import-Module "$PSScriptRoot..\..\pwBitmapper" -Force
}
Describe -Name 'Copy-pwBitmapImage' -Fixture {
    BeforeAll -Scriptblock {
        InModuleScope -ModuleName 'pwBitmapper' -ScriptBlock {
            Mock -CommandName 'Get-pwBitmap' -MockWith {
                [System.Drawing.Bitmap]::new(2, 2)
            } -Verifiable
        }
    }
    Context -Name 'When copying a bitmap object' -Fixture {
        It -Name 'Should not Throw' -Test {
            {Copy-pwBitmapImage -File "${ENV:TEMP}\test.bmp"}| Should -Not -Throw
        }
        It -Name 'Should return a Bitmap Object of same size' -Test {
            $Return = Copy-pwBitmapImage -File "${ENV:TEMP}\test.bmp"
            $Return | Should -BeOfType 'System.Drawing.Bitmap'
            $Return.Height | Should -Be 2
            $Return.Width | Should -Be 2
        }
    }
}