BeforeAll -Scriptblock {
    Import-Module "$PSScriptRoot..\..\pwBitmapper" -Force
}
Describe -Name 'New-pwEmptyBitmap' -Fixture {
    Context -Name 'When given dimensions of 10 by 10' -Fixture {
        It -Name 'Should not throw' -Test {
            {New-pwEmptyBitmap -Width 10 -Height 10} | Should -Not -Throw
        }
        It -Name 'Should create a 10x10 bitmap object' -Test {
            $bitmap = New-pwEmptyBitmap -Width 10 -Height 10
            $bitmap | Should -BeOfType 'System.Drawing.Bitmap'
            $bitmap.Width | Should -Be 10
            $bitmap.Height | Should -Be 10
        }
    }    
}