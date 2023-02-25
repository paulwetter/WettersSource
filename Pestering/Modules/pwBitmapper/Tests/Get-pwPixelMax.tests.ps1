BeforeAll -Scriptblock {
    Import-Module "$PSScriptRoot..\..\pwBitmapper" -Force
}
Describe -Name "Get-pwPixelMax" -Fixture {
    Context -Name "When looking at a 2 by 2 pixel set" -Fixture {
        BeforeAll -Scriptblock {
            $Pixels = @{
                '0,0' = '255,255,255'
                '0,1' = '255,255,255'
                '1,0' = '255,255,255'
                '1,1' = '255,255,254'
            }
        }
        It -Name 'Should not throw' -Test {
            {Get-pwPixelMax -Pixels $Pixels} | Should -Not -Throw
        }
        It -Name 'Should have a Max X of 2' -Test {
            (Get-pwPixelMax -Pixels $Pixels).xMax |Should -Be 2
        }
        It -Name 'Should have a Max Y of 2' -Test {
            (Get-pwPixelMax -Pixels $Pixels).yMax |Should -Be 2
        }
    }
}
