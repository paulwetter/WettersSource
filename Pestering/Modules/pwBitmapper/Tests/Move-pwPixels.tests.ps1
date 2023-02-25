BeforeAll -Scriptblock {
    Import-Module "$PSScriptRoot..\..\pwBitmapper" -Force
}
Describe -Name "Move-pwPixels" -Fixture {
    BeforeAll -Scriptblock {
        $Pixels = @{
            '0,0' = '255,255,255'
            '0,1' = '255,255,255'
            '1,0' = '255,255,255'
            '1,1' = '255,255,254'
        }
    }
    Context -Name "When looking at a 2 by 2 pixel set" -Fixture {
        It -Name 'Should not throw' -Test {
            { Move-pwPixels -Pixels $Pixels } | Should -Not -Throw
        }
    }
    Context -Name "When moving at a 2 by 2 pixel set 2 pixels in X and Y direction" -Fixture {
        It -Name 'Should shift the pixels in the hashset by 2 positions' -Test {
            $Result = Move-pwPixels -Pixels $Pixels -MoveX 2 -MoveY 2
            $Result.'2,2' | Should -Be '255,255,255'
            $Result.'3,3' | Should -Be '255,255,254'
        }
    }
}