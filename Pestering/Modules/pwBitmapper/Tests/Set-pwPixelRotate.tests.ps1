BeforeAll -Scriptblock {
    Import-Module ..\..\pwBitmapper -Force
}
Describe -Name 'Set-pwPixelRotate' -Fixture {
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
            Mock -CommandName 'Set-pwBmpRotate' -MockWith {
                return [System.Drawing.Bitmap]::new(2, 2)
            } -Verifiable
            Mock -CommandName 'Convert-pwBmpToPixels' -MockWith { 
                return @{
                    '0,0' = '255,255,255'
                    '0,1' = '255,255,255'
                    '1,0' = '255,255,255'
                    '1,1' = '255,255,255'
                }
            } -Verifiable    
        }
    }
    Context -Name 'Rotate Image 90 degrees' -Fixture {
        BeforeEach -Scriptblock {
            $newPixels = Set-pwPixelRotate -Pixels $Pixels -Rotate 90
        }
        It -Name 'Should not throw' -Test {
            {Set-pwPixelRotate -Pixels $Pixels -Rotate 90} | Should -Not -Throw
        }
        It -Name 'Should rotate the image' -Test {
            Should -InvokeVerifiable
            $newPixels.'0,0' | Should -Be '255,255,255'
        }
    }    
}