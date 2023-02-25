BeforeAll -Scriptblock {
    Import-Module ..\..\pwBitmapper -Force
}
Describe -Name 'Set-pwBmpRotate' -Fixture {
    BeforeAll -Scriptblock {
        #$obj = New-MockObject -Type 'System.Drawing.Image'
        $bmp = New-MockObject -InputObject $([System.Drawing.Bitmap]::new(10, 10))
    }
    $Tests = @(
        @{Rotate = 90}
        @{Rotate = 180}
        @{Rotate = 270}
    )
    Context -Name 'Rotate Image <Rotate> degrees' -ForEach $Tests -Fixture {
        It -Name 'Should not throw' -Test {
            {Set-pwBmpRotate -Bitmap $bmp -Rotate $Rotate} | Should -Not -Throw
        }
        It -Name 'Should return a Bitmap' -Test {
            $Return = Set-pwBmpRotate -Bitmap $bmp -Rotate $Rotate
            $Return | Should -BeOfType 'System.Drawing.Bitmap'
        }
    }
}
