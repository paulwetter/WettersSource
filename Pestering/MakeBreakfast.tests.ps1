BeforeAll -Scriptblock {
    Mock -CommandName Add-pwBeverage -Verifiable
    Mock -CommandName Add-pwBreakfastMeat -Verifiable
    Mock -CommandName Add-pwEggs
    Mock -CommandName Add-pwPastry
    Mock -CommandName Add-pwToast
}
Describe -Name "Checking various breakfast orders with MakeBreakfast.ps1" -Fixture {
    Context -Name "When I order Coffee, Sausage and Toast" -Fixture {
        BeforeEach -Scriptblock {
            {C:\Users\pwett\Documents\GitHub\WettersSource\Pestering\MakeBreakfast.ps1 -Meat Sausage -Beverage Coffee -Toast Wheat} | Should -Not -Throw
        }
        It -Name "Should Get a beverage" -Test {
            Should -Invoke Add-pwBeverage -Times 1 -Exactly
        }
        It -Name "Should add sausages to the meal" -Test {
            Should -Invoke Add-pwBreakfastMeat -Times 1 -Exactly
        }
        It -Name "Should add toast to the meal" -Test {
            Should -Invoke Add-pwToast -Times 1 -Exactly
        }
    }
    Context -Name "When I order OJ and Sausage" -Fixture {
        BeforeEach -Scriptblock {
            {C:\Users\pwett\Documents\GitHub\WettersSource\Pestering\MakeBreakfast.ps1 -Meat Sausage,Bacon -Beverage Coffee -Toast Wheat} | Should -Not -Throw
        }
        It -Name "Should Get a beverage and meat" -Test {
            Should -InvokeVerifiable
        }
        It -Name "Should Add 2 meats" -Test {
            Should -Invoke -CommandName Add-pwBreakfastMeat -Times 2 -Exactly
        }
    }
}
