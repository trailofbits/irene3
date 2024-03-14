# Slicing

Slicing allows the user to generate patches that edit a sub-basicblock region or even insert code without modifying the existing code. The slice manager shows currently active slice addresses and can be opened by `Window -> Anvill Slices` or by selecting the slices button in the Ghidra toolbar. The red `X` in the slice manager allows removing addresses from the slice set.



## Slicing an Existing Block

A subregion can be added by highlighting an address range in the Ghidra listing window, right clicking, and selecting `Add selection to slice`. 

## Inserting new Code

To insert new code before or after an instruction, right click the instruction and select `Add patch block before/after instruction(s)`. This command will add a slice at that instruction and create a zero byte block to insert new code into.