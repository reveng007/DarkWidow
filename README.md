# DarkWidow

### Capabilities:
1. Indirect Dynamic Syscall
2. SSN + Syscall address sorting via Modified TartarusGate approach
3. Remote Process Injection via APC Early Bird
4. Spawns a sacrificial Process as target process
5. ACG(Arbitary Code Guard)/BlockDll mitigation policy on spawned process
6. PPID spoofing (Emotet method)
7. Api resolving from TIB (Directly via offset (from TIB) -> TEB -> PEB -> resolve Api)
8. API hashing

### = EDR/UserLand hook Bypass Probably! -> Don't have EDR to check it though ;(


### Links that helped me:
1. TIB:
   - https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
   - https://www.wikiwand.com/en/Win32_Thread_Information_Block
2. GS and FS register:
   - https://stackoverflow.com/questions/39137043/what-is-the-gs-register-used-for-on-windows
   - https://stackoverflow.com/questions/10810203/what-is-the-fs-gs-register-intended-for#:~:text=The%20registers%20FS%20and%20GS,to%20access%20thread%2Dspecific%20memory.
3. 
