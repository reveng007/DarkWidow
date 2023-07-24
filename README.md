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


### Links that Helped me:
1. TIB: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
