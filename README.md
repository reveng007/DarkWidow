# DarkWidow

- Indirect Dynamic Syscall
- SSN + Syscall address sorting via Modified TartarusGate approach
- Remote Process Injection via APC Early Bird
- Spawns a sacrificial Process as target process
- ACG(Arbitary Code Guard)/BlockDll mitigation policy on spawned process
- PPID spoofing (Emotet method)
- Api resolving from TIB (TIB -> TEB -> PEB -> resolve Api)
- API hashing

### = EDR/UserLand hook Bypass Probably! -> Don't have EDR to check it though ;(
