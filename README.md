# DarkWidow

### Capabilities:
1. Indirect Dynamic Syscall
2. SSN + Syscall address sorting via Modified TartarusGate approach
3. Remote Process Injection via APC Early Bird
4. Spawns a sacrificial Process as the target process
5. ACG(Arbitrary Code Guard)/BlockDll mitigation policy on spawned process
6. PPID spoofing (**MITRE ATT&CK TTP: [T1134.004](https://attack.mitre.org/techniques/T1134/004/)**)
7. Api resolving from TIB (Directly via offset (from TIB) -> TEB -> PEB -> resolve Api)
8. API hashing

### Bonus: If blessed with Admin privilege =>
1. Disables Event Log via _killing_ EventLog Service Threads (**MITRE ATT&CK TTP: [T1562.002](https://attack.mitre.org/techniques/T1562/002/)**)
> **Disadv**: If threads are resumed, all events that occurred during the suspension of Event Logger, get logged Again!

**So, thought of killing them instead!**
> "It's more Invasive than suspension, but the decision is always up to the operator. Besides, killing threads get logged on the kernel level" - [@SEKTOR7net](https://twitter.com/Sektor7Net)

### = EDR/Ring-3/UserLand hook Bypass Probably! -> Don't have EDR to check it though ;(

-----

### Further Improvements:
1. PPID spoofing (**Emotet method**)
2. ***Much Stabler*** Use Case of EventLog Disabling!
-----

### Portions of the Code and links those helped:
1. TIB:
   - https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
   - https://www.wikiwand.com/en/Win32_Thread_Information_Block
2. GS and FS register:
   - https://stackoverflow.com/questions/39137043/what-is-the-gs-register-used-for-on-windows
   - https://stackoverflow.com/questions/10810203/what-is-the-fs-gs-register-intended-for#:~:text=The%20registers%20FS%20and%20GS,to%20access%20thread%2Dspecific%20memory.
3. PEB LDR structure: 
   - [BlackHat - What Malware Authors Don't Want You to Know - Evasive Hollow Process Injection](https://www.youtube.com/watch?v=9L9I1T5QDg4&t=205s) by [@monnappa22](https://twitter.com/monnappa22)
   - A pic of process Memory from the Above link:\
   ![image](https://github.com/reveng007/DarkWidow/assets/61424547/df32d679-e2e7-44cd-9291-3246cb86ef4f)

   - From [labs.cognisys.group](https://labs.cognisys.group/posts/Combining-Indirect-Dynamic-Syscalls-and-API-Hashing/#retrieving-apis-base-address), a blog by [@D1rkMtr
](https://twitter.com/D1rkMtr):\
   ![image](https://github.com/reveng007/DarkWidow/assets/61424547/dad91491-4ab2-481a-90a5-7842816507da)

4. TIB -> TEB -> PEB -> Resolve API
   - https://stackoverflow.com/questions/41277888/iterating-over-peb-dllname-shows-only-exe-name
   - https://doxygen.reactos.org/d7/d55/ldrapi_8c_source.html#l01124
   - A pic of the snippet from the above link, which I used here to resolve API dynamically without HardCoding Offsets:\
     ![image](https://github.com/reveng007/DarkWidow/assets/61424547/9aa9f990-e6fc-419d-87f0-c058c7ba61a2)

5. ACG(Arbitrary Code Guard)/BlockDll mitigation policy:
   - links:
   - [Protecting Your Malware](https://blog.xpnsec.com/protecting-your-malware/) by [@_xpn_](https://twitter.com/_xpn_)
   - [Wraith](https://github.com/reveng007/AQUARMOURY/blob/1923e65190875f7c61c76fb430d526e5deaa062a/Wraith/Src/Injector.h) by [@winterknife](https://twitter.com/_winterknife_)
   - [spawn](https://github.com/boku7/spawn) and [HOLLOW](https://github.com/boku7/HOLLOW) by [@0xBoku](https://twitter.com/0xBoku)
   ![image](https://github.com/reveng007/DarkWidow/assets/61424547/dceef77b-c3a4-464f-812d-df8f03214558)

6. PPID Spoofing Detection:
   - [PPID Spoofing Detect](https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing) by [@spotheplanet](https://twitter.com/spotheplanet)
   - If got time, I will be adding a detection Portion to this portion! -> _[Remaining..............................................!]_

7. Moneta Detection and PESieve Detection:
   - awdwadadwwd
   - adawdd

8. EventLogger Config, I used:
![image](https://github.com/reveng007/DarkWidow/assets/61424547/c2005b8c-1750-4046-bffa-9d09eb4472a8)
![WhatsApp Image 2023-07-26 at 10 55 15](https://github.com/reveng007/DarkWidow/assets/61424547/28b22684-3403-4be2-a862-e963339e2240)

9. Setting SeDebugPrivilege:\
   **From** Here:
   ![image](https://github.com/reveng007/DarkWidow/assets/61424547/f345af8c-b2b2-4918-b00b-f481694f29ec)
   **To** Here:
   ![image](https://github.com/reveng007/DarkWidow/assets/61424547/279f906b-faae-477e-9192-8bc0ec950376)

10. Killing Event Log Threads:\
    - [rto-win-evasion](https://institute.sektor7.net/rto-win-evasion) by [@SEKTOR7net](https://twitter.com/Sektor7Net)
    - [Phant0m](https://github.com/hlldz/Phant0m) by [@hlldz](https://twitter.com/hlldz)
    - [disabling-windows-event-logs-by-suspending-eventlog-service-threads](https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads) by [@spotheplanet](https://twitter.com/spotheplanet)
    **From** here:\
    ![image](https://github.com/reveng007/DarkWidow/assets/61424547/c5985623-9974-424a-b739-64097ee98747)\
    **To** here:\
    ![image](https://github.com/reveng007/DarkWidow/assets/61424547/4d039ea6-730e-414c-8cf0-afa5960f4480)

