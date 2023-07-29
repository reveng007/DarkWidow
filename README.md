# DarkWidow
This is a Dropper/PostExploitation Tool (or can be used in both situations) targeting Windows.

### Capabilities:
1. Indirect Dynamic Syscall
2. SSN + Syscall address sorting via Modified TartarusGate approach
3. Remote Process Injection via APC Early Bird
4. Spawns a sacrificial Process as the target process
5. ACG(Arbitrary Code Guard)/BlockDll mitigation policy on spawned process
6. PPID spoofing (**MITRE ATT&CK TTP: [T1134.004](https://attack.mitre.org/techniques/T1134/004/)**)
7. Api resolving from TIB (Directly via offset (from TIB) -> TEB -> PEB -> resolve Nt Api)
8. Cursed Nt API hashing

### Bonus: If blessed with Admin privilege =>
1. Disables Event Log via _killing_ EventLog Service Threads (**MITRE ATT&CK TTP: [T1562.002](https://attack.mitre.org/techniques/T1562/002/)**)
> **Disadv**: If threads are resumed, all events that occurred during the suspension of Event Logger, get logged Again!

**So, thought of killing them instead!**
> "It's more Invasive than suspension, but the decision is always up to the operator. Besides, killing threads get logged on the kernel level" - [@SEKTOR7net](https://twitter.com/Sektor7Net)

#### While Killing only those threads in the indirect syscall implant, was facing an error. I was unable to get the "**eventlog**" _SubProcessTag Value_. So thought of killing all threads, i.e. killing the whole process (responsible **svchost.exe**). Yeah creating ***an IOC***!.

### = EDR/Ring-3/UserLand hook Bypass!

### Compile:
1.
```
Directly via VS compiler:
```
![image](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion/assets/61424547/622c39a1-c3b3-4388-ad3a-5a36d18e29ff)

#### Also add **/MT** compiler flag! => To statically links CRT functions together in a binary (Yeah, U guessed it, it bloats the implant)

![image](https://github.com/reveng007/DarkWidow/assets/61424547/58e9a9d4-e068-4364-8114-96744bdbc0a7)

2. Also via compile.bat (prefer option 1.)
```
./compile.bat
```

### Usage:
```
PS C:> .\x64\Release\indirect.exe
[!] Wrong!
[->] Syntax: .\x64\Release\indirect.exe <PPID to spoof>
```
### In Action:

https://github.com/reveng007/DarkWidow/assets/61424547/62a90c5b-84af-4389-8ddc-9f7926debdcf

### Sofos XDR Bypass:

![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/SofosXDR.PNG)

-----

### Further Improvements:
1. PPID spoofing (**Emotet method**)
2. ***Much Stealthier*** Use Case of EventLog Disabling!
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
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/1.png)

   - From [labs.cognisys.group](https://labs.cognisys.group/posts/Combining-Indirect-Dynamic-Syscalls-and-API-Hashing/#retrieving-apis-base-address), a blog by [@D1rkMtr
](https://twitter.com/D1rkMtr):\
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/2.png)

4. TIB -> TEB -> PEB -> Resolve Nt API and API hashing
   - https://stackoverflow.com/questions/41277888/iterating-over-peb-dllname-shows-only-exe-name
   - https://doxygen.reactos.org/d7/d55/ldrapi_8c_source.html#l01124
   - [labs.cognisys.group](https://labs.cognisys.group/posts/Combining-Indirect-Dynamic-Syscalls-and-API-Hashing/#retrieving-apis-base-address), a blog by [@D1rkMtr
](https://twitter.com/D1rkMtr)
   - A pic of the snippet from the above link, which I used here to resolve API dynamically without HardCoding Offsets:\
     ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/3.png)

5. ACG(Arbitrary Code Guard)/BlockDll mitigation policy:
   - links:
   - [Protecting Your Malware](https://blog.xpnsec.com/protecting-your-malware/) by [@_xpn_](https://twitter.com/_xpn_)
   - [Wraith](https://github.com/reveng007/AQUARMOURY/blob/1923e65190875f7c61c76fb430d526e5deaa062a/Wraith/Src/Injector.h) by [@winterknife](https://twitter.com/_winterknife_)
   - [spawn](https://github.com/boku7/spawn) and [HOLLOW](https://github.com/boku7/HOLLOW) by [@0xBoku](https://twitter.com/0xBoku)
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/4.png)

6. PPID Spoofing Detection:
   - [PPID Spoofing Detect](https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing) by [@spotheplanet](https://twitter.com/spotheplanet)
   - If got time, I will be adding a detection Portion to this portion! -> _[Remaining..............................................!]_

7. Moneta Detection and PESieve Detection:\
   - **Moneta**:\
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/5.png)

   - **PESieve**:\
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/6.png)

9. Capa Scan:\
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/7.png)

10. How Thread Stack Looks of the Implant Process:

| Implant Process  |   Legit Cmd process    |
| ---------------- | ---------------- |  
|  ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/8.png) | ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/9.png) |

> **It follows that by executing the return instruction in the memory of the ntdll.dll in the indirect syscall POC, the return address can be successfully spoofed, the ntdll.dll can be placed at the top of the call stack and the EDR will interpret a higher legitimacy.** - [@VirtualAllocEx](https://twitter.com/VirtualAllocEx) from [DirectSyscall Vs Indirect Syscall](https://redops.at/blog/direct-syscalls-vs-indirect-syscalls)\
Also thanks to, [@peterwintrsmith](https://twitter.com/peterwintrsmith)!

10. EventLogger Config, I used:
![image](https://github.com/reveng007/DarkWidow/assets/61424547/c2005b8c-1750-4046-bffa-9d09eb4472a8)
![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/10.png)

11. Setting SeDebugPrivilege:\
   **From** Here:
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/11.png)
   **To** Here:
   ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/12.png)

12. Killing Event Log Threads:
    - [rto-win-evasion](https://institute.sektor7.net/rto-win-evasion) by [@SEKTOR7net](https://twitter.com/Sektor7Net)
    - [Phant0m](https://github.com/hlldz/Phant0m) by [@hlldz](https://twitter.com/hlldz)
    - [Goblin](https://github.com/reveng007/AQUARMOURY/blob/master/Goblin/Src/EventLog.h) by [@winterknife](https://twitter.com/_winterknife_)
    - [disabling-windows-event-logs-by-suspending-eventlog-service-threads](https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads) by [@spotheplanet](https://twitter.com/spotheplanet)\
    **From** here:\
    ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/13.png)\
    **To** here:\
    ![alt text](https://github.com/reveng007/DarkWidow/blob/main/img/14.png)
    - **This Method, Ended up causing errors in indirect syscall implementation. So, I ended up killing all those threads present within responsible svchost.exe** (reason: [Go up](https://github.com/reveng007/DarkWidow/edit/main/README.md#bonus-if-blessed-with-admin-privilege-)).

### Major Thanks for helping me out (Directly/indirectly (pun NOT intended :))):
1. [@SEKTOR7net](https://twitter.com/Sektor7Net)
2. [@peterwintrsmith](https://twitter.com/peterwintrsmith)
3. [@Jean_Maes_1994](https://twitter.com/Jean_Maes_1994)
4. [@D1rkMtr](https://twitter.com/D1rkMtr)
5. [@spotheplanet](https://twitter.com/spotheplanet)
6. [@0xBoku](https://twitter.com/0xBoku)
7. [@Sh0ckFR](https://twitter.com/Sh0ckFR)
8. [@winterknife](https://twitter.com/_winterknife_)
9. [@monnappa22](https://twitter.com/monnappa22)
10. [@_xpn_](https://twitter.com/_xpn_)
11. [@hlldz](https://twitter.com/hlldz)

I hope I didn't miss someone!

### This project is a part of my journey to learn about EDR World! => [Learning-EDR-and-EDR_Evasion](https://github.com/reveng007/Learning-EDR-and-EDR_Evasion)

