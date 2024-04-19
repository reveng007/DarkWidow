#pragma once
//#define SPAWN "C:\\Users\\HP\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe"
//#define SPAWN_DIR "C:\\Users\\HP\\AppData\\Roaming\\Zoom\\bin"
//#define SPAWN "C:\\Users\\Victim3\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe"
//#define SPAWN_DIR "C:\\Users\\Victim3\\AppData\\Roaming\\Zoom\\bin"
#define SPAWN "C:\\Windows\\System32\\RuntimeBroker.exe"
#define SPAWN_DIR "C:\\Windows\\System32"
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#define true 1
#define MAX_STACK_SIZE 12000
#define RBP_OP_INFO 0x5


//"C:\\Users\\HP\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe"
//"c:\\windows\\system32\\SecurityHealthSystray.exe"
//"C:\\Windows\\System32\\SecurityHealthSystray.exe"

#define TARGET_PROCESS          L"\\??\\C:\\Windows\\System32\\RuntimeBroker.exe"
#define PROCESS_PARMS           L"C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"
#define PROCESS_PATH            L"C:\\Windows\\System32"

// "C:\\Users\\HP\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe"
// "C:\\Users\\HP\\AppData\\Roaming\\Zoom\\bin"

// "C:\Users\\Victim3\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe"
// "C:\Users\\Victim3\\AppData\\Roaming\\Zoom\\bin"

