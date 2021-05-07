#include "AntiDBG.h"
#include <iostream>
#define SHOW_DEBUG_MESSAGES

// =======================================================================
// Debugging helper
// =======================================================================
void DBG_MSG(WORD dbg_code, const char* message)
{
#ifdef SHOW_DEBUG_MESSAGES
    printf("[MSG-0x%X]: %s\n", dbg_code, message);
    MessageBoxA(NULL, message, "GAME OVER!", 0);
#endif
}

// =======================================================================
// Memory Checks
// These checks focus on Windows structures containing information which 
// can reveal the presence of a debugger. 
// =======================================================================

/*
 * Want to inspect the PEB structure? Launch gauntlet in WinDBG and run
 * this command: dt ntdll!_PEB
 * Example output:
 * 0:000> dt ntdll!_PEB
 * +0x000 InheritedAddressSpace : UChar
 * +0x001 ReadImageFileExecOptions : UChar
 * +0x002 BeingDebugged    : UChar        <-- This is what we're checking
 * ...snip...
 */
void adbg_BeingDebuggedPEB(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    found = adbg_BeingDebuggedPEBx64();
#else
    _asm
    {
        xor eax, eax;			// clear eax
        mov eax, fs: [0x30] ;	// Reference start of the PEB
        mov eax, [eax + 0x02];	// PEB+2 points to BeingDebugged
        and eax, 0xFF;			// only reference one byte
        mov found, eax;			// Copy BeingDebugged into 'found'
    }
#endif

    if (found)
    {
        DBG_MSG(DBG_BEINGEBUGGEDPEB, "Caught by BeingDebugged PEB check!");
        exit(DBG_BEINGEBUGGEDPEB);
    }
}


void adbg_CheckRemoteDebuggerPresent(void)
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    BOOL found = FALSE;

    hProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(hProcess, &found);

    if (found)
    {
        DBG_MSG(DBG_CHECKREMOTEDEBUGGERPRESENT, "Caught by CheckRemoteDebuggerPresent!");
        exit(DBG_CHECKREMOTEDEBUGGERPRESENT);
    }
}

void adbg_CheckWindowName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const wchar_t* WindowNameOlly = L"OllyDbg - [CPU]";
    const wchar_t* WindowNameImmunity = L"Immunity Debugger - [CPU]";

    // Check for OllyDBG class name
    hWindow = FindWindow(NULL, WindowNameOlly);
    if (hWindow)
    {
        found = TRUE;
    }

    // Check for Immunity class name
    hWindow = FindWindow(NULL, WindowNameImmunity);
    if (hWindow)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_FINDWINDOW, "Caught by FindWindow (WindowName)!");
        exit(DBG_FINDWINDOW);
    }
}

void adbg_ProcessFileName(void)
{
    // detect debugger by process file (for example: ollydbg.exe)
    const wchar_t *debuggersFilename[6] = {
        L"cheatengine-x86_64.exe", 
        L"ollydbg.exe", 
        L"ida.exe", 
        L"ida64.exe", 
        L"radare2.exe", 
        L"x64dbg.exe"
    };

    wchar_t* processName;
    PROCESSENTRY32W processInformation{ sizeof(PROCESSENTRY32W) };
    HANDLE processList;

    processList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    processInformation = { sizeof(PROCESSENTRY32W) };
    if (!(Process32FirstW(processList, &processInformation)))
        printf("[Warning] It is impossible to check process list.");
    else
    {
        do
        {
            for (const wchar_t *debugger : debuggersFilename)
            {
                processName = processInformation.szExeFile;
                if (_wcsicmp(debugger, processName) == 0) {
                    DBG_MSG(DBG_PROCESSFILENAME, "Caught by ProcessFileName!");
                    exit(DBG_PROCESSFILENAME);
                }
            }
        } while (Process32NextW(processList, &processInformation));
    }
    CloseHandle(processList);
}

void adbg_CheckWindowClassName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const wchar_t* WindowClassNameOlly = L"OLLYDBG";		// OllyDbg
    const wchar_t* WindowClassNameImmunity = L"ID";			// Immunity Debugger

    // Check for OllyDBG class name
    hWindow = FindWindow(WindowClassNameOlly, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    // Check for Immunity class name
    hWindow = FindWindow(WindowClassNameImmunity, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_FINDWINDOW, "Caught by FindWindow (ClassName)!");
        exit(DBG_FINDWINDOW);
    }
}

void adbg_IsDebuggerPresent(void)
{
    BOOL found = FALSE;
    found = IsDebuggerPresent();

    if (found)
    {
        DBG_MSG(DBG_ISDEBUGGERPRESENT, "Caught by IsDebuggerPresent!");
        exit(DBG_ISDEBUGGERPRESENT);
    }
}

/*
 * Want to inspect the value of something in the PEB? Launch WinDBG,
 * Attach to, or launch a process and run this command: 
 * dt ntdll!_PEB @$peb -r
 * Want more info on NtGlobalFlag? See these resources:
 * https://www.aldeid.com/wiki/PEB-Process-Environment-Block/NtGlobalFlag
 * https://www.geoffchappell.com/studies/windows/win32/ntdll/api/rtl/regutil/getntglobalflags.htm
 */
void adbg_NtGlobalFlagPEB(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    found = adbg_NtGlobalFlagPEBx64();
#else
    _asm
    {
        xor eax, eax;			// clear eax
        mov eax, fs: [0x30] ;	// Reference start of the PEB
        mov eax, [eax + 0x68];	// PEB+0x68 points to NtGlobalFlag
        and eax, 0x00000070;	// check three flags:
                                //   FLG_HEAP_ENABLE_TAIL_CHECK   (0x10)
                                //   FLG_HEAP_ENABLE_FREE_CHECK   (0x20)
                                //   FLG_HEAP_VALIDATE_PARAMETERS (0x40)
        mov found, eax;			// Copy result into 'found'
    }
#endif

    if (found)
    {
        DBG_MSG(DBG_NTGLOBALFLAGPEB, "Caught by NtGlobalFlag PEB check!");
        exit(DBG_NTGLOBALFLAGPEB);
    }
}


void adbg_NtQueryInformationProcess(void)
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    PROCESS_BASIC_INFORMATION pProcBasicInfo = {0};
    ULONG returnLength = 0;
    
    // Get a handle to ntdll.dll so we can import NtQueryInformationProcess
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
    {
        return;
    }

    // Dynamically acquire the addres of NtQueryInformationProcess
    _NtQueryInformationProcess  NtQueryInformationProcess = NULL;
    NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (NtQueryInformationProcess == NULL)
    {
        return;
    }
    
    hProcess = GetCurrentProcess();
    
    // Note: There are many options for the 2nd parameter NtQueryInformationProcess
    // (ProcessInformationClass) many of them are opaque. While we use ProcessBasicInformation (0), 
    // we could also use:
    //      ProcessDebugPort (7)
    //      ProcessDebugObjectHandle (30)
    //      ProcessDebugFlags (31)
    // There are likely others. You can find many other options for ProcessInformationClass over at PINVOKE:
    //      https://www.pinvoke.net/default.aspx/ntdll/PROCESSINFOCLASS.html
    // Keep in mind that NtQueryInformationProcess will return different things depending on the ProcessInformationClass used.
    // Many online articles using NtQueryInformationProcess for anti-debugging will use DWORD types for NtQueryInformationProcess 
    // paramters. This is fine for 32-builds with some ProcessInformationClass values, but it will cause some to fail on 64-bit builds.
    // In the event of a failure NtQueryInformationProcess will likely return STATUS_INFO_LENGTH_MISMATCH (0xC0000004). 

    // Query ProcessDebugPort
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pProcBasicInfo, sizeof(pProcBasicInfo), &returnLength);
    if (NT_SUCCESS(status)) {
        PPEB pPeb = pProcBasicInfo.PebBaseAddress;
        if (pPeb)
        {
            if (pPeb->BeingDebugged)
            {
                DBG_MSG(DBG_NTQUERYINFORMATIONPROCESS, "Caught by NtQueryInformationProcess (ProcessDebugPort)!");
                exit(DBG_NTQUERYINFORMATIONPROCESS);
            }
        }
    }
}


void adbg_NtSetInformationThread(void)
{
    THREAD_INFORMATION_CLASS ThreadHideFromDebugger = (THREAD_INFORMATION_CLASS)0x11;

    // Get a handle to ntdll.dll so we can import NtSetInformationThread
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
    {
        return;
    }

    // Dynamically acquire the addres of NtSetInformationThread and NtQueryInformationThread
    _NtSetInformationThread NtSetInformationThread = NULL;
    NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");

    if (NtSetInformationThread == NULL)
    {
        return;
    }

    // There is nothing to check here after this call.
    NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);
}


void adbg_DebugActiveProcess(const char* cpid)
{
    BOOL found = FALSE;
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    TCHAR szPath[MAX_PATH];
    DWORD exitCode = 0;

    CreateMutex(NULL, FALSE, L"antidbg");
    if (GetLastError() != ERROR_SUCCESS)
    {
        // If we get here we are in the child process
        if (DebugActiveProcess((DWORD)atoi(cpid)))
        {
            // No debugger found.
            return;
        }
        else
        {
            // Debugger found, exit child with a unique code we can check for.
            exit(555);
        }
    }

    // parent process
    DWORD pid = GetCurrentProcessId();
    GetModuleFileName(NULL, szPath, MAX_PATH);

    char cmdline[MAX_PATH + 1 + sizeof(int)];
    snprintf(cmdline, sizeof(cmdline), "%ws %d", szPath, pid);

    // Start the child process. 
    BOOL success = CreateProcessA(
        NULL,		// path (NULL means use cmdline instead)
        cmdline,	// Command line
        NULL,		// Process handle not inheritable
        NULL,		// Thread handle not inheritable
        FALSE,		// Set handle inheritance to FALSE
        0,			// No creation flags
        NULL,		// Use parent's environment block
        NULL,		// Use parent's starting directory 
        &si,		// Pointer to STARTUPINFO structure
        &pi);		// Pointer to PROCESS_INFORMATION structure

    // Wait until child process exits and get the code
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Check for our unique exit code
    GetExitCodeProcess(pi.hProcess, &exitCode);
    if (exitCode == 555)
    {
        found = TRUE;
    }

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (found)
    {
        DBG_MSG(DBG_DEBUGACTIVEPROCESS, "Caught by DebugActiveProcess!");
        exit(DBG_DEBUGACTIVEPROCESS);
    }
}


// =======================================================================
// Timing Checks
// These checks focus on comparison of time stamps between a portion
// of code which is likely to be analyzed under a debugger. The goal
// is to determine with high probability that a debugger is allowing
// single step control, or that a breakpoint had been hit between
// the time check locations.
// =======================================================================

void adbg_RDTSC(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    uint64_t timeA = 0;
    uint64_t timeB = 0;
    TimeKeeper timeKeeper = { 0 };
    adbg_RDTSCx64(&timeKeeper);
    
    timeA = timeKeeper.timeUpperA;
    timeA = (timeA << 32) | timeKeeper.timeLowerA;

    timeB = timeKeeper.timeUpperB;
    timeB = (timeB << 32) | timeKeeper.timeLowerB;

    // 0x100000 is purely empirical and is based on the CPU clock speed
    // This value should be change depending on the length and complexity of 
    // code between each RDTSC operation.

    if (timeB - timeA > 0x100000)
    {
        found = TRUE;
    }

#else
    int timeUpperA = 0;
    int timeLowerA = 0;
    int timeUpperB = 0;
    int timeLowerB = 0;
    int timeA = 0;
    int timeB = 0;

    _asm
    {
        // rdtsc stores result across EDX:EAX
        rdtsc;
        mov [timeUpperA], edx;
        mov [timeLowerA], eax;

        // Junk code to entice stepping through or a breakpoint
        xor eax, eax;
        mov eax, 5;
        shr eax, 2;
        sub eax, ebx;
        cmp eax, ecx;

        rdtsc;
        mov [timeUpperB], edx;
        mov [timeLowerB], eax;
    }

    timeA = timeUpperA;
    timeA = (timeA << 32) | timeLowerA;

    timeB = timeUpperB;
    timeB = (timeB << 32) | timeLowerB;

    // 0x100000 is purely empirical and is based on the CPU clock speed
    // This value should be change depending on the length and complexity of 
    // code between each RDTSC operation.

    if (timeB - timeA > 0x10000)
    {
        found = TRUE;
    }

#endif

    if (found)
    {
        DBG_MSG(DBG_RDTSC, "Caught by RDTSC!");
        exit(DBG_RDTSC);
    }
}


void adbg_QueryPerformanceCounter(void)
{
    BOOL found = FALSE;
    LARGE_INTEGER t1;
    LARGE_INTEGER t2;

    QueryPerformanceCounter(&t1);

#ifdef _WIN64
    adbg_QueryPerformanceCounterx64();
#else
    // Junk or legit code.
    _asm
    {
        xor eax, eax;
        push eax;
        push ecx;
        pop eax;
        pop ecx;
        sub ecx, eax;
        shl ecx, 4;
    }
#endif

    QueryPerformanceCounter(&t2);

    // 30 is an empirical value
    if ((t2.QuadPart - t1.QuadPart) > 30)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_QUERYPERFORMANCECOUNTER, "Caught by QueryPerformanceCounter!");
        exit(DBG_QUERYPERFORMANCECOUNTER);
    }
}


void adbg_GetTickCount(void)
{
    BOOL found = FALSE;
    DWORD t1;
    DWORD t2;

    t1 = GetTickCount();

#ifdef _WIN64
    adbg_GetTickCountx64();
#else
    // Junk or legit code.
    _asm
    {
        xor eax, eax;
        push eax;
        push ecx;
        pop eax;
        pop ecx;
        sub ecx, eax;
        shl ecx, 4;
    }
#endif

    t2 = GetTickCount();

    // 30 milliseconds is an empirical value
    if ((t2 - t1) > 30)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_GETTICKCOUNT, "Caught by GetTickCount!");
        exit(DBG_GETTICKCOUNT);
    }
}


// =======================================================================
// CPU Checks
// These checks focus on aspects of the CPU, including hardware break-
// points, special interrupt opcodes, and flags.
// =======================================================================

void adbg_HardwareDebugRegisters(void)
{
    BOOL found = FALSE;
    CONTEXT ctx = { 0 };
    HANDLE hThread = GetCurrentThread();

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx))
    {
        if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
        {
            found = TRUE;
        }
    }

    if (found)
    {
        DBG_MSG(DBG_HARDWAREDEBUGREGISTERS, "Caught by a Hardware Debug Register Check!");
        exit(DBG_HARDWAREDEBUGREGISTERS);
    }
}


void adbg_MovSS(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    // This method does not work on x64
#else
    _asm
    {
        push ss;
        pop ss;
        pushfd;
        test byte ptr[esp + 1], 1;
        jne fnd;
        jmp end;
    fnd:
        mov found, 1;
    end:
        nop;
    }
#endif

    if (found)
    {
        DBG_MSG(DBG_MOVSS, "Caught by a MOV SS Single Step Check!");
        exit(DBG_MOVSS);
    }
}


// =======================================================================
// Exception Checks
// These checks focus on exceptions that occur when under the control of 
// a debugger. In several cases, there are certain exceptions that will
// be thrown only when running under a debugger.
// =======================================================================


void adbg_CloseHandleException(void)
{
    HANDLE hInvalid = (HANDLE)0xBEEF; // an invalid handle
    DWORD found = FALSE;

    __try
    {
        CloseHandle(hInvalid);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_CLOSEHANDLEEXCEPTION, "Caught by an CloseHandle exception!");
        exit(DBG_CLOSEHANDLEEXCEPTION);
    }
}


void adbg_SingleStepException(void)
{
    DWORD found = TRUE;

    // In this method we force an exception to occur. If it occurs
    // outside of a debugger, the __except() handler is called setting
    // found to FALSE. If the exception occurs inside of a debugger, the
    // __except() will not be called (in certain cases) leading to
    // found being TRUE.

    __try
    {
#ifdef _WIN64
        adbg_SingleStepExceptionx64();
#else
        _asm
        {
            pushfd;						// save EFFLAGS register
            or byte ptr[esp + 1], 1;	// set trap flag in EFFLAGS
            popfd;						// restore EFFLAGS register
        }
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_SINGLESTEPEXCEPTION, "Caught by a Single Step Exception!");
        exit(DBG_SINGLESTEPEXCEPTION);
    }
}


void adbg_Int3(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        adbg_Int3x64();
#else
        _asm
        {
            int 3;	// 0xCC standard software breakpoint
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_INT3CC, "Caught by a rogue INT 3!");
        exit(DBG_INT3CC);
    }
}


void adbg_PrefixHop(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        // TODO: Not yet implemented in x64
        found = FALSE;
#else
        _asm
        {
            __emit 0xF3;	// 0xF3 0x64 is the prefix 'REP'
            __emit 0x64;
            __emit 0xCC;	// this gets skipped over if being debugged
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_PREFIXHOP, "Caught by a Prefix Hop!");
        exit(DBG_PREFIXHOP);
    }
}


void adbg_Int2D(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        adbg_Int2Dx64();
#else
        _asm
        {
            int 0x2D;
            nop;
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_NONE, "Caught by a rogue INT 2D!");
        exit(DBG_NONE);
    }
}

// =======================================================================
// Other Checks
// Other kinds of checks that don't fit into the normal categories.
// =======================================================================

void adbg_CrashOllyDbg(void)
{
    // crash OllyDbg v1.x by exploit
    __try {
        OutputDebugString(TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { ; }
}
