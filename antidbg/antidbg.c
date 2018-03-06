#include <Windows.h>
#include "antidbg.h"

#define SHOW_DEBUG_MESSAGES

// =======================================================================
// Debugging helper
// =======================================================================
void DBG_MSG(WORD dbg_code, char* message)
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
 * // adbg_BeingDebuggedPEB()
 *
 * // How it works:
 * Checks the Process Environment Block (PEB) for a "BeingDebugged"
 * field which is set when the process launches under a debugger. This
 * method is exactly what IsDebuggerPresent() checks under the hood,
 * it is simply the assembly version of this call.
 * 
 * // Indication:
 * Look for PEB references.
 * These references typically start with FS:[0x30h]. FS stands for
 * "Frame Segment" and generally indicates references to an application's
 * own internal header structures. These should not raise red flags,
 * however they should be noted.
 *
 * // Bypass:
 * Once the BeingDebugged byte in the PEB is queried, flip the value
 * from 1 to 0 before it is evaluated by the application logic.
 */
void adbg_BeingDebuggedPEB(void)
{
	BOOL found = FALSE;
	_asm
	{
		xor eax, eax;			// clear eax
		mov eax, fs:[0x30];		// Reference start of the PEB
		mov eax, [eax + 0x02];	// PEB+2 points to BeingDebugged
		and eax, 0x000000FF;	// only reference one byte
		mov found, eax;			// Copy BeingDebugged into 'found'
	}

	if (found)
	{
		DBG_MSG(DBG_BEINGEBUGGEDPEB, "Caught by BeingDebugged PEB check!");
		exit(DBG_BEINGEBUGGEDPEB);
	}
}


/* 
 * // adbg_CheckRemoteDebuggerPresent()
 *
 * // How it works:
 * ...
 * 
 * // Indication: 
 * Look for this imported function or calls to GetProcAddress().
 * CheckRemoteDebuggerPresent is similar to IsDebuggerPresent,
 * except. It allows an applicaion to query the debugging state of
 * another application via a process handle. The BOOL return value
 * is used to determine if the process (hProcess) is being debugged.
 *
 * // Bypass: 
 * Set a breakpoint on CheckRemoteDebuggerPresent(), single step, 
 * then switch the return value to 0.
 */
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


/*
* // adbg_CheckWindowName()
*
* // How it works:
* Checks for a window with a specific Class name. This name is
* not the title of the Window. Use tools like Nirsoft Winlister
* to find this value.
*
* // Indication:
* Look for FindWindow on the imports list or strings of common
* begugger names. Some exeptions exist, like in the case of IDA
* whose window Class name is "QWidget" and nothing related to IDA.
*
* // Bypass:
* Set a breakpoint on FindWindow, single step, then
* switch the return value to 0.
*/
void adbg_CheckWindowName(void)
{
	BOOL found = FALSE;
	HANDLE hWindow = NULL;
	wchar_t *WindowClassNameIDA = L"Qt5QWindowIcon";	// IDA Pro
	wchar_t *WindowClassNameOlly = L"OLLYDBG";			// OllyDbg
	wchar_t *WindowClassNameImmunity = L"ID";			// Immunity Debugger
	
	// Check for IDA Pro
	hWindow = FindWindow(WindowClassNameIDA, 0);
	if (hWindow)
	{
		found = TRUE;
	}
	
	// Check for OllyDBG
	hWindow = FindWindow(WindowClassNameOlly, 0);
	if (hWindow)
	{
		found = TRUE;
	}
	
	// Check for Immunity
	hWindow = FindWindow(WindowClassNameImmunity, 0);
	if (hWindow)
	{
		found = TRUE;
	}

	if (found)
	{
		DBG_MSG(DBG_FINDWINDOW, "Caught by FindWindow!");
		exit(DBG_FINDWINDOW);
	}
}


/*
 * // adbg_IsDebuggerPresent()
 *
 * // How it works:
 * Checks the PEB structure for the value of BeingDebugged.
 * 
 * // Indication:
 * Look for this imported function or calls to GetProcAddress().
 * IsDebuggerPresent is exported from kernel32.dll. The BOOL return value
 * is used to determine if an application is being debugged.
 *
 * // Bypass:
 * Set a breakpoint on IsDebuggerPresent(), single step, then
 * switch the return value to 0.
 */
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
 * // adbg_NtGlobalFlagPEB()
 *
 * // How it works:
 * 
 * 
 * // Indication:
 * Look for Process Environment Block (PEB) references.
 * These references typically start with FS:[0x30h]. FS stands for
 * "Frame Segment" and generally indicates references to an application's
 * own internal header structures. These should not raise red flags,
 * however they should be noted. 0x68 offset from the PEB is the
 * NtGlobalFlag value. When a process is being debugged, three flags
 * are set, FLG_HEAP_ENABLE_TAIL_CHECK (0x10), FLG_HEAP_ENABLE_FREE_CHECK
 * (0x20), and FLG_HEAP_VALIDATE_PARAMETERS (0x40).
 *
 * // Bypass:
 * ...
 */
void adbg_NtGlobalFlagPEB(void)
{
	BOOL found = FALSE;
	_asm
	{
		xor eax, eax;			// clear eax
		mov eax, fs:[0x30];		// Reference start of the PEB
		mov eax, [eax + 0x68];	// PEB+0x68 points to NtGlobalFlags
		and eax, 0x00000070;	// check three flags
		mov found, eax;			// Copy result into 'found'
	}

	if (found)
	{
		DBG_MSG(DBG_NTGLOBALFLAGPEB, "Caught by NtGlobalFlag PEB check!");
		exit(DBG_NTGLOBALFLAGPEB);
	}
}


/* 
 * // adbg_NtQueryInformationProcess()
 *
 * // How it works:
 * ... There are two checks here... (1. xxx, 2. NoDebugInherit)
 * 
 * // Indication:
 * ...
 *
 * // Bypass:
 * ...
 */
void adbg_NtQueryInformationProcess(void)
{
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	DWORD found = FALSE;
	DWORD ProcessDebugPort = 0x07;	// 1st method; See MSDN for details
	DWORD ProcessDebugFlags = 0x1F;	// 2nd method; See MSDN for details
	
	// Get a handle to ntdll.dll so we can import NtQueryInformationProcess
	HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
	{
		goto CANT_CHECK;
	}

	// Dynamically acquire the addres of NtQueryInformationProcess
	_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

	if (NtQueryInformationProcess == NULL)
	{
		goto CANT_CHECK;
	}

	// Method 1: Query ProcessDebugPort
	hProcess = GetCurrentProcess();
	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessDebugPort, &found, sizeof(DWORD), NULL);

	if (!status && found)
	{
		DBG_MSG(DBG_NTQUERYINFORMATIONPROCESS, "Caught by NtQueryInformationProcess, (ProcessDebugPort)!");
		exit(DBG_NTQUERYINFORMATIONPROCESS);
	}

	// Method 2: Query ProcessDebugFlags
	status = NtQueryInformationProcess(hProcess, ProcessDebugFlags, &found, sizeof(DWORD), NULL);

	// The ProcessDebugFlags caused 'found' to be 1 if no debugger is found, so we check !found.
	if (!status && !found)
	{
		DBG_MSG(DBG_NTQUERYINFORMATIONPROCESS, "Caught by NtQueryInformationProcess, (ProcessDebugFlags)!");
		exit(DBG_NTQUERYINFORMATIONPROCESS);
	}

	CANT_CHECK:
	_asm
	{
		nop;
	}
}


/*
 * // adbg_NtSetInformationThread()
 *
 * // How it works:
 * Hides the main thread from the debugger. Any attempt to control 
 * the process after this call will end the debugging session.
 *
 * // Indication:
 * ...
 *
 * // Bypass:
 * ...
 */
void adbg_NtSetInformationThread(void)
{
	DWORD ThreadHideFromDebugger = 0x11;

	// Get a handle to ntdll.dll so we can import NtSetInformationThread
	HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
	{
		goto CANT_CHECK;
	}

	// Dynamically acquire the addres of NtSetInformationThread and NtQueryInformationThread
	_NtSetInformationThread NtSetInformationThread = NULL;
	NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
	
	if (NtSetInformationThread == NULL)
	{
		goto CANT_CHECK;
	}
	
	// There is nothing to check here after this call.
	NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);

CANT_CHECK:
	_asm
	{
		nop;
	}
}


/*
* // adbg_DebugActiveProcess()
*
* // How it works:
* ...
*
* // Indication:
* ...
*
* // Bypass:
* ...
*/
void adbg_DebugActiveProcess(const char *cpid)
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

/*
 * // adbg_RDTSC()
 *
 * // How it works:
 * ...
 *
 * // Indication:
 * ...
 *
 * // Bypass:
 * ...
 */
void adbg_RDTSC(void)
{
	BOOL found = FALSE;

	UINT64 timeA, timeB = 0;
	int timeUpperA, timeLowerA = 0;
	int timeUpperB, timeLowerB = 0;

	_asm
	{
		// rdtsc stores result across EDX:EAX
		rdtsc;
		mov timeUpperA, edx;
		mov timeLowerA, eax;

		// Junk code to entice stepping through or a breakpoint
		xor eax, eax;
		mov eax, 5;
		shr eax, 2;
		sub eax, ebx;
		cmp eax, ecx

		rdtsc;
		mov timeUpperB, edx;
		mov timeLowerB, eax;
	}

	timeA = timeUpperA;
	timeA = (timeA << 32) | timeLowerA;

	timeB = timeUpperB;
	timeB = (timeB << 32) | timeLowerB;

	/* 0x10000 is purely empirical and is based on the computer's clock cycle
	   This value should be change depending on the length and complexity of 
	   code between each RDTSC operation. */
	if (timeB - timeA > 0x10000)
	{
		found = TRUE;
	}

	if (found)
	{
		DBG_MSG(DBG_RDTSC, "Caught by RDTSC!");
		exit(DBG_RDTSC);
	}
}


/*
* // adbg_QueryPerformanceCounter()
*
* // How it works:
* ...
*
* // Indication:
* ...
*
* // Bypass:
* ...
*/
void adbg_QueryPerformanceCounter(void)
{
	BOOL found = FALSE;
	LARGE_INTEGER t1;
	LARGE_INTEGER t2;

	QueryPerformanceCounter(&t1);

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


/*
* // adbg_RDTSC()
*
* // How it works:
* ...
*
* // Indication:
* ...
*
* // Bypass:
* ...
*/
void adbg_GetTickCount(void)
{
	BOOL found = FALSE;
	DWORD t1;
	DWORD t2;

	t1 = GetTickCount();

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

/*
 * // adbg_HardwareDebugRegisters()
 * 
 * // How it works:
 * ...
 * 
 * // Indication:
 * ...
 * 
 * // Bypass:
 * ...
 */
void adbg_HardwareDebugRegisters(void)
{
	BOOL found = FALSE;
	CONTEXT ctx = { 0 };
	HANDLE hThread = GetCurrentThread();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if(GetThreadContext(hThread, &ctx))
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


/*
* // adbg_MovSS()
*
* // How it works:
* ...
*
* // Indication:
* ...
*
* // Bypass:
* ...
*/
void adbg_MovSS(void)
{
	BOOL found = FALSE;
	
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

/* 
 * // adbg_CloseHandleException()
 *
 * // How it works:
 * CloseHandle will throw an exception when trying to close an
 * invalid handle, only when running under a debugger. We pass
 * an invalid handle into CloseHandle to force an exception, 
 * where our own exception handler will close the application.
 * 
 * // Indication:
 * Look for possibly invalid handles passed to CloseHandle().
 * The validity of a handle can be difficult to assess, but
 * an application closing shortly after CloseHandle is a great
 * indication.
 *
 * // Bypass:
 * Modify the invalid handle passed into CloseHandle()
 * to be INVALID_HANDLE_VALUE, patch the call, or adjust EIP to
 * skip over the invalid CloseHandle. This may be easier said than
 * done if the CloseHandle is called many times with a mix of
 * valid and invalid handles.
 *
 */
void adbg_CloseHandleException(void)
{
	HANDLE hInvalid = (HANDLE)0xDEADBEEF; // an invalid handle
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


/*
 * // adbg_SingleStepException()
 * 
 * // How it works:
 * ...
 *
 * // Indication:
 * ...
 *
 * // Bypass:
 * ...
 *
 */
void adbg_SingleStepException(void)
{
	DWORD found = TRUE;

	/*
	In this method we force an exception to occur. If it occurs
	outside of a debugger, the __except() handler is called setting
	found to FALSE. If the exception occurs inside of a debugger, the
	__except() will not be called (in certain cases) leading to
	found being TRUE.
	*/

	__try
	{
		_asm 
		{
			pushfd;						// save flag register
			or byte ptr[esp + 1], 1;	// set trap flag in EFlags
			popfd;						// restore flag register
		}
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

/*
* // adbg_Int3()
*
* // How it works:
* INT 3 is a standard software breakpoint (opcode 0xCC). When
* you set a breakpoint, your debugger replaces the first opcode
* under the breakpoint location with a 0xCC (INT 3). When the
* debugger hits this opcode it breaks and restores the original
* opcode. We add an exeption handler that switches 'found' from
* true to false. Without a debugger, *something must* handle the
* breakpoint exception (which is our handler). If our handler does
* not get hit, it means a debugger attempted to handle the
* exception itself, an in turn, leaving 'found' marked true.
*
* // Indication:
* Most debuggers go out of their way to hide the fact that they
* have replaced an opcode with 0xCC. In IDA for example, you need
* to specifically set an option to show these replacements. If you
* ever see an INT 3 instruction or a 0xCC (standalone) opcode, 
* red flags should go up.
*
* // Bypass:
* Most debuggers will give you an option when an exception is 
* thrown - either pass the exception to the application (and
* hope it's equipped to handle it), or discard the exception
* and have the debugger handle it instead. Your debugger is 
* perfectly capacble of handling a breakpoint exception, but
* if your debugger handles this exception, 'found' is never
* marked false, and you're busted. When in doubt, pass
* exceptions to the application.
*/
void adbg_Int3(void)
{
	BOOL found = TRUE;

	__try 
	{	
		_asm 
		{
			int 3;	// 0xCC standard software breakpoint
		}
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


/*
* // adbg_PrefixHop()
*
* // How it works:
* ...
*
* // Indication:
* ...
*
* // Bypass:
* ...
*
*/
void adbg_PrefixHop(void)
{
	BOOL found = TRUE;

	__try
	{
		_asm 
		{
			__emit 0xF3;	// 0xF3 0x64 is the prefix 'REP'
			__emit 0x64;
			__emit 0xCC;	// this gets skipped over if being debugged
		}
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


/*
* // adbg_Int2D()
*
* // How it works:
* ...
*
* // Indication:
* ...
*
* // Bypass:
* ...
*
*/
void adbg_Int2D(void)
{
	BOOL found = TRUE;

	__try
	{
		_asm
		{
			int 0x2D;	// kernel breakpoint
		}
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
