#pragma once

#include <Windows.h>
#include <Winternl.h>
#include <stdio.h>

// Error Codes
enum DBG_CATCH
{
	DBG_NONE = 0x0000,

	// Memory Codes (0x1000 range)
	DBG_BEINGEBUGGEDPEB = 0x1000,
	DBG_CHECKREMOTEDEBUGGERPRESENT = 0x1001,
	DBG_ISDEBUGGERPRESENT = 0x1002,
	DBG_NTGLOBALFLAGPEB = 0x1003,
	DBG_NTQUERYINFORMATIONPROCESS = 0x1004,
	DBG_FINDWINDOW = 0x1005,
	DBG_OUTPUTDEBUGSTRING = 0x1006,
	DBG_NTSETINFORMATIONTHREAD = 0x1007,
	DBG_DEBUGACTIVEPROCESS = 0x1008,

	// CPU Codes (0x2000 range)
	DBG_HARDWAREDEBUGREGISTERS = 0x2000,
	DBG_MOVSS = 0x2001,

	// Timing Codes (0x3000 range)
	DBG_RDTSC = 0x3000,
	DBG_QUERYPERFORMANCECOUNTER = 0x3001,
	DBG_GETTICKCOUNT = 0x3002,

	// Exception Codes (0x4000 range)
	DBG_CLOSEHANDLEEXCEPTION = 0x4000,
	DBG_SINGLESTEPEXCEPTION = 0x4001,
	DBG_INT3CC = 0x4002,
	DBG_PREFIXHOP = 0x4003,

} DBG_CATCH;

// Debugging messages
void DBG_MSG(WORD dbg_code, char* message);

// Dynamically resolved functions
typedef NTSTATUS(__stdcall *_NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall *_NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);

// Memory
void adbg_BeingDebuggedPEB(void);
void adbg_CheckRemoteDebuggerPresent(void);
void adbg_CheckWindowName(void);
void adbg_IsDebuggerPresent(void);
void adbg_NtGlobalFlagPEB(void);
void adbg_NtQueryInformationProcess(void);
void adbg_NtSetInformationThread(void);
void adbg_DebugActiveProcess(const char*);

// CPU
void adbg_HardwareDebugRegisters(void);
void adbg_MovSS(void);

// Timing
void adbg_RDTSC(void);
void adbg_QueryPerformanceCounter(void);
void adbg_GetTickCount(void);

// Exception
void adbg_CloseHandleException(void);
void adbg_SingleStepException(void);
void adbg_Int3(void);
void adbg_Int2D(void);
void adbg_PrefixHop(void);
