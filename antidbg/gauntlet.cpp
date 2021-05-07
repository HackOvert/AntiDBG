/*
 * AntiDBG is a collection of Windows anti-debugging tricks.
 * The "gaultlet" execuable is a sample application you can test under a debugger.
 * Most anti-debugging methods are located in AntiDBG.cpp
 * Any x64 anti-debugging methods using inline assembly have their assembly 
 * located in AntiDBG.asm
 */

#include "AntiDBG.h"

 // =======================================================================
// The Gauntlet
// =======================================================================
int main(int argc, char* argv[])
{
	/*
	This sample application calls all included anti-debugging methods
	one after the other. Your goal is to start from the entry point,
	and debug your way to the end without the debugger closing on you.

	Make sure to try the gauntlet out in different debuggers:
		- OllyDBG
		- Immunity
		- x64dbg
		- WinDBG
		- IDA Pro
		- etc.

	Different debuggers will handle exceptions their own way by default. 
	For example, some of our breakpoint exceptions will not work in x64dbg
	under default setting.

	Good Luck!
	*/
	
	// -------------------------------------------------------------------
	// -- Memory Checks --------------------------------------------------
	// -------------------------------------------------------------------
	adbg_IsDebuggerPresent();
	adbg_BeingDebuggedPEB();
	adbg_NtGlobalFlagPEB();
	adbg_CheckRemoteDebuggerPresent();
	adbg_NtQueryInformationProcess();
	adbg_CheckWindowClassName();
	adbg_CheckWindowName();
	adbg_ProcessFileName();
	adbg_NtSetInformationThread();
	adbg_DebugActiveProcess(argv[1]);

	// -------------------------------------------------------------------
	// -- CPU Checks -----------------------------------------------------
	// -------------------------------------------------------------------
	adbg_HardwareDebugRegisters();
	adbg_MovSS();

	// -------------------------------------------------------------------
	// -- Timing Checks --------------------------------------------------
	// -------------------------------------------------------------------
	adbg_RDTSC();
	adbg_QueryPerformanceCounter();
	adbg_GetTickCount();

	// -------------------------------------------------------------------
	// -- Exception Checks -----------------------------------------------
	// -------------------------------------------------------------------
	adbg_CloseHandleException();
	adbg_SingleStepException();
	adbg_Int3();
	adbg_Int2D();
	adbg_PrefixHop();
	
	// -------------------------------------------------------------------
	// -- Other ----------------------------------------------------------
	// -------------------------------------------------------------------
	adbg_CrashOllyDbg();

	// Your goal is to get here in a debugger without modifying EIP yourself.
	MessageBoxA(NULL, "Congratulations! You made it!", "You Win!", 0);

	return 0;
}
