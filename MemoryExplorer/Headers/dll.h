
#include "loader.h"
#pragma comment(lib, "..\\Libs\\loader.lib")

#ifndef __MEMORY_DLL_HEADER__
#define __MEMORY_DLL_HEADER__

#ifdef __CPLUSPLUS
extern "C" {
#endif


#ifdef __DLL_SOURCE_CODE
#define SINFUNC		__declspec(dllexport)
#else
#define SINFUNC		__declspec(dllimport)
#endif
	SINFUNC		BOOLEAN ConnectToKernel();
	SINFUNC		VOID CancelPendingIrp();
	SINFUNC		BOOLEAN DisConnect();
	SINFUNC		BOOLEAN SendControlMessage(UCHAR control, ULONG message);
	SINFUNC		BOOLEAN SendControlMessageByPointer(UCHAR control, PVOID pMessage, ULONG length);
	SINFUNC		BOOLEAN ReadMessage(PVOID buffer);
	SINFUNC		BOOLEAN GetAddressDetails(UCHAR type, PMESSAGE_ENTRY buffer);
	SINFUNC		ULONG GetMemoryDump(UCHAR type, ULONG startAddress, PUCHAR buffer);
	SINFUNC		BOOLEAN ManipulateMemory(ULONG startAddress, ULONG length, PUCHAR buffer);
#ifdef __CPLUSPLUS
}
#endif
#endif



