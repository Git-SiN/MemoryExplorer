#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>

#include "..\Headers\\driver.h"
#define __DLL_SOURCE_CODE
#include "..\Headers\dll.h"

#define SIN_DRIVER_NAME		_T("MemoryExplorer")
#define SIN_DEVICE_NAME		_T("\\\\.\\MemoryExplorer")


TCHAR DRIVER_FULL_NAME[MAX_PATH] = { 0, };
HANDLE hDevice = INVALID_HANDLE_VALUE;
OVERLAPPED readOverlapped;


BOOLEAN MakeFullName() {
	ULONG bufferLength = 0;

	bufferLength = GetCurrentDirectory(MAX_PATH * sizeof(TCHAR), DRIVER_FULL_NAME);
	if (bufferLength == 0)
		return FALSE;

	_tcscat_s(DRIVER_FULL_NAME, MAX_PATH - 1, _T("\\"));
#ifdef _DEBUG
	_tcscat_s(DRIVER_FULL_NAME, MAX_PATH - 1, _T("i386\\"));
#endif
	_tcscat_s(DRIVER_FULL_NAME, MAX_PATH - 1, SIN_DRIVER_NAME);
	_tcscat_s(DRIVER_FULL_NAME, MAX_PATH - 1, _T(".sys"));
	return TRUE;
}

// Store the Starting address in the first 4 bytes of buffer at here. 
BOOLEAN ManipulateMemory(ULONG startAddress, ULONG length, PUCHAR buffer) {
	BOOLEAN result = FALSE;
	ULONG received = 0;
	OVERLAPPED manipulateOverlapped;

	if ((startAddress == 0) || (startAddress > 0xFFFFFFF0) || (length == 0) || (length > 16))
		return FALSE;

	ZeroMemory(&manipulateOverlapped, sizeof(OVERLAPPED));
	manipulateOverlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (manipulateOverlapped.hEvent == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	*(PULONG)buffer = startAddress;
	*(PULONG)(buffer + 4) = length;

	result = DeviceIoControl(hDevice, IOCTL_MANIPULATE_MEMORY, buffer, 8+length, NULL, 0, &received, &manipulateOverlapped);
	if (!result) {
		if (GetLastError() == ERROR_IO_PENDING) {
			WaitForSingleObject(manipulateOverlapped.hEvent, INFINITE);
			result = (GetOverlappedResult(hDevice, &manipulateOverlapped, &received, FALSE));
		}		
	}

	return result;
}

ULONG GetMemoryDump(UCHAR type, ULONG startAddress, PUCHAR buffer) {
	OVERLAPPED dumpOverlapped;
	ULONG received = 0;
	BOOLEAN result = FALSE;

	ZeroMemory(&dumpOverlapped, sizeof(OVERLAPPED));
	dumpOverlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (dumpOverlapped.hEvent == INVALID_HANDLE_VALUE) {
		return 0;
	}

	result = DeviceIoControl(hDevice, (ULONG)CTL_CODE(SIN_DEV_MEM, type, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS), &startAddress, 4, buffer, 4100, &received, &dumpOverlapped);
	if (!result) {
		if (GetLastError() == ERROR_IO_PENDING) {
			WaitForSingleObject(dumpOverlapped.hEvent, INFINITE);
			result = GetOverlappedResult(hDevice, &dumpOverlapped, &received, FALSE);
		}
	}
	else
		GetOverlappedResult(hDevice, &dumpOverlapped, &received, FALSE);

	CloseHandle(dumpOverlapped.hEvent);
	if (result)
		return received;
	else
		return 0;
}


BOOLEAN GetAddressDetails(UCHAR type, PMESSAGE_ENTRY buffer) {
	OVERLAPPED detailOverlapped;
	BOOLEAN result = 0;
	ULONG received = 0;

	ZeroMemory(&detailOverlapped, sizeof(OVERLAPPED));
	detailOverlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (detailOverlapped.hEvent == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	
	result = DeviceIoControl(hDevice, CTL_CODE(SIN_DEV_MEM, type, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS), NULL, 0, buffer, sizeof(MESSAGE_ENTRY), &received, &detailOverlapped);
	if (!result) {
		if (GetLastError() == ERROR_IO_PENDING) {
			WaitForSingleObject(detailOverlapped.hEvent, INFINITE);
			result = GetOverlappedResult(hDevice, &detailOverlapped, &received, FALSE);
		}
	}
	CloseHandle(detailOverlapped.hEvent);
	return result;
}


BOOLEAN ReadMessage(PVOID buffer) {
	BOOLEAN result;
	ULONG received = 0;

	result = ReadFile(hDevice, buffer, sizeof(MESSAGE_ENTRY), &received, &readOverlapped);
	if (!result) {
		if (GetLastError() == ERROR_IO_PENDING) {
			WaitForSingleObject(readOverlapped.hEvent, INFINITE);
			result = GetOverlappedResult(hDevice, &readOverlapped, &received, FALSE);
		}
	}

	return result;	
}



BOOLEAN SendControlMessageByPointer(UCHAR control, PVOID pMessage, ULONG length) {
	OVERLAPPED controlOverapped;
	BOOLEAN result;
	ULONG received = 0;

	ZeroMemory(&controlOverapped, sizeof(OVERLAPPED));
	controlOverapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (controlOverapped.hEvent == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	result = DeviceIoControl(hDevice, CTL_CODE(SIN_DEV_MEM, control, METHOD_BUFFERED, FILE_WRITE_ACCESS), pMessage, length, NULL, 0, &received, &controlOverapped);
	if (!result) {
		if (GetLastError() == ERROR_IO_PENDING) {
			WaitForSingleObject(controlOverapped.hEvent, INFINITE);
			result = GetOverlappedResult(hDevice, &controlOverapped, &received, FALSE);		
		}
	}

	CloseHandle(controlOverapped.hEvent);
	return result;
}

// Only METHOD_BUFFERED...
BOOLEAN SendControlMessage(UCHAR control, ULONG message) {
	BOOLEAN result;
	ULONG received = 0;
	OVERLAPPED controlOverlapped;

	ZeroMemory(&controlOverlapped, sizeof(OVERLAPPED));
	controlOverlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (controlOverlapped.hEvent == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	result = DeviceIoControl(hDevice, (ULONG)CTL_CODE(SIN_DEV_MEM, control, METHOD_BUFFERED, FILE_WRITE_ACCESS), &message, 4, NULL, 0, &received, &controlOverlapped);
	if (!result) {
		if (GetLastError() == ERROR_IO_PENDING) {
			WaitForSingleObject(controlOverlapped.hEvent, INFINITE);
			result = GetOverlappedResult(hDevice, &controlOverlapped, &received, FALSE);
		}
	}

	CloseHandle(controlOverlapped.hEvent);
	return result;
}

BOOLEAN ConnectToKernel() {
	// Check the privilege and Load my driver.
	if (TestPrivileges() && MakeFullName() &&
		ManageDriver(DRIVER_FULL_NAME, MANAGE_DRIVER_INSTALL) &&
		ManageDriver(DRIVER_FULL_NAME, MANAGE_DRIVER_START)) {

		hDevice = CreateFile(SIN_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
		if (hDevice != INVALID_HANDLE_VALUE) {
			ZeroMemory(&readOverlapped, sizeof(OVERLAPPED));
			readOverlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			if ((readOverlapped.hEvent != INVALID_HANDLE_VALUE) ) {
				return TRUE;
			}
			else
				DisConnect();
		}
		else
			OutputDebugString(L"Can not open the device...\n");
	}
	else
		OutputDebugString(L"Failed to start the driver...\n");
	return FALSE;
}

VOID CancelPendingIrp() {
	BOOLEAN result = FALSE;
	
	result = CancelIoEx(hDevice, NULL);
	if (!result) {
		OutputDebugString(L"**** CancelPendingIrp() success...\n");
	}
	else {
		if (GetLastError() == ERROR_NOT_FOUND) {
			OutputDebugString(L"**** CancelPendingIrp() failed : ERROR_NOT_FOUND\n");
		}
		else
			OutputDebugString(L"**** CancelPendingIrp() failed...\n");
	}
	return;
}

BOOLEAN DisConnect() {
	if (readOverlapped.hEvent != INVALID_HANDLE_VALUE)
		CloseHandle(readOverlapped.hEvent);

	CloseHandle(hDevice);
	return ((ManageDriver(DRIVER_FULL_NAME, MANAGE_DRIVER_STOP)) &&
		(ManageDriver(DRIVER_FULL_NAME, MANAGE_DRIVER_REMOVE)));
}
