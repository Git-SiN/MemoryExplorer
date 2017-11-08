#pragma once

#ifndef __LOADER_H__
#define __LOADER_H__

#define MANAGE_DRIVER_INSTALL		(UCHAR)0x01
#define MANAGE_DRIVER_START			(UCHAR)0x02
#define MANAGE_DRIVER_STOP			(UCHAR)0x04
#define MANAGE_DRIVER_REMOVE		(UCHAR)0x08



#ifdef __cplusplus
extern "C" {
#endif


#ifdef __EXPORT_DLL__
#define __LOADERFUNC		__declspec(dllexport)
#else
#define __LOADERFUNC		__declspec(dllimport)
#endif

	__LOADERFUNC BOOLEAN TestPrivileges();
	__LOADERFUNC BOOLEAN ManageDriver(LPCTSTR fullName, UCHAR behavior);
	__LOADERFUNC BOOLEAN InstallDriver(SC_HANDLE hSCM, LPCTSTR driverName, LPCTSTR fullName);
	__LOADERFUNC BOOLEAN RemoveDriver(SC_HANDLE hSCM, LPCTSTR driverName);
	__LOADERFUNC BOOLEAN StartDriver(SC_HANDLE hSCM, LPCTSTR driverName);
	__LOADERFUNC BOOLEAN StopDriver(SC_HANDLE hSCM, LPCTSTR driverName);


#ifdef __cplusplus
	}
#endif

#endif