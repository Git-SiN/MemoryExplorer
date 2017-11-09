#include "symbols.h"


#define		SIN_DEV_MEM							(ULONG)0x7789



#define		IOCTL_REQUEST_DATA					(ULONG)CTL_CODE(SIN_DEV_MEM, 0x01, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define		IOCTL_SELECT_TARGET					(ULONG)CTL_CODE(SIN_DEV_MEM, 0X02, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define		IOCTL_UNSELECT_TARGET				(ULONG)CTL_CODE(SIN_DEV_MEM, 0X03, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define		IOCTL_MANIPULATE_MEMORY				(ULONG)CTL_CODE(SIN_DEV_MEM, 0X20, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define		IOCTL_GET_PFN_DETAILS				(ULONG)CTL_CODE(SIN_DEV_MEM, 0X21, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)

#define		IOCTL_GET_VAD_MAP					(ULONG)CTL_CODE(SIN_DEV_MEM, 0X41, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define		IOCTL_GET_VAD_DETAILS				(ULONG)CTL_CODE(SIN_DEV_MEM, 0X42, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)
#define		IOCTL_GET_VAD_SUBSECTIONS			(ULONG)CTL_CODE(SIN_DEV_MEM, 0X43, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)

#define		IOCTL_MEMORY_DUMP_PAGE				(ULONG)CTL_CODE(SIN_DEV_MEM, 0X60, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)
#define		IOCTL_MEMORY_DUMP_VAD				(ULONG)CTL_CODE(SIN_DEV_MEM, 0X61, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)
#define		IOCTL_MEMORY_DUMP_ULONG_FLAGS		(ULONG)CTL_CODE(SIN_DEV_MEM, 0X62, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)
#define		IOCTL_MEMORY_DUMP_CA				(ULONG)CTL_CODE(SIN_DEV_MEM, 0X63, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)
#define		IOCTL_MEMORY_DUMP_SEGMENT			(ULONG)CTL_CODE(SIN_DEV_MEM, 0X64, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)
#define		IOCTL_MEMORY_DUMP_SUBSECTION		(ULONG)CTL_CODE(SIN_DEV_MEM, 0X65, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)
#define		IOCTL_MEMORY_DUMP_RANGE				(ULONG)CTL_CODE(SIN_DEV_MEM, 0X70, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)

#define		IOCTL_FIND_PATTERN_UNICODE			(ULONG)CTL_CODE(SIN_DEV_MEM, 0X80, METHOD_BUFFERED, FILE_WRITE_ACCESS)


#define		IOCTL_QUIT_COMMUNICATION			(ULONG)CTL_CODE(SIN_DEV_MEM, 0X81, METHOD_BUFFERED, FILE_WRITE_ACCESS)


#pragma pack(1)

typedef struct _PROCESS_INFO {
	ULONG Eprocess;
	ULONG DirectoryTableBase;
	ULONG ProcessId;
	ULONG HandleTable;
	WCHAR ImageFullName[256];
	ULONG Peb;
	ULONG VadRoot;
	ULONG ThreadListHead;
}PROCESS_INFO, *PPROCESS_INFO;

typedef struct _VAD_MAP {
	ULONG Vad;
	ULONG Start;
	ULONG End;
	ULONG Commit;	
	WCHAR FileName[256];
	UCHAR Level;
	BOOLEAN isPrivate;
}VAD_MAP, *PVAD_MAP;

typedef struct _VAD_DETAILS_SUBSECTION {
	ULONG SubsectionAddress;
	ULONG BasePTE;
	ULONG PtesInSubsection;
	ULONG UnusedPtes;
	ULONG Flags;
	ULONG StartingSector;
	ULONG NumberOfFullSectors;
} VAD_DETAILS_SUBSECTION, *PVAD_DETAILS_SUBSECTION;

typedef struct _VAD_DETAILS {
	ULONG VadAddress;		
	ULONG StartVPN;
	ULONG EndVPN;
	ULONG VadFlags;
	ULONG VadFlags3;
	ULONG VadFlags2;
	ULONG FirstPrototypePte;
	ULONG LastContiguousPte;
	ULONG ControlArea;
	ULONG CA_Flags;
	ULONG CA_Deref_FLink;
	ULONG CA_Deref_BLink;
	ULONG CA_NumberOfSectionReferences;
	ULONG CA_NumberOfPfnReferences;
	ULONG CA_NumberOfMappedViews;
	ULONG CA_NumberOfUserReferences;
	ULONG CA_FlushInProgressCount;
	ULONG CA_ModifiedWriteCount;
	ULONG CA_WaitingForDeletion;
	ULONG CA_NumberOfSystemCacheViews;
	ULONG CA_WritableUserReferences;
	ULONG CA_View_FLink; 
	ULONG CA_View_BLink;
	ULONG CA_FileObject;
	WCHAR CA_FileName[256];
	ULONG Segment;
	ULONG SG_TotalNumberOfPtes;
	ULONG SG_Flags;
	ULONG SG_NumberOfCommittedPages;
	LARGE_INTEGER SG_SizeOfSegment;
	VAD_DETAILS_SUBSECTION ASubsection;		// if Any Subsections exist, ASubsection.SubsectionAddress is 0xFFFFFFFF.
}VAD_DETAILS, *PVAD_DETAILS;

typedef struct _HANDLE_ENTRY {
	ULONG HandleNumber;
	ULONG EntryAddress;	
	ULONG FileObject;
	ULONG GrantedAccess;
	ULONG Type;
	WCHAR Name[256];
}HANDLE_ENTRY, *PHANDLE_ENTRY;

typedef struct _WORKINGSET_SUMMARY {
	ULONG Count;
	ULONG Contents[18];
}WORKINGSET_SUMMARY, *PWORKINGSET_SUMMARY;

typedef struct _PFN_DETAILS
{
	ULONG DirBase;
	ULONG PDPTAddress;
	ULONG PDPEAddress;
	LARGE_INTEGER PDPEValue;
	ULONG PDTAddress;
	ULONG PDEAddress;
	LARGE_INTEGER PDEValue;
	ULONG PTAddress;
	ULONG PTEAddress;
	LARGE_INTEGER PTEValue;
	LARGE_INTEGER PhysicalAddress;
	UCHAR PDTPfnDatabase[28];
	UCHAR PTPfnDatabase[28];
	UCHAR PagePfnDatabase[28];
}PFN_DETAILS, *PPFN_DETAILS;

typedef struct	_MESSAGE_ENTRY {
	ULONG MessageType;
	UCHAR Buffer[1024];
}MESSAGE_ENTRY, *PMESSAGE_ENTRY;


#pragma pack()