#pragma pack(1)


// #define	   MmPfnDatabase		0x82f80834// 이거 하드코딩되어있긴한데.... 혹시 모르니 그냥 오프셋으로하자...
#define		OFFSET_PFN_DATABASE_IN_MmGetVirtualForPhysical			0x1A
#define		LENGTH_OF_PFN_ENTRY										0x1C
/////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////			MiSystemVaTypeArray			/////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
#define    MiVaSessionSpace			0x1
#define    MiVaProcessSpace			0x2
#define    MiVaBootLoaded			0x3
#define    MiVaPfnDatabase			0x4
#define    MiVaNonPagedPool			0x5
#define    MiVaPagedPool			0x6
#define    MiVaSpecialPool			0x7
#define    MiVaSystemCache			0x8
#define    MiVaSystemPte			0x9
#define    MiVaHal					0xA
#define    MiVaSessionGlobalSpace	0xB
#define    MiVaDriverImages			0xC
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////			EPROCESS		  ///////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
#define EPROC_OFFSET_Pcb							0x000 //  _KPROCESS
#define EPROC_OFFSET_CreateTime						0x0a0 //  _LARGE_INTEGER
#define EPROC_OFFSET_ExitTime						0x0a8 //  _LARGE_INTEGER
#define EPROC_OFFSET_UniqueProcessId				0x0b4 //  Void
#define EPROC_OFFSET_ActiveProcessLinks				0x0b8 //  _LIST_ENTRY
#define EPROC_OFFSET_VirtualSize					0x0e0 //  Uint4B
#define EPROC_OFFSET_SessionProcessLinks			0x0e4 //  _LIST_ENTRY
#define EPROC_OFFSET_ObjectTable					0x0f4 //  _HANDLE_TABLE
#define EPROC_OFFSET_Token							0x0f8 //  _EX_FAST_REF
#define EPROC_OFFSET_PhysicalVadRoot				0x110 //  _MM_AVL_TABLE
#define EPROC_OFFSET_Win32Process					0x120 //  Void
#define EPROC_OFFSET_InheritedFromUniqueProcessId	0x140 //  Void
#define EPROC_OFFSET_ConsoleHostProcess				0x14c //  Uint4B
#define EPROC_OFFSET_DeviceMap						0x150 //  Void
#define EPROC_OFFSET_PageDirectoryPte				0x160 //  _HARDWARE_PTE
#define EPROC_OFFSET_Session						0x168 //  Void
#define EPROC_OFFSET_ImageFileName					0x16c //  [15] EPROC_OFFSET_UChar
#define EPROC_OFFSET_PriorityClass					0x17b //  UChar
#define EPROC_OFFSET_ThreadListHead					0x188 //  _LIST_ENTRY
#define EPROC_OFFSET_ActiveThreads					0x198 //  Uint4B
#define EPROC_OFFSET_ImagePathHash					0x19c //  Uint4B
#define EPROC_OFFSET_Peb							0x1a8 //  _PEB
#define EPROC_OFFSET_SeAuditProcessCreationInfo		0x1ec //  _SE_AUDIT_PROCESS_CREATION_INFO
#define EPROC_OFFSET_Vm								0x1f0 //  _MMSUPPORT
#define EPROC_OFFSET_MmProcessLinks					0x25c //  _LIST_ENTRY
#define EPROC_OFFSET_ModifiedPageCount				0x268 //  Uint4B
#define EPROC_OFFSET_VadRoot						0x278 //  _MM_AVL_TABLE
#define EPROC_OFFSET_AlpcContext					0x298 //  _ALPC_PROCESS_CONTEXT
#define EPROC_OFFSET_SequenceNumber					0x2c0 //  Uint8B


/////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////			KPROCESS			/////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
#define KPROC_OFFSET_Header							0x000 //  _DISPATCHER_HEADER
#define KPROC_OFFSET_ProfileListHead				0x010 //  _LIST_ENTRY
#define KPROC_OFFSET_DirectoryTableBase				0x018 //  Uint4B
#define KPROC_OFFSET_LdtDescriptor					0x01c //  _KGDTENTRY
#define KPROC_OFFSET_Int21Descriptor				0x024 //  _KIDTENTRY
#define KPROC_OFFSET_ThreadListHead					0x02c //  _LIST_ENTRY
#define KPROC_OFFSET_ReadyListHead					0x044 //  _LIST_ENTRY
#define KPROC_OFFSET_SwapListEntry					0x04c //  _SINGLE_LIST_ENTRY
#define KPROC_OFFSET_ActiveProcessors				0x050 //  _KAFFINITY_EX
#define KPROC_OFFSET_BasePriority					0x060 //  Char
#define KPROC_OFFSET_Flags							0x06c //  _KEXECUTE_OPTIONS
#define KPROC_OFFSET_StackCount						0x074 //  _KSTACK_COUNT
#define KPROC_OFFSET_ProcessListEntry				0x078 //  _LIST_ENTRY
#define KPROC_OFFSET_CycleTime						0x080 //  Uint8B
#define KPROC_OFFSET_KernelTime						0x088 //  Uint4B
#define KPROC_OFFSET_UserTime						0x08c //  Uint4B


/////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////			KTHREAD			///////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
#define KTHREAD_OFFSET_State					0x068		// UChar
#define KTHREAD_OFFSET_Queue					0x07C		// Ptr32 _KQUEUE
#define KTHREAD_OFFSET_Teb						0x088		// Ptr32 Void
#define KTHREAD_OFFSET_QueueListEntry			0x120		// _LIST_ENTRY
#define KTHREAD_OFFSET_FirstArgument			0x12C		// Ptr32 Void	
#define KTHREAD_OFFSET_BasePriority				0x135		// Char
#define KTHREAD_OFFSET_PriorityDecrement		0x136		// Char
#define KTHREAD_OFFSET_KPROCESS					0x150		//  Ptr32 _KPROCESS

#define KTHREAD_OFFSET_Win32Thread				0x18C		 // Ptr32 Void
#define KTHREAD_OFFSET_StackBase				0x190		// Ptr32 Void
#define KTHREAD_OFFSET_ThreadListEntry			0x1E0		// LIST_ENTRY

#define KTHREAD_OFFSET_TrapFrame				0x128 // Ptr32 _KTRAP_FRAME


typedef struct _KTHREAD_OFFSET_038 {
	struct _KWAIT_STATUS_REGISTER {
		union {
			UCHAR Flags;
			struct {
				UCHAR State : 2;
				UCHAR Affinity : 1;
				UCHAR Priority : 1;
				UCHAR Apc : 1;
				UCHAR UserApc : 1;
				UCHAR Alert : 1;
				UCHAR Unused : 1;
			};
		};
	} WaitRegister;
	UCHAR Running;
	UCHAR Alerted[2];
	union {
		struct {
			ULONG KernelStackResident : 1;
			ULONG ReadyTransition : 1;
			ULONG ProcessReadyQueue : 1;
			ULONG WaitNext : 1;
			ULONG SystemAffinityActive : 1;
			ULONG Alertable : 1;
			ULONG GdiFlushActive : 1;
			ULONG UserStackWalkActive : 1;
			ULONG ApcInterruptRequest : 1;
			ULONG ForceDeferSchedule : 1;
			ULONG QuantumEndMigrate : 1;
			ULONG UmsDirectedSwitchEnable : 1;
			ULONG TimerActive : 1;
			ULONG SystemThread : 1;
			ULONG Reserved : 18;
		};
		ULONG MiscFlags;
	};
} KTHREAD_OFFSET_038, *PKTHREAD_OFFSET_038;


typedef struct _KQUEUE {
	//DISPATCHER_HEADER Header;
	LIST_ENTRY EntryListHead;
	ULONG CurrentCount;
	ULONG MaximumCount;
	LIST_ENTRY ThreadListHead;
} KQUEUE, *PKQUEUE;

//		재정의 오류.
//typedef struct _EXCEPTION_REGISTRATION_RECORD{
//	struct _EXCEPTION_REGISTRATION_RECORD *Next;
//	EXCEPTION_DISPOSITION *Handler;
//} EXCEPTION_REGISTRATION_REC
typedef struct _KTRAP_FRAME {
	ULONG DbgEbp;
	ULONG DbgEip;
	ULONG DbgArgMark;
	ULONG DbgArgPointer;
	USHORT TempSegCs;
	UCHAR Logging;
	UCHAR Reserved;
	ULONG TempEsp;
	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;
	ULONG SegGs;
	ULONG SegEs;
	ULONG SegDs;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG PreviousPreviousMode;
	PVOID ExceptionList;		// PEXCEPTION_REGISTRATION_RECORD 
	ULONG SegFs;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Ebp;
	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
	ULONG V86Es;
	ULONG V86Ds;
	ULONG V86Fs;
	ULONG V86Gs;
} KTRAP_FRAME, *PKTRAP_FRAME;

/////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////			ETHREAD			///////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
#define ETHREAD_OFFSET_StartAddreass		0x218			// PVOID
#define ETHREAD_OFFSET_Cid					0x234		
#define ETHREAD_OFFSET_ClientSecurity   	0x248 			// PS_CLIENT_SECURITY_CONTEXT
#define ETHREAD_OFFSET_IrpList				0x24C			// ListEntry 
#define ETHREAD_OFFSET_DeviceToVerify		0x258			// PDEVICE_OBJECT
#define ETHREAD_OFFSET_Win32StartAddress	0x260			// PVOID
#define ETHRERD_OFFSET_ThreadListEntry		0x268			// ListEntry
#define ETHREAD_OFFSET_IrpListLock			0x2A8			// ULONG
#define ETHREAD_OFFSET_KernelStackReference	0X2B4			// ULONG
#define ETHREAD_OFFSET_CacheManagerActive   0x28C			// UCHAR



typedef struct _PS_CLIENT_SECURITY_CONTEXT {
	union {
		ULONG ImpersonationData;
		PVOID ImpersonationToken;	// 3비트 제거.
		struct {
			ULONG ImpersonationLevel : 2;
			ULONG EffectiveOnly : 1;
		};
	};
} PS_CLIENT_SECURITY_CONTEXT, *PPS_CLIENT_SECURITY_CONTEXT;

typedef struct _ETHREAD_FLAGS_280 {
	union {
		ULONG CrossThreadFlags;
		struct {
			ULONG Terminated :	1;
			ULONG ThreadInserted : 1;
			ULONG HideFromDebugger : 1;
			ULONG ActiveImpersonationInfo : 1;
			ULONG Reserved : 1;
			ULONG HardErrorsAreDisabled : 1;
			ULONG BreakOnTermination : 1;
			ULONG SkipCreationMsg : 1;
			ULONG SkipTerminationMsg : 1;
			ULONG CopyTokenOnOpen : 1;
			ULONG ThreadIoPriority : 3;
			ULONG ThreadPagePriority : 3;
			ULONG RundownFail : 1;
			ULONG NeedsWorkingSetAging : 1;
		};
	};
} ETHREAD_FLAGS_280;

typedef struct _ETHREAD_FLAGS_284 {
	union {
		ULONG SameThreadPassiveFlags;
		struct {
			ULONG ActiveExWorker : 1;
			ULONG ExWorkerCanWaitUser : 1;
			ULONG MemoryMaker : 1;
			ULONG ClonedThread : 1;
			ULONG KeyedEventInUse : 1;
			ULONG RateApcState : 2;
			ULONG SelfTerminate : 1;
		};
	};
} ETHREAD_FLAGS_284;

typedef struct _ETHREAD_FLAGS_288 {
	union {
		ULONG  SameThreadApcFlags;
		struct {
			struct {
				UCHAR Spare : 1;
				UCHAR StartAddressInvalid : 1;
				UCHAR EtwPageFaultCalloutActive : 1;
				UCHAR OwnsProcessWorkingSetExclusive : 1;
				UCHAR OwnsProcessWorkingSetShared : 1;
				UCHAR OwnsSystemCacheWorkingSetExclusive : 1;
				UCHAR OwnsSystemCacheWorkingSetShared : 1;
				UCHAR OwnsSessionWorkingSetExclusive : 1;

				UCHAR OwnsSessionWorkingSetShared : 1;
				UCHAR OwnsProcessAddressSpaceExclusive : 1;
				UCHAR OwnsProcessAddressSpaceShared : 1;
				UCHAR SuppressSymbolLoad : 1;
				UCHAR Prefetching : 1;
				UCHAR OwnsDynamicMemoryShared : 1;
				UCHAR OwnsChangeControlAreaExclusive : 1;
				UCHAR OwnsChangeControlAreaShared : 1;

				UCHAR OwnsPagedPoolWorkingSetExclusive : 1;
				UCHAR OwnsPagedPoolWorkingSetShared : 1;
				UCHAR OwnsSystemPtesWorkingSetExclusive : 1;
				UCHAR OwnsSystemPtesWorkingSetShared : 1;
				UCHAR TrimTrigger : 2;
				UCHAR Spare1 : 2;
			};
			UCHAR PriorityRegionActive;
		};
	};
} ETHREAD_FLAGS_288;

/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////			_OBJECT_HEADER			/////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////


// 사이즈 체크 완료.
typedef struct _OBJECT_HEADER {
	ULONG PointerCount;
	union {
		ULONG HandleCount;
		PVOID NextToFree;
	};
	ULONG Lock;			// _EX_PUSH_LOCK
	UCHAR TypeIndex;
	UCHAR TraceFlags;
	UCHAR InfoMask;
	UCHAR Flags;
	union {
		PVOID ObjectCreateInfo;		// _OBJECT_CREATE_INFORMATION
		PVOID QuotaBlockCharged;
	};
	PVOID SecurityDescriptor;
}OBJECT_HEADER, *POBJECT_HEADER;



/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////			_OBJECT_TYPE			/////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
#define OBJECT_TYPE_OFFSET_Name										0x08	// UNICODE_STRING
#define OBJECT_TYPE_OFFSET_TypeInfo									0x28	// _OBJECT_TYPE_INITIALIZER
#define OBJECT_TYPE_INITIALIZER_OFFSET_Length						0x00	// USHORT
#define OBJECT_TYPE_INITIALIZER_OFFSET_QueryNameProcedure			0x48 // PVOID

/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////				_KPRCB				//////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
#define KPRCB_OFFSET_HyperPte			0x3364			// PVOID

typedef struct _SIN_CONTEXT {
	ULONG ContextFlags;  //Uint4B
	ULONG Dr0;  //Uint4B
	ULONG Dr1;  //Uint4B
	ULONG  Dr2;  //Uint4B
	ULONG Dr3;  //Uint4B
	ULONG Dr6;  //Uint4B
	ULONG  Dr7;  //Uint4B
	UCHAR FloatSave[112];  //+0x01c FloatSave      ;  //_FLOATING_SAVE_AREA size;0x70   =112
	ULONG SegGs;  //Uint4B
	ULONG SegFs;  //Uint4B
	ULONG  SegEs;  //Uint4B
	ULONG SegDs;  //Uint4B
	ULONG Edi;  //Uint4B
	ULONG Esi;  //Uint4B
	ULONG Ebx;  //Uint4B
	ULONG Edx;  //Uint4B
	ULONG Ecx;  //Uint4B
	ULONG  Eax;  //Uint4B
	ULONG Ebp;  //Uint4B
	ULONG Eip;  //Uint4B
	ULONG  SegCs;  //Uint4B
	ULONG EFlags;  //Uint4B
	ULONG Esp;  //Uint4B
	ULONG  SegSs;  //Uint4B
	UCHAR ExtendedRegisters[512];  //[512] UChar
}SIN_CONTEXT, *PSIN_CONTEXT;

typedef struct _DESCRIPTOR {
	USHORT Pad;    // Uint2B
	USHORT Limit;    // Uint2B
	ULONG Base;    // Uint4B
} DESCRIPTOR, *PDESCRIPTOR;

typedef struct _SIN_KSPECIAL_REGISTERS {
	ULONG Cr0;    // Uint4B
	ULONG Cr2;    // Uint4B
	ULONG Cr3;    // Uint4B
	ULONG Cr4;    // Uint4B
	ULONG  KernelDr0;    // Uint4B
	ULONG KernelDr1;    // Uint4B
	ULONG KernelDr2;    // Uint4B
	ULONG KernelDr3;    // Uint4B
	ULONG  KernelDr6;    // Uint4B
	ULONG  KernelDr7;    // Uint4B
	DESCRIPTOR Gdtr;    // _DESCRIPTOR
	DESCRIPTOR Idtr;    // _DESCRIPTOR
	USHORT Tr;    // Uint2B
	USHORT Ldtr;    // Uint2B
	ULONG Reserved[6];    // [6] Uint4B
}SIN_KSPECIAL_REGISTERS, *PSIN_KSPECIAL_REGISTERS;


typedef struct _SIN_KPROCESSOR_STATE {
	SIN_CONTEXT ContextFrame;     // _CONTEXT
	SIN_KSPECIAL_REGISTERS SpecialRegisters; // _KSPECIAL_REGISTERS
}SIN_KPROCESSOR_STATE, *PSIN_KPROCESSOR_STATE;

typedef struct _KPRCB {
	USHORT MinorVersion; // 1
	USHORT MajorVersion; // 1
	PVOID CurrentThread; // 0x82f72480 _KTHREAD
	PVOID NextThread; // (null) 
	PVOID IdleThread; // 0x82f72480 _KTHREAD
	UCHAR LegacyNumber; // 0 ''
	UCHAR NestingLevel; // 0 ''
	USHORT BuildType; // 0
	UCHAR CpuType; // 6 ''
	UCHAR CpuID; // 1 ''
	union {
		USHORT CpuStep; // 0x4501
		struct {
			UCHAR CpuStepping; // 0x1 ''
			UCHAR CpuModel; // 0x45 'E'
		};
	};
	SIN_KPROCESSOR_STATE  ProcesserState; // _KPROCESSOR_STATE  ProcesserState; // Size; // 0x320

	ULONG KernelReserved[16]; // [16] 0
	ULONG HalReserved[16]; // [16] 0xb2a700
	ULONG CFlushSize; // 0x40
	UCHAR CoresPerPhysicalProcessor; // 0x2 ''
	UCHAR LogicalProcessorsPerCore; // 0x1 ''
	UCHAR PrcbPad0[2]; // [2]  ""
	ULONG MHz; // Uint4B
	UCHAR CpuVendor; // UChar
	UCHAR GroupIndex; // UChar
	USHORT Group; // Uint2B
	ULONG GroupSetMember; // Uint4B
	ULONG Number; // Uint4B
	UCHAR PrcbPad1[72]; // [72] UChar
	LARGE_INTEGER LockQueue[17]; // [17] _KSPIN_LOCK_QUEUE
	PVOID NpxThread; // Ptr32 _KTHREAD
	ULONG InterruptCount; // Uint4B
	ULONG KernelTime; // Uint4B
	ULONG UserTime; // Uint4B
	ULONG DpcTime; // Uint4B
	ULONG DpcTimeCount; // Uint4B
	ULONG InterruptTime; // Uint4B
	ULONG AdjustDpcThreshold; // Uint4B
	ULONG PageColor; // Uint4B
	UCHAR DebuggerSavedIRQL; // UChar
	UCHAR NodeColor; // UChar
	UCHAR PrcbPad20[2]; // [2] UChar
	ULONG NodeShiftedColor; // Uint4B
	PVOID ParentNode; // Ptr32 _KNODE
	ULONG SecondaryColorMask; // Uint4B
	ULONG DpcTimeLimit; // Uint4B
	ULONG PrcbPad21[2]; // [2] Uint4B
	ULONG CcFastReadNoWait; // Uint4B
	ULONG CcFastReadWait; // Uint4B
	ULONG CcFastReadNotPossible; // Uint4B
	ULONG CcCopyReadNoWait; // Uint4B
	ULONG CcCopyReadWait; // Uint4B
	ULONG CcCopyReadNoWaitMiss; // Uint4B
	ULONG MmSpinLockOrdering; // Int4B
	ULONG IoReadOperationCount; // Int4B
	ULONG IoWriteOperationCount; // Int4B
	ULONG IoOtherOperationCount; // Int4B
	LARGE_INTEGER IoReadTransferCount; // _LARGE_INTEGER
	LARGE_INTEGER IoWriteTransferCount; // _LARGE_INTEGER
	LARGE_INTEGER IoOtherTransferCount; // _LARGE_INTEGER
	ULONG CcFastMdlReadNoWait; // Uint4B
	ULONG CcFastMdlReadWait; // Uint4B
	ULONG CcFastMdlReadNotPossible; // Uint4B
	ULONG CcMapDataNoWait; // Uint4B
	ULONG CcMapDataWait; // Uint4B
	ULONG CcPinMappedDataCount; // Uint4B
	ULONG CcPinReadNoWait; // Uint4B
	ULONG CcPinReadWait; // Uint4B
	ULONG CcMdlReadNoWait; // Uint4B
	ULONG CcMdlReadWait; // Uint4B
	ULONG CcLazyWriteHotSpots; // Uint4B
	ULONG CcLazyWriteIos; // Uint4B
	ULONG CcLazyWritePages; // Uint4B
	ULONG CcDataFlushes; // Uint4B
	ULONG CcDataPages; // Uint4B
	ULONG CcLostDelayedWrites; // Uint4B
	ULONG CcFastReadResourceMiss; // Uint4B
	ULONG CcCopyReadWaitMiss; // Uint4B
	ULONG CcFastMdlReadResourceMiss; // Uint4B
	ULONG CcMapDataNoWaitMiss; // Uint4B
	ULONG CcMapDataWaitMiss; // Uint4B
	ULONG CcPinReadNoWaitMiss; // Uint4B
	ULONG CcPinReadWaitMiss; // Uint4B
	ULONG CcMdlReadNoWaitMiss; // Uint4B
	ULONG CcMdlReadWaitMiss; // Uint4B
	ULONG CcReadAheadIos; // Uint4B
	ULONG KeAlignmentFixupCount; // Uint4B
	ULONG KeExceptionDispatchCount; // Uint4B
	ULONG KeSystemCalls; // Uint4B
	ULONG AvailableTime; // Uint4B
	ULONG PrcbPad22[2]; // [2] Uint4B
	ULONG LookasideLists[1184]; // size : 0x1280  = 4736	ULONG[1184]
								/*
								+0x5a0 PPLookasideList; // [16] _PP_LOOKASIDE_LIST
								+0x620 PPNPagedLookasideList; // [32] _GENERAL_LOOKASIDE_POOL
								+0xf20 PPPagedLookasideList; // [32] _GENERAL_LOOKASIDE_POOL
								*/
	ULONG PacketBarrier; // Uint4B
	LONG ReverseStall; // Int4B
	PVOID IpiFrame; // Ptr32 Void
	UCHAR PrcbPad3[52]; // [52] UChar
	PVOID CurrentPacket[3]; // [3] Ptr32 Void
	ULONG TargetSet; // Uint4B
	PVOID WorkerRoutine; // Ptr32     void 
	ULONG IpiFrozen; // Uint4B
	UCHAR PrcbPad4[40]; // [40] UChar
	ULONG RequestSummary; // Uint4B
	struct _KPRCB *SignalDone; // Ptr32 _KPRCB
	UCHAR PrcbPad50[56]; // [56] UChar
	UCHAR DpcData[40]; // +0x18e0 DpcData; // [2] _KDPC_DATA	size : 0x28 =40 
	PVOID DpcStack; // Ptr32 Void
	ULONG MaximumDpcQueueDepth; // Int4B
	ULONG DpcRequestRate; // Uint4B
	ULONG MinimumDpcRate; // Uint4B
	ULONG DpcLastCount; // Uint4B
	ULONG PrcbLock; // Uint4B
	UCHAR DpcGate[16]; // +0x1920 DpcGate; // _KGATE
	UCHAR ThreadDpcEnable; // UChar
	UCHAR QuantumEnd; // UChar
	UCHAR DpcRoutineActive; // UChar
	UCHAR IdleSchedule; // UChar
	union {
		ULONG DpcRequestSummary; // Int4B
		USHORT DpcRequestSlot[2]; // [2] Int2B
		struct {
			USHORT NormalDpcState; // Int2B
			union {
				USHORT DpcThreadActive : 1; // Pos 0, 1 Bit
				USHORT ThreadDpcState; // 첫 번째 비트 제거 후 사용.
			};
		};
	};
	ULONG TimerHand; // Uint4B
	ULONG LastTick; // Uint4B
	LONG MasterOffset; // Int4B
	ULONG PrcbPad41[2]; // [2] Uint4B
	ULONG PeriodicCount; // Uint4B
	ULONG PeriodicBias[2]; // Uint4B	단순한 4바이트 필든데.... 사이즈가 8이네... 정렬 걸렸나? 배열2개로 해놓자...
	LARGE_INTEGER TickOffset; // Uint8B	
	UCHAR TimerTable[6208]; // +0x1960 TimerTable; // _KTIMER_TABLE		size : 0x1840	=6208
	UCHAR CallDpc[32]; // +0x31a0 CallDpc; // _KDPC		size : 0x20   =32
	ULONG ClockKeepAlive; // Int4B
	UCHAR ClockCheckSlot; // UChar
	UCHAR ClockPollCycle; // UChar
	UCHAR PrcbPad6[2]; // [2] UChar
	ULONG DpcWatchdogPeriod; // Int4B
	ULONG DpcWatchdogCount; // Int4B
	LONG ThreadWatchdogPeriod; // Int4B
	LONG ThreadWatchdogCount; // Int4B
	LONG KeSpinLockOrdering; // Int4B
	ULONG PrcbPad70[1]; // [1] Uint4B
	LIST_ENTRY WaitListHead; // _LIST_ENTRY
	ULONG WaitLock; // Uint4B
	ULONG ReadySummary; // Uint4B
	ULONG QueueIndex; // Uint4B
	SINGLE_LIST_ENTRY DeferredReadyListHead; // _SINGLE_LIST_ENTRY
	LARGE_INTEGER StartCycles; // Uint8B
	LARGE_INTEGER CycleTime; // Uint8B
	ULONG HighCycleTime; // Uint4B
	ULONG PrcbPad71; // Uint4B
	LARGE_INTEGER PrcbPad72[2]; // [2] Uint8B
	LIST_ENTRY DispatcherReadyListHead[32]; // [32] _LIST_ENTRY
	PVOID ChainedInterruptList; // Ptr32 Void
	ULONG LookasideIrpFloat; // Int4B
	ULONG MmPageFaultCount; // Int4B
	ULONG MmCopyOnWriteCount; // Int4B
	LONG MmTransitionCount; // Int4B
	LONG MmCacheTransitionCount; // Int4B
	LONG MmDemandZeroCount; // Int4B
	LONG MmPageReadCount; // Int4B
	LONG MmPageReadIoCount; // Int4B
	LONG MmCacheReadCount; // Int4B
	LONG  MmCacheIoCount; // Int4B
	LONG  MmDirtyPagesWriteCount; // Int4B
	LONG  MmDirtyWriteIoCount; // Int4B
	LONG MmMappedPagesWriteCount; // Int4B
	LONG MmMappedWriteIoCount; // Int4B
	ULONG CachedCommit; // Uint4B
	ULONG CachedResidentAvailable; // Uint4B
	PVOID  HyperPte; // Ptr32 Void
	UCHAR PrcbPad8[4]; // [4] UChar
	UCHAR VendorString[13]; // [13] UChar
	UCHAR InitialApicId; // UChar
	UCHAR LogicalProcessorsPerPhysicalProcessor; // UChar
	UCHAR PrcbPad9[5]; // [5] UChar
	ULONG FeatureBits[2]; // Uint4B		; // 요거도 ULONG 인데 사이즈는 8
	LARGE_INTEGER UpdateSignature; // _LARGE_INTEGER
	LARGE_INTEGER IsrTime; // Uint8B
	LARGE_INTEGER RuntimeAccumulation; // Uint8B
	UCHAR PowerState[200]; //	+0x33a0 PowerState; // _PROCESSOR_POWER_STATE	; // SIZE : 0xC8	=200
	UCHAR DpcWatchdogDpc[32]; // +0x3468 DpcWatchdogDpc; // _KDPC	size : 0x20
	UCHAR DpcWatchdogTimer[40]; // +0x3488 DpcWatchdogTimer; // _KTIMER	size :0x28	=40
	PVOID WheaInfo; // Ptr32 Void
	PVOID EtwSupport; // Ptr32 Void
	LARGE_INTEGER InterruptObjectPool; // _SLIST_HEADER
	LARGE_INTEGER HypercallPageList; // _SLIST_HEADER
	PVOID HypercallPageVirtual; // Ptr32 Void
	PVOID VirtualApicAssist; // Ptr32 Void
	PLARGE_INTEGER StatisticsPage; // Ptr32 Uint8B
	PVOID RateControl; // Ptr32 Void
	UCHAR Cache[60]; // +0x34d8 Cache; // [5] _CACHE_DESCRIPTOR			; // Size : 0x3c =60
	ULONG CacheCount; // Uint4B
	ULONG CacheProcessorMask[5]; // [5] Uint4B
	UCHAR PackageProcessorSet[12]; // +0x352c PackageProcessorSet; // _KAFFINITY_EX		Size = 0xC  =12
	ULONG PrcbPad91[1]; // [1] Uint4B
	ULONG CoreProcessorSet; // Uint4B
	UCHAR TimerExpirationDpc[32]; // +0x3540 TimerExpirationDpc; // _KDPC		Size : 0x20	=32
	ULONG SpinLockAcquireCount; // Uint4B
	ULONG SpinLockContentionCount; // Uint4B
	ULONG SpinLockSpinCount; // Uint4B
	ULONG IpiSendRequestBroadcastCount; // Uint4B
	ULONG IpiSendRequestRoutineCount; // Uint4B
	ULONG IpiSendSoftwareInterruptCount; // Uint4B
	ULONG ExInitializeResourceCount; // Uint4B
	ULONG ExReInitializeResourceCount; // Uint4B
	ULONG ExDeleteResourceCount; // Uint4B
	ULONG ExecutiveResourceAcquiresCount; // Uint4B
	ULONG ExecutiveResourceContentionsCount; // Uint4B
	ULONG ExecutiveResourceReleaseExclusiveCount; // Uint4B
	ULONG ExecutiveResourceReleaseSharedCount; // Uint4B
	ULONG ExecutiveResourceConvertsCount; // Uint4B
	ULONG ExAcqResExclusiveAttempts; // Uint4B
	ULONG ExAcqResExclusiveAcquiresExclusive; // Uint4B
	ULONG ExAcqResExclusiveAcquiresExclusiveRecursive; // Uint4B
	ULONG ExAcqResExclusiveWaits; // Uint4B
	ULONG ExAcqResExclusiveNotAcquires; // Uint4B
	ULONG ExAcqResSharedAttempts; // Uint4B
	ULONG ExAcqResSharedAcquiresExclusive; // Uint4B
	ULONG ExAcqResSharedAcquiresShared; // Uint4B
	ULONG ExAcqResSharedAcquiresSharedRecursive; // Uint4B
	ULONG ExAcqResSharedWaits; // Uint4B
	ULONG ExAcqResSharedNotAcquires; // Uint4B
	ULONG ExAcqResSharedStarveExclusiveAttempts; // Uint4B
	ULONG ExAcqResSharedStarveExclusiveAcquiresExclusive; // Uint4B
	ULONG ExAcqResSharedStarveExclusiveAcquiresShared; // Uint4B
	ULONG ExAcqResSharedStarveExclusiveAcquiresSharedRecursive; // Uint4B
	ULONG ExAcqResSharedStarveExclusiveWaits; // Uint4B
	ULONG ExAcqResSharedStarveExclusiveNotAcquires; // Uint4B
	ULONG ExAcqResSharedWaitForExclusiveAttempts; // Uint4B
	ULONG ExAcqResSharedWaitForExclusiveAcquiresExclusive; // Uint4B
	ULONG ExAcqResSharedWaitForExclusiveAcquiresShared; // Uint4B
	ULONG UExAcqResSharedWaitForExclusiveAcquiresSharedRecursive; // Uint4B
	ULONG ExAcqResSharedWaitForExclusiveWaits; // Uint4B
	ULONG ExAcqResSharedWaitForExclusiveNotAcquires; // Uint4B
	ULONG ExSetResOwnerPointerExclusive; // Uint4B
	ULONG ExSetResOwnerPointerSharedNew; // Uint4B
	ULONG ExSetResOwnerPointerSharedOld; // Uint4B
	ULONG ExTryToAcqExclusiveAttempts; // Uint4B
	ULONG ExTryToAcqExclusiveAcquires; // Uint4B
	ULONG ExBoostExclusiveOwner; // Uint4B
	ULONG ExBoostSharedOwners; // Uint4B
	ULONG ExEtwSynchTrackingNotificationsCount; // Uint4B
	ULONG ExEtwSynchTrackingNotificationsAccountedCount; // Uint4B
	PVOID Context; // Ptr32 _CONTEXT
	ULONG ContextFlags; // Uint4B
	PVOID ExtendedState; // Ptr32 _XSAVE_AREA
} KPRCB, *PKPRCB;

//typedef struct _NT_TIB {
//	PVOID ExceptionList;   //Ptr32 _EXCEPTION_REGISTRATION_RECORD
//	PVOID StackBase;   //Ptr32 Void
//	PVOID StackLimit;   //Ptr32 Void
//	PVOID SubSystemTib;   //Ptr32 Void
//	union {
//		PVOID FiberData;   //Ptr32 Void
//		ULONG Version;   //Uint4B
//	};
//	PVOID ArbitraryUserPointer;   //Ptr32 Void
//	struct _NT_TIB *Self;   //Ptr32 _NT_TIB
//} NT_TIB, *PNT_TIB;

typedef struct _SIN_KPCR {
	union {
		NT_TIB NtTib;
		struct {
			PVOID Used_ExceptionList;  //    Ptr32 _EXCEPTION_REGISTRATION_RECORD
		PVOID Used_StackBase;  //    Ptr32 Void
		PVOID Spare2;  //    Ptr32 Void
		PVOID TssCopy;  //    Ptr32 Void
		ULONG ContextSwitches;  //    Uint4B
		ULONG SetMemberCopy;  //    Uint4B
		PVOID Used_Self;  //    Ptr32 Void
		};
	};
	struct _KPCR *SelfPcr;  //    Ptr32 _KPCR
	PKPRCB Prcb;  //Ptr32 _KPRCB
	UCHAR Irql[4];  //UChar인데, 4바이트 정렬됨.
	ULONG IRR;  // Uint4B
	ULONG  IrrActive;  //    Uint4B
	ULONG IDR;  // Uint4B
	PVOID KdVersionBlock;  //    Ptr32 Void
	PVOID IDT;  // Ptr32 _KIDTENTRY
	PVOID GDT;  // Ptr32 _KGDTENTRY
	PVOID TSS;  // Ptr32 _KTSS
	USHORT MajorVersion;  //    Uint2B
	USHORT MinorVersion;  //    Uint2B
	ULONG SetMember;  //    Uint4B
	ULONG StallScaleFactor;  //    Uint4B
	UCHAR SpareUnused;  //    UChar
	UCHAR Number;  //    UChar
	UCHAR Spare0;  //    UChar
	UCHAR SecondLevelCacheAssociativity;  //    UChar
	ULONG VdmAlert;  //    Uint4B
	ULONG KernelReserved[14];  //    [14] Uint4B
	ULONG SecondLevelCacheSize;  //    Uint4B
	ULONG HalReserved[16];  //    [16] Uint4B
	ULONG InterruptMode;  //    Uint4B
	UCHAR Spare1[4];  //    UChar형인데, 4바이트 정렬됨.
	ULONG KernelReserved2[17];  //    [17] Uint4B
	KPRCB PrcbData;  //    _KPRCB
} SIN_KPCR, *PSIN_KPCR;
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////			MMWSL			/////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _MMWSLE {
	union {
		PVOID VirtualAddress;   // PVoid
		LONG Long;
		struct _MMWSLENTRY{
			ULONG Valid : 1;
			ULONG Spare : 1;
			ULONG Hashed : 1;
			ULONG Direct : 1;
			ULONG Protection : 5;
			ULONG Age : 3;
			ULONG VirtualPageNumber : 20;
		}e1;
		struct _MMWSLE_FREE_ENTRY {
			ULONG MustBeZero : 1;
			ULONG PreviousFree : 11;
			ULONG NextFree : 20;
		}e2;
	}u1;
} MMWSLE, *PMMWSLE;

typedef struct _MMWSLE_NONDIRECT_HASH {
	PVOID Key;             // Ptr32 Void
	ULONG Index;            //  Uint4B
} MMWSLE_NONDIRECT_HASH, *PMMWSLE_NONDIRECT_HASH;

typedef struct _MMWSLE_HASH {
	ULONG Index; //Uint4B
}MMWSLE_HASH, *PMMWSLE_HASH;

typedef struct _MMWSL {
	ULONG FirstFree;  //Uint4B
	ULONG  FirstDynamic;  //Uint4B
	ULONG LastEntry;  //Uint4B
	ULONG  NextSlot;  //Uint4B
	PMMWSLE	Wsle;  //Ptr32 _MMWSLE
	PVOID LowestPagableAddress;  //Ptr32 Void
	ULONG  LastInitializedWsle;  //Uint4B
	ULONG  NextAgingSlot;  //Uint4B
	ULONG  NumberOfCommittedPageTables;  //Uint4B
	ULONG VadBitMapHint;  //Uint4B
	ULONG  NonDirectCount;  //Uint4B
	ULONG  LastVadBit;  //Uint4B
	ULONG  MaximumLastVadBit;  //Uint4B
	ULONG  LastAllocationSizeHint;  //Uint4B
	ULONG LastAllocationSize;  //Uint4B
	PMMWSLE_NONDIRECT_HASH NonDirectHash;  //Ptr32 _MMWSLE_NONDIRECT_HASH
	PMMWSLE_HASH HashTableStart;  //Ptr32 _MMWSLE_HASH
	PMMWSLE_HASH HighestPermittedHashAddress;  //Ptr32 _MMWSLE_HASH
	USHORT UsedPageTableEntries[1536];  //[1536] Uint2B
	ULONG CommittedPageTables[48];  //[48] Uint4B
} MMWSL, *PMMWSL;

typedef struct _MMSUPPORT {
	ULONG WorkingSetMutex; // _EX_PUSH_LOCK
	PVOID ExitGate; // Ptr32 _KGATE
	PVOID AccessLog; // Ptr32 Void
	LIST_ENTRY WorkingSetExpansionLinks; // _LIST_ENTRY
	ULONG AgeDistribution[7]; // [7] Uint4B
	ULONG MinimumWorkingSetSize; // Uint4B
	ULONG WorkingSetSize; // Uint4B
	ULONG  WorkingSetPrivateSize; // Uint4B
	ULONG  MaximumWorkingSetSize; // Uint4B
	ULONG  ChargedWslePages; // Uint4B
	ULONG  ActualWslePages; // Uint4B
	ULONG  WorkingSetSizeOverhead; // Uint4B
	ULONG  PeakWorkingSetSize; // Uint4B
	ULONG  HardFaultCount; // Uint4B
	PMMWSL VmWorkingSetList; // Ptr32 _MMWSL
	USHORT NextPageColor; // Uint2B
	USHORT LastTrimStamp; // Uint2B
	ULONG  PageFaultCount; // Uint4B
	ULONG  RepurposeCount; // Uint4B
	ULONG Spare[1]; // [1] Uint4B
	struct _MMSUPPORT_FLAGS {
		ULONG WorkingSetType : 3;
		ULONG ModwriterAttached : 1;
		ULONG TrimHard : 1;
		ULONG MaximumWorkingSetHard5 : 1;
		ULONG ForceTrim : 1;
		ULONG MinimumWorkingSetHard7 : 1;
		ULONG SessionMaster : 1;
		ULONG TrimmerState : 2;
		ULONG Reserved : 1;
		ULONG PageStealers : 4;
		ULONG MemoryPriority : 8;
		ULONG WsleDeleted : 1;
		ULONG VmExiting : 1;
		ULONG ExpansionFailed : 1;
		ULONG Available : 5;
	} Flags;
}MMSUPPORT, *PMMSUPPORT;
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////// 이 두 개는 VAD 에 대한 구조체가 아니고, VAL_TABLE의 구조체.	(최상위 루트만 이 구조체 적용)
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 사이즈 체크 완료.
typedef struct _MMADDRESS_NODE {
	union {
		ULONG Balance : 2;
		struct _MMADDRESS_NODE *Parent;	// 2비트 제거 후 사용.
	};
	struct _MMADDRESS_NODE *LeftChild;
	struct _MMADDRESS_NODE *RightChild;
	ULONG StartingVpn;
	ULONG EndingVpn;
} MMADDRESS_NODE, *PMMADDRESS_NODE;

// 사이즈 체크 완료.
typedef struct _MM_AVL_TABLE {	
	MMADDRESS_NODE BalancedRoot;
	//ULONG Flags;	// DepthOfTree : 5, Unused : 3, NumberGenericTableElements : 24
	struct {
		ULONG DepthOfTree : 5;
		ULONG  Unused : 3;
		ULONG NumberGenericTableElements : 24;
	};
	PVOID NodeHint;
	PVOID NodeFreeHint;
	//USHORT Commit;
	//UCHAR Flag1;
	//UCHAR Flag2;			// 최상위 루트를 제외하고는 이런 패턴인듯.		-> 최상위 루트도 DepthOfTree가 MAX Depth값인건 아니군....
	//PVOID NodeHint;
	//PVOID NodeFreeHint;
} MM_AVL_TABLE, *PMM_AVL_TABLE;
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 사이즈 체크 완료.
typedef struct _MMEXTEND_INFO {
	LARGE_INTEGER CommittedSize;
	ULONG ReferenceCount;
} MMEXTEND_INFO, *PMMEXTEND_INFO;

// 사이즈 체크 완료.
typedef struct _MMPTE {
	union {
		LARGE_INTEGER Long;
		LARGE_INTEGER VolatileLong;
		struct _MMPTE_HIGHLOW {
			ULONG LowPart;
			ULONG HighPart;
		} HighLow;
		struct _HARDWARE_PTE {
			union {
				struct {
					ULONG Valid : 1;
					ULONG Write : 1;
					ULONG Owner : 1;
					ULONG WriteThrough : 1;
					ULONG CacheDisable : 1;
					ULONG Accessed : 1;
					ULONG Dirty : 1;
					ULONG LargePage : 1;
					ULONG Global : 1;
					ULONG CopyOnWrite : 1;
					ULONG Prototype : 1;
					ULONG reserved0 : 1;
					ULONG PageFrameNumber : 26;
					ULONG reserved1 : 26;
				};
				struct {
					ULONG LowPart;
					ULONG HighPart;
				};
			};
		} Flush;
		struct _MMPTE_HARDWARE {
			ULONG Valid : 1;
			ULONG Dirty1 : 1;
			ULONG Owner : 1;
			ULONG WriteThrough : 1;
			ULONG CacheDisable : 1;
			ULONG Accessed : 1;
			ULONG Dirty : 1;
			ULONG LargePage : 1;
			ULONG Global : 1;
			ULONG CopyOnWrite : 1;
			ULONG Unused : 1;
			ULONG Write : 1;
			ULONG PageFrameNumber : 26;
			ULONG reserved1 : 26;
		} Hard;
		struct _MMPTE_PROTOTYPE {
			ULONG Valid : 1;
			ULONG Unused0 : 7;
			ULONG ReadOnly : 1;
			ULONG Unused1 : 1;
			ULONG Prototype : 1;
			ULONG Protection : 5;
			ULONG Unused : 16;
			ULONG ProtoAddress : 32;
		} Proto;
		struct _MMPTE_SOFTWARE {
			ULONG Valid : 1;
			ULONG PageFileLow : 4;
			ULONG Protection : 5;
			ULONG Prototype : 1;
			ULONG Transition : 1;
			ULONG InStore : 1;
			ULONG Unused1 : 19;
			ULONG PageFileHigh : 32;
		} Soft;
		struct _MMPTE_TIMESTAMP {
			ULONG MustBeZero : 1;
			ULONG PageFileLow : 4;
			ULONG Protection : 5;
			ULONG Prototype : 1;
			ULONG Transition : 1;
			ULONG Unused : 20;
			ULONG GlobalTimeStamp : 32;
		} TimeStamp;
		struct _MMPTE_TRANSITION {
			ULONG Valid : 1;
			ULONG Write : 1;
			ULONG Owner : 1;
			ULONG WriteThrough : 1;
			ULONG CacheDisable : 1;
			ULONG Protection : 5;
			ULONG Prototype : 1;
			ULONG Transition : 1;
			ULONG PageFrameNumber : 26;
			ULONG Unused : 26;
		} Trans;
		struct _MMPTE_SUBSECTION {
			ULONG Valid : 1;
			ULONG Unused0 : 4;
			ULONG Protection : 5;
			ULONG Prototype : 1;
			ULONG Unused1 : 21;
			ULONG SubsectionAddress : 32;
		} Subsect;
		struct _MMPTE_LIST {
			ULONG Valid : 1;
			ULONG OneEntry : 1;
			ULONG filler0 : 8;
			ULONG Prototype : 1;
			ULONG filler1 : 21;
			ULONG NextEntry : 32;
		} List;
	};
} MMPTE, *PMMPTE;

// 사이즈 체크 완료.
typedef struct _SEGMENT {
	struct _CONTROL_AREA *ControlArea;		// PCONTROL_AREA 
	ULONG TotalNumberOfPtes;
	union {
		ULONG LongFlags;	
		struct _SEGMENT_FLAGS {
			ULONG TotalNumberOfPtes4132 : 10;
			ULONG ExtraSharedWowSubsections : 1;
			ULONG LargePages : 1;
			ULONG WatchProto : 1;
			ULONG DebugSymbolsLoaded : 1;
			ULONG WriteCombined : 1;
			ULONG NoCache : 1;
			ULONG FloppyMedia : 1;
			ULONG DefaultProtectionMask : 5;
			ULONG Binary32 : 1;
			ULONG ContainsDebug : 1;
			ULONG Spare : 8;
		} SegmentFlags;
	}; 
	ULONG NumberOfCommittedPages;
	LARGE_INTEGER SizeOfSegment;
	union {
		PMMEXTEND_INFO pExtendInfo;  
		PVOID pBasedAddress;  // Ptr32 Void
	};
	ULONG SegmentLock;  // _EX_PUSH_LOCK
	union {
		ULONG ImageCommitment;
		PVOID CreatingProcess;		// PEPROCESS
	};
	union {
		PVOID ImageInformation;		 // Ptr32 _MI_SECTION_IMAGE_INFORMATION
		PVOID FirstMappedVa;
	};
	PMMPTE PrototypePte;
	MMPTE ThePtes[1];
} SEGMENT, *PSEGMENT;

// 사이즈 체크 완료.
typedef struct _CONTROL_AREA {
	PSEGMENT pSegment;
	LIST_ENTRY DereferenceList;
	ULONG NumberOfSectionReferences;
	ULONG NumberOfPfnReferences;
	ULONG NumberOfMappedViews;
	ULONG NumberOfUserReferences;
	union {
		ULONG LongFlags;
		struct _MMSECTION_FLAGS{
			ULONG BeingDeleted : 1;
			ULONG BeingCreated : 1;
			ULONG BeingPurged : 1;
			ULONG NoModifiedWriting : 1;
			ULONG FailAllIo : 1;
			ULONG Image : 1;
			ULONG Based : 1;
			ULONG File : 1;
			ULONG Networked : 1;
			ULONG Rom : 1;
			ULONG PhysicalMemory : 1;
			ULONG CopyOnWrite : 1;
			ULONG Reserve : 1;
			ULONG Commit : 1;
			ULONG Accessed : 1;
			ULONG WasPurged : 1;
			ULONG UserReference : 1;
			ULONG GlobalMemory : 1;
			ULONG DeleteOnClose : 1;
			ULONG FilePointerNull : 1;
			ULONG GlobalOnlyPerSession : 1;
			ULONG SetMappedFileIoComplete : 1;
			ULONG CollidedFlush : 1;
			ULONG NoChange : 1;
			ULONG Spare : 1;
			ULONG UserWritable : 1;
			ULONG PreferredNode : 6;
		};
	};
	ULONG FlushInProgressCount;
	union _EX_FAST_REF {
			ULONG RefCnt : 3;
			PVOID Object;	// 3비트 제거 후 사용.
			ULONG Value;
	} FilePointer;
	ULONG ControlAreaLock;
	union {
		ULONG ModifiedWriteCount;
		ULONG StartingFrame;
	};
	PVOID pWaitingForDeletion;  //  Ptr32 _MI_SECTION_CREATION_GATE
	struct {
		union {
			ULONG NumberOfSystemCacheViews;
			ULONG ImageRelocationStartBit;
		};
		union {
			ULONG WritableUserReferences;
			struct {
				ULONG ImageRelocationSizeIn64k : 16;
				ULONG Unused : 14;
				ULONG BitMap64 : 1;
				ULONG ImageActive : 1;
			};
			
		};
		union {
			PVOID SubsectionRoot;		//_MM_SUBSECTION_AVL_TABLE
			PVOID SeImageStub;			// _MI_IMAGE_SECURITY_REFERENCE
		};	
	};
	ULONG LockedPages;
	LIST_ENTRY ViewList;
} CONTROL_AREA, *PCONTROL_AREA;

// 사이즈 체크 완료.
typedef struct _MMSUBSECTION_NODE {
	union {
		ULONG LongFlags;
		struct _MMSUBSECTION_FLAGS {
			USHORT SubsectionAccessed : 1;
			USHORT Protection : 5;
			USHORT StartingSector4132 : 10;
			USHORT  SubsectionStatic : 1;
			USHORT  GlobalMemory : 1;
			USHORT  DirtyPages : 1;
			USHORT  Spare : 1;
			USHORT  SectorEndOffset : 12;
		} SubsectionFlags;
	};
	ULONG StartingSector;
	ULONG NumberOfFullSectors;
	union {
		ULONG Balance : 2;
		struct _MMSUBSECTION_NODE *Parent;		// 2비트 제거 후 사용.
	};
	struct _MMSUBSECTION_NODE *LeftChild;
	struct _MMSUBSECTION_NODE *RightChild;
} MMSUBSECTION_NODE, *PMMSUBSECTION_NODE;

// 사이즈 체크 완료.
typedef struct _SUBSECTION {
	struct _CONTROL_AREA *pControlArea;		// PCONTROL_AREA 
	PMMPTE pSubsectionBase;
	struct _SUBSECTION *pNextSubsection;
	ULONG PtesInSubsection;
	union {
		ULONG UnusedPtes;
		PMM_AVL_TABLE pGlobalPerSessionHead;
	};
	union {
		ULONG LongFlags;
		struct _MMSUBSECTION_FLAGS SubsectionFlags;
	};
	ULONG StartingSector;
	ULONG NumberOfFullSectors;
	union {
		ULONG Balance : 2;
		PMMSUBSECTION_NODE Parent;	// 2비트 제거 후 사용.
	};
	PMMSUBSECTION_NODE LeftChild;
	PMMSUBSECTION_NODE RightChild;
	LIST_ENTRY DereferenceList;
	ULONG NumberOfMappedViews;
} SUBSECTION, *PSUBSECTION;

// 사이즈 체크 완료.
typedef struct _MSUBSECTION {
	struct _CONTROL_AREA *pControlArea;		// PCONTROL_AREA
	PMMPTE pSubsectionBase;
	union {
		PSUBSECTION pNextSubsection;
		struct _MSUBSECTION *pNextMappedSubsection;
	};
	ULONG PtesInSubsection;
	union {
		ULONG  UnusedPtes;
		PMM_AVL_TABLE pGlobalPerSessionHead;
	};
	union {
		ULONG LongFlags;
		struct _MMSUBSECTION_FLAGS SubsectionFlags;
	};
	ULONG StartingSector;
	ULONG NumberOfFullSectors;
	union {
		ULONG Balance : 2;	
		PMMSUBSECTION_NODE Parent;	// 2비트 제거 후 사용.
	};
	PMMSUBSECTION_NODE LeftChild;
	PMMSUBSECTION_NODE RightChild;
	LIST_ENTRY DereferenceList;
	ULONG NumberOfMappedViews;
} MSUBSECTION, *PMSUBSECTION;

// 사이즈 체크 완료.
typedef struct _MMVAD {
	union {
		ULONG Balance : 2;
		struct _MMVAD *Parent;	// 2비트 제거 후 사용.
	};					
	struct _MMVAD *LeftChild;
	struct _MMVAD *RightChild;
	ULONG StartingVpn;
	ULONG EndingVpn;
	union {
		ULONG LongFlags;
		struct _MMVAD_FLAGS {
			ULONG CommitCharge : 19;
			ULONG NoChange : 1;
			ULONG VadType : 3;
			ULONG MemCommit : 1;
			ULONG Protection : 5;
			ULONG Spare : 2;
			ULONG PrivateMemory : 1;
		} VadFlags;
	};
	ULONG PushLock;					//_EX_PUSH_LOCK
	union {
		ULONG LongFlags3;
		struct _MMVAD_FLAGS3 {
			ULONG PreferredNode : 6;
			ULONG Teb : 1;
			ULONG Spare : 1;
			ULONG SequentialAccess : 1;
			ULONG LastSequentialTrim : 15;
			ULONG Spare2 : 8;
		} VadFlags3;
	};
	union {
		ULONG LongFlags2;
		struct _MMVAD_FLAGS2 {
			ULONG FileOffset : 24;
			ULONG SecNoChange : 1;
			ULONG OneSecured : 1;
			ULONG MultipleSecured : 1;
			ULONG Spare3 : 1;
			ULONG LongVad : 1;
			ULONG ExtendableFile : 1;
			ULONG Inherit : 1;
			ULONG CopyOnWrite : 1;
		} VadFlags2;
	};
	union {
		PSUBSECTION pSubsection;
		PMSUBSECTION pMappedSubsection;
	};
	PMMPTE pFirstPrototypePte;
	PMMPTE pLastContiguousPte;
	LIST_ENTRY ViewLinks;
	PVOID pVadsProcess;			// PEPROCESS	
} MMVAD, *PMMVAD;


#pragma pack()
