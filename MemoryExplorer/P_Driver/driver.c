/*
	Copy in 2017/11/08 for GITHUB
		When I am making WorkingSetListMaker()

*/


#include "ntddk.h"
#include "..\Headers\driver.h"

WCHAR nameBuffer[] = L"\\Device\\MemoryExplorer";
WCHAR linkBuffer[] = L"\\DosDevices\\MemoryExplorer";
PDEVICE_OBJECT pMyDevice = NULL;


/////////////////////////////////////		MESSAGE_TYPE		////////////////////////////////////////
#define MESSAGE_TYPE_FAILED					(ULONG)0
#define MESSAGE_TYPE_PROCESS_INFO			(ULONG)1
#define MESSAGE_TYPE_VAD					(ULONG)2
#define MESSAGE_TYPE_THREADS				(ULONG)3
#define MESSAGE_TYPE_SECURITY				(ULONG)4
#define	MESSAGE_TYPE_HANDLES				(ULONG)5
#define MESSAGE_TYPE_FINDER_UNICODE			(ULONG)6
#define MESSAGE_TYPE_WORKINGSET_SUMMARY		(ULONG)7
#define MESSAGE_TYPE_WORKINGSET_LIST		(ULONG)8
////////////////////////////////////////////////////////////////////////////////////////////////////////

#define VA_FOR_PAGE_DIRECTORY_TABLE			(ULONG)0xC0600000				// PAE에서는 이 주소임. [기본 : 0xC0300000]
#define VA_FOR_PAGE_TABLE					(ULONG)0xC0000000


#pragma pack(1)
typedef struct _TARGET_OBJECT {
	ULONG ProcessId;
	ULONG pEprocess;
	ULONG pVadRoot;
	UCHAR ImageFileName[15];
}TARGET_OBJECT, *PTARGET_OBJECT;

typedef struct _SNIFF_OBJECT {
	ULONG backedEthread;
	ULONG backedEprocess;
	//ULONG backedVadRoot;
	ULONG backedCR3;
	ULONG backedHyperPte;
}SNIFF_OBJECT, *PSNIFF_OBJECT;

typedef struct _DEVICE_EXTENSION{
	LIST_ENTRY PendingIrpQueue;
	KSPIN_LOCK PendingIrpLock;
	KEVENT WaitingIRPEvent;
	BOOLEAN isWaitingIRP;
	LIST_ENTRY MessageQueue;
	KSPIN_LOCK MessageLock;	
	PETHREAD CommunicationThread;
	KSEMAPHORE CommunicationSemapohore;
	BOOLEAN bTerminateThread;
	PTARGET_OBJECT pTargetObject;
	PSNIFF_OBJECT pSniffObject;
}DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _MESSAGE_LIST {
	LIST_ENTRY ListEntry;
	MESSAGE_ENTRY Message;
}MESSAGE_LIST, *PMESSAGE_LIST;
#pragma pack()

//__declspec(dllimport) ULONG MiSystemVaType;		// 해당 값도 익스포트하지 않음.
//__declspec(dllimport)	ULONG MmPfnDatabase;
// __declspec(dllimport) ULONG ObTypeIndexTable;	 // 해당 값은 익스포트하지 않는다.
PVOID NTAPI ObGetObjectType(PVOID pObject);


NTSTATUS ManipulateAddressTables() {
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PDEVICE_EXTENSION pExtension = pMyDevice->DeviceExtension;
	ULONG backedCR3 = 0;
	//ULONG backedVadRoot = 0;
	ULONG backedEprocess = 0;
	ULONG backedEthread = 0;

	// 그냥 제거하고 새로 생성하자.
	if (pExtension->pSniffObject) {
		DbgPrintEx(101, 0, "[ERROR] Already the SNIFF_OBJECT exists...\n");
		DbgPrintEx(101, 0, "    -> Remove it...\n");
		ExFreePool(pExtension->pSniffObject);
		pExtension->pSniffObject = NULL;
		//return ntStatus;
	}

	pExtension->pSniffObject = ExAllocatePool(NonPagedPool, sizeof(SNIFF_OBJECT));
	if (pExtension->pSniffObject == NULL) {
		DbgPrintEx(101, 0, "[ERROR] Failed to create the SNIFF_OBJECT...\n");
		return ntStatus;
	}
	RtlZeroMemory(pExtension->pSniffObject, sizeof(SNIFF_OBJECT));

	__try {
		__asm {
			push eax;

			// Backup the current ETHREAD.
			mov eax, fs:0x124;
			mov backedEthread, eax;

			// Backup the current thread's KPROCESS.
			add eax, KTHREAD_OFFSET_KPROCESS;
			mov eax, [eax];
			mov backedEprocess, eax;

			// Backup the current process' VADRoot.
			/*add eax, EPROC_OFFSET_VadRoot;
			mov eax, [eax];
			mov backedVadRoot, eax;*/

			// Backup the register CR3.
			mov eax, cr3;
			mov backedCR3, eax;
			//			mov originalCR3, cr3	// -> 바로 넣으면 빌드할 때 에러뜸.

			pop eax;
		}

		// 중간에 해당 프로세스가 종료되는 것을 방지하기 위해 레퍼런스 하나 증가시키자.
		//	-> 실패 시, 해당 프로세스가 종료된 것으로 간주. 실패 처리.
		ntStatus = ObReferenceObjectByPointer((PVOID)backedEprocess, GENERIC_ALL, NULL, KernelMode);
		if (!NT_SUCCESS(ntStatus)) {
			ExFreePool(pExtension->pSniffObject);
			DbgPrintEx(101, 0, "[ERROR] Failed to increase the current Process' reference count.\n");
			DbgPrintEx(101, 0, "    -> Maybe the process terminated... Try again..\n");
			return ntStatus;
		}

		//pExtension->pSniffObject->backedVadRoot = backedVadRoot;
		pExtension->pSniffObject->backedEprocess = backedEprocess;
		pExtension->pSniffObject->backedCR3 = backedCR3;
		pExtension->pSniffObject->backedEthread = backedEthread;

		/////////////////////////////////////////////////// 이거 왜 backedVadRoot를 그대로 넣었지????
		// 현재 프로세스의 VADRoot 변경.
		//	*(PULONG)((pExtension->pSniffObject->backedEprocess) + EPROC_OFFSET_VadRoot) = pExtension->pTargetObject->pVadRoot;

		// 현재 스레드의 KPROCESS 변경.
		*(PULONG)((pExtension->pSniffObject->backedEthread) + KTHREAD_OFFSET_KPROCESS) = pExtension->pTargetObject->pEprocess;

		//// CR3 레지스터 변경.
		//	-> 이거 EPROC_OFFSET_PageDirectoryPte가 아니다!! 주의하자
		backedCR3 = *(PULONG)((pExtension->pTargetObject->pEprocess) + KPROC_OFFSET_DirectoryTableBase);
		__asm {
			push eax;

			// Manipulate the register CR3.
			mov eax, backedCR3;
			mov cr3, eax;

			// mov eax, [Output]		 -> 요게 문제였다. 변수에는 포인터 연산자 안통함.
			//	mov cr3, eax

			pop eax;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Failed to backup & change the registers...\n");

		ExFreePool(pExtension->pSniffObject);
		pExtension->pSniffObject = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(101, 0, "   ::: Current Process's EPROCESS : 0x%08X\n", pExtension->pSniffObject->backedEprocess);
	DbgPrintEx(101, 0, "       -> Changed EPROCESS : 0x%08X\n", pExtension->pTargetObject->pEprocess);
	DbgPrintEx(101, 0, "   ::: Current CR3 : 0x%08X\n", pExtension->pSniffObject->backedCR3);
	DbgPrintEx(101, 0, "       -> Changed CR3 : 0x%08X\n", backedCR3);


	return STATUS_SUCCESS;
}


VOID RestoreAddressTables() {
	PDEVICE_EXTENSION pExtension = pMyDevice->DeviceExtension;
	ULONG backedEthread = 0;
	ULONG backedCR3 = 0;
	ULONG backedEprocess = 0;
	BOOLEAN isRestored = FALSE;

	if ((pExtension != NULL) && (pExtension->pSniffObject != NULL)) {
		backedEprocess = pExtension->pSniffObject->backedEprocess;
		backedEthread = pExtension->pSniffObject->backedEthread;
		backedCR3 = pExtension->pSniffObject->backedCR3;

		__try {
			// 백업된 프로세스의 VADRoot 복구
			//*(PULONG)(backedEprocess + EPROC_OFFSET_VadRoot) = pExtension->pSniffObject->backedVadRoot;

			// 백업된 KTHREAD의 KPROCESS 복구
			*(PULONG)(backedEthread + KTHREAD_OFFSET_KPROCESS) = backedEprocess;

			// CR3 복구.
			// 단, 현재의 스레드가 백업 당시의 프로세스와 동일한 경우에만....
			__asm {
				push eax;
				push ebx;

				// Check the current thread.
				mov eax, fs:0x124;
				mov ebx, backedEthread;
				cmp eax, ebx;
				jne PASS;

				// Restore CR3
				mov eax, backedCR3;
				mov cr3, eax;
				mov isRestored, 1;

			PASS:
				pop ebx;
				pop eax;
			}

			// 현재 프로세스가 변경되어서, CR3를 복구하지 않은 경우에는 
			// EPROCESS를 통해 PDT 를 변경시키자. 필요없을 듯도 하지만 혹시모르니...
			//	이거 바꿔줘서 괜히 BSOD 뜨는거 같기도 한데.. 
			//	일단 지움...    -> 비교나 해볼까????
			if (!isRestored) {
				// 이거 EPROC_OFFSET_PageDirectoryPte가 아니다!! 주의하자
				//	*(PULONG)(backedEprocess + KPROC_OFFSET_DirectoryTableBase) = backedCR3;
				DbgPrintEx(101, 0, "    -> CR3 is not restored, Because the current process is switched...\n");
				DbgPrintEx(101, 0, "        -> Backed Process's PDT : 0x%08X\n", *(PULONG)(backedEprocess + KPROC_OFFSET_DirectoryTableBase));
				DbgPrintEx(101, 0, "        -> Backed CR3           : 0x%08X\n", backedCR3);
			}

			DbgPrintEx(101, 0, "    -> Succeeded to restore the Tables...\n");
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] Failed to restore the backed values...\n");
		}

		// 프로세스 종료 방지를 위해 증가시켰던, Reference count 감소시키자.
		ObDereferenceObject(backedEprocess);

		ExFreePool(pExtension->pSniffObject);
		pExtension->pSniffObject = NULL;
		return;
	}

}



VOID ListCleaner(PLIST_ENTRY pListEntry, PKSPIN_LOCK pLock) {
	KIRQL oldIrql;
	PVOID currentEntry = NULL;
	ULONG count = 0;

	if ((pListEntry == NULL) || (pLock == NULL)) {
		DbgPrintEx(101, 0, "[ERROR] Invalied parameters In ListCleaner().\n");
		return;
	}
	else if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		DbgPrintEx(101, 0, "[ERROR] Current IRQL is above PASSIVE_LEVEL.\n");
		return;
	}
	else
		DbgPrintEx(101, 0, "::: ListCleaner() is called...\n");

	KeAcquireSpinLock(pLock, &oldIrql);
	while (!IsListEmpty(pListEntry)) {
		currentEntry = RemoveHeadList(pListEntry);
		if (currentEntry) {
			ExFreePool(currentEntry);
			currentEntry = NULL;
			count++;
		}
	}
	KeReleaseSpinLock(pLock, oldIrql);
	DbgPrintEx(101, 0, "    -> %u entries are removed...\n", count);
	return;
}

VOID OnUnload(PDRIVER_OBJECT pDriverObject) {
	UNICODE_STRING linkName;
	PDEVICE_EXTENSION pExtension = NULL;
	KIRQL oldIrql;
	PVOID pTmp = NULL;

	pExtension = pDriverObject->DeviceObject->DeviceExtension;
	if ((pExtension->CommunicationThread) && !(pExtension->bTerminateThread)) {
		if (pExtension->isWaitingIRP) {
			pExtension->isWaitingIRP = FALSE;
			KeSetEvent(&(pExtension->WaitingIRPEvent), 0, FALSE);
		}

		pExtension->bTerminateThread = TRUE;
		KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
		KeWaitForSingleObject(pExtension->CommunicationThread, Executive, KernelMode, FALSE, NULL);
	
		ObDereferenceObject(pExtension->CommunicationThread);
	}
	

	KeAcquireSpinLock(&(pExtension->PendingIrpLock), &oldIrql);
	if (!IsListEmpty(&(pExtension->PendingIrpQueue))) {
		pTmp = RemoveHeadList(&(pExtension->PendingIrpQueue));
		pTmp = CONTAINING_RECORD(pTmp, IRP, Tail.Overlay, ListEntry);
		((PIRP)pTmp)->IoStatus.Status = STATUS_CANCELLED;
		((PIRP)pTmp)->IoStatus.Information = 0;
		KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);
		IoCompleteRequest(pTmp, IO_NO_INCREMENT);
		pTmp = NULL;
	}
	else
		KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);
	
	ListCleaner(&(pExtension->MessageQueue), &(pExtension->MessageLock));

	if (pExtension->pTargetObject) {
		ExFreePool(pExtension->pTargetObject);
		pExtension->pTargetObject = NULL;
	}

	RtlInitUnicodeString(&linkName, linkBuffer);
	IoDeleteSymbolicLink(&linkName);
	IoDeleteDevice(pMyDevice);
	
	
	DbgPrintEx(101, 0, "Driver unloaded...\n");
}



NTSTATUS DispatchRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

//NTSTATUS RetrieveData(ULONG Pid, ULONG VirtualAddress, PULONG Output) {
//	PEPROCESS pFirstProcess = NULL;
//	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
//	PEPROCESS pCurrentProcess = NULL;	
//	ULONG changed = 0;
//	
//	pFirstProcess = IoGetCurrentProcess();
//	if (pFirstProcess == NULL) {
//		DbgPrintEx(101, 0, "[ERROR] Failed to get the first process...\n");
//		return ntStatus;
//	}
//	//DbgPrintEx(101, 0, "   ::: the First Process [%d]: 0x%08X\n", *(PULONG)(((ULONG)pFirstProcess) + EPROC_OFFSET_UniqueProcessId) , (ULONG)pFirstProcess);
//	//DbgPrintEx(101, 0, "           -> Next List Entry : 0x%08X\n",(*(PULONG)(((ULONG)pFirstProcess) + EPROC_OFFSET_ActiveProcessLinks)));
//	//return STATUS_SUCCESS;
//
//	// Find Target Process
//	pCurrentProcess = pFirstProcess;
//	do {
//		if (*(PULONG)(((ULONG)pCurrentProcess) + EPROC_OFFSET_UniqueProcessId) == Pid)
//			break;
//		else {
//			pCurrentProcess = (PEPROCESS)((*(PULONG)(((ULONG)pCurrentProcess) + EPROC_OFFSET_ActiveProcessLinks)) - EPROC_OFFSET_ActiveProcessLinks);
//		}
//	} while (pCurrentProcess != pFirstProcess);
//
//	if (pCurrentProcess == pFirstProcess) {
//		DbgPrintEx(101, 0, "[ERROR] Target PID is not exist...\n");
//		return ntStatus;
//	}
//	else {
//		DbgPrintEx(101, 0, "   ::: Taregt Process : 0x%08X\n", (ULONG)pCurrentProcess);
//		*Output = *(PULONG)(((ULONG)pCurrentProcess) + KPROC_OFFSET_DirectoryTableBase);
//
//		// Get my CR3's value
//		__asm {
//			push eax;
//
//			// CR3 레지스터 백업
//			mov eax, cr3;
//			mov originalCR3, eax;
//			//			mov originalCR3, cr3	// -> 바로 넣으면 빌드할 때 에러뜸.
//
//			// CR3 레지스터 변경	[타겟 프로세스의 PDT 주소를, 임시로 Output 변수에 저장한다.]
//			// mov eax, [Output]		 -> 요게 문제였다. 변수에는 포인터 연산자 안통함.
//			//	mov cr3, eax
//			mov eax, Output;
//			mov eax, [eax];
//			mov cr3, eax;
//
//			// 변경 제대로 됐는지 확인.
//			mov eax, cr3;
//			mov changed, eax;
//
//
//			pop eax;
//		}
//
//		DbgPrintEx(101, 0, "   ::: Target Process's Directory table base : 0x%08X\n", *Output);
//		DbgPrintEx(101, 0, "   ::: My Process's Directory table base : 0x%08X\n", *(PULONG)(((ULONG)pFirstProcess) + KPROC_OFFSET_DirectoryTableBase));
//		DbgPrintEx(101, 0, "   ::: My CR3's Value : 0x%08X\n", originalCR3);
//		DbgPrintEx(101, 0, "   ::: Corrupted CR3 : 0x%08X\n", changed);
//
//		// 가상 주소의 데이터 뽑아올 때, 해당 프로세스 내에서 할당되지 않은 주소일 수 있으니, 예외처리 하자.
//		__try {
//			*Output = *(PULONG)VirtualAddress;
//			DbgPrintEx(101, 0, "::: Target process's data at 0x%08X : 0x%08X\n", VirtualAddress, *Output);
//			ntStatus = STATUS_SUCCESS;
//		}
//		__except (EXCEPTION_EXECUTE_HANDLER) {
//			ntStatus = STATUS_UNSUCCESSFUL;
//			DbgPrintEx(101, 0, "::::: Address 0x%08X in target process is  not allocated...\n", VirtualAddress);
//		}
//
//		__asm {
//			push eax;
//
//			// 복구
//			mov eax, originalCR3;
//			mov cr3, eax;
//
//			mov eax, cr3;
//			mov changed, eax;
//
//			pop eax;
//		}
//
//		DbgPrintEx(101, 0, "   ::: Restored CR3 : 0x%08X\n", changed);
//
//		return ntStatus;
//	}
//
//}

VOID MyCancelRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	PKSPIN_LOCK pLock = NULL;
	KIRQL oldIrql;

	IoReleaseCancelSpinLock(pIrp->CancelIrql);

	pLock = &(((PDEVICE_EXTENSION)(pDeviceObject->DeviceExtension))->PendingIrpLock);
	KeAcquireSpinLock(pLock, &oldIrql);
	RemoveEntryList(&(pIrp->Tail.Overlay.ListEntry));
	KeReleaseSpinLock(pLock, oldIrql);

	pIrp->IoStatus.Status = STATUS_CANCELLED;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return;
}

NTSTATUS ProcessInfoMaker(PTARGET_OBJECT pTargetObject, PPROCESS_INFO pProcessInfo) {
	PUNICODE_STRING pImageFullName = NULL;
//	ULONG currentEthread = 0;
	
	__try {
		pProcessInfo->Eprocess = pTargetObject->pEprocess;
		pProcessInfo->VadRoot = pTargetObject->pVadRoot;
		pProcessInfo->DirectoryTableBase = *(PULONG)((pTargetObject->pEprocess) + KPROC_OFFSET_DirectoryTableBase);
		pProcessInfo->HandleTable = *(PULONG)((pTargetObject->pEprocess) + EPROC_OFFSET_ObjectTable);
		pProcessInfo->ProcessId = pTargetObject->ProcessId;
		pProcessInfo->ThreadListHead = (pTargetObject->pEprocess) + EPROC_OFFSET_ThreadListHead;

		pImageFullName = (PUNICODE_STRING)(*(PULONG)((pTargetObject->pEprocess) + EPROC_OFFSET_SeAuditProcessCreationInfo));
		if ((pImageFullName != NULL) && (pImageFullName->Length > 0)) {
			RtlCopyMemory(pProcessInfo->ImageFullName, pImageFullName->Buffer, pImageFullName->Length);
		}

	/*	__asm {
			push eax;

			mov eax, fs:0x124;
			mov currentEthread, eax;

			pop eax;
		}
		if (currentEthread != 0) {
			DbgPrintEx(101, 0, "%s's CACHEMANAGERACTIVE : 0x%02X\n",
				(PUCHAR)((*(PULONG)(currentEthread + KTHREAD_OFFSET_KPROCESS)) + EPROC_OFFSET_ImageFileName), *(PUCHAR)(currentEthread + ETHREAD_OFFSET_CacheManagerActive));

		}*/
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Failed to make a PROCESS_INFO.\n");
		return STATUS_UNSUCCESSFUL;	
	}
}

//// 커널 스택이 부족할 수 있으니, pMyDevice 변수를 이용하자.
//// 좌중우로 탐색한다.
//			-> 아마도 recursion 횟수가 증가함에 따라 커널 스택이 부족해져서 BSOD 발생하는 듯.
//					-> KeExpandKernelStackAndCallout() 해도 마찬가지...................
//	[해결] 이거 문제가 KeInitailizeSemaphore()에서 Limit 값을 너무 작게줘서 예외 발생했던 것.
//			-> 이게.... VadMapMakre()가 도는 동안, IRP를 받지를 못해, 작업자 스레드가 계속 멈춰있다.
//				-> 따라서 Semaphore 카운트는 계속 쌓아기만 하고 한계치 도달함.
//EXPAND_STACK_CALLOUT VadMapMaker;
//VOID VadMapMaker(PVAD_PARAMS Params) {
//	PMESSAGE_LIST pMessageList = NULL;
//	PVAD_MAP pVadMap = NULL;
//	VAD_PARAMS newParams;
//	ULONG tmp = 0;
//	
//	newParams.Level = (Params->Level) + 1;
//	if ((Params->VadRoot->LeftChild) != NULL) {
//		newParams.VadRoot = Params->VadRoot->LeftChild;
//		KeExpandKernelStackAndCallout(VadMapMaker, &newParams, 60);
//		//VadMapMaker(&newParams);
//	}
//		
//	pMessageList = ExAllocatePool(NonPagedPool, sizeof(MESSAGE_LIST));
//	if (pMessageList == NULL)
//		return;
//
//	RtlZeroMemory(pMessageList, sizeof(MESSAGE_LIST));
//	pVadMap = pMessageList->Message.Buffer;
//	pVadMap->Vad = (ULONG)(Params->VadRoot);
//	pVadMap->Start = (ULONG)(Params->VadRoot->StartingVpn);
//	pVadMap->End = (ULONG)(Params->VadRoot->EndingVpn);
//	pVadMap->isShared = ((((PMM_AVL_TABLE)Params->VadRoot)->Flag2) & 0x80) ? TRUE : FALSE;
//
//	//if(Level == 0)
//	//	pVadMap->Level = (UCHAR)((((PMM_AVL_TABLE)VadRoot)->Flags) & 0x1F);		// 5bit		// MAX Depth가 아니였다....
//
//	pVadMap->Commit = ((PMM_AVL_TABLE)Params->VadRoot)->Commit;	
//	pVadMap->Level = Params->Level;
//
//	pMessageList->Message.MessageType = MESSAGE_TYPE_VAD;
//	ExInterlockedInsertTailList(&(((PDEVICE_EXTENSION)(pMyDevice->DeviceExtension))->MessageQueue), &(pMessageList->ListEntry), &(((PDEVICE_EXTENSION)(pMyDevice->DeviceExtension))->MessageLock));
//RETRY_RELEASE_SEM:
//	__try {
//		tmp = KeReleaseSemaphore(&(((PDEVICE_EXTENSION)(pMyDevice->DeviceExtension))->CommunicationSemapohore), 0, 1, FALSE);
//	}
//	__except (EXCEPTION_EXECUTE_HANDLER) {
//		if (GetExceptionCode() == STATUS_SEMAPHORE_LIMIT_EXCEEDED) {
//			DbgPrintEx(101, 0, "[ERROR] The Semaphore limit exceeded...\n");
//			DbgPrintEx(101, 0, "    -> Waiting...\n");
//		
//			KeStallExecutionProcessor(1000000);
//			goto RETRY_RELEASE_SEM;
//		/*	__try {
//				KeReleaseSemaphore(&(((PDEVICE_EXTENSION)(pMyDevice->DeviceExtension))->CommunicationSemapohore), 0, 1, FALSE);
//			}
//			__except (EXCEPTION_EXECUTE_HANDLER) {
//				DbgPrintEx(101, 0, "[ERROR] Semaphore limit exceeded Again.\n");
//				DbgPrintEx(101, 0, "    -> Quit this execution.\n");
//				return;
//			}*/
//		}
//	}
//	DbgPrintEx(101, 0, "Append VAD Entry[%d], SEM : %u \n", Params->Level, tmp);
//	DbgPrintEx(101, 0, "    -> VAD Root : 0x%08X\n", pVadMap->Vad);
//
//	if ((Params->VadRoot->RightChild) != NULL) {
//		newParams.VadRoot = Params->VadRoot->RightChild;
//		KeExpandKernelStackAndCallout(VadMapMaker, &newParams, 60);
////		VadMapMaker(&newParams);
//	}
//
//}

BOOLEAN VadEntryMaker(PMMADDRESS_NODE pNode, ULONG Level, PDEVICE_EXTENSION pExtension) {
	PMESSAGE_LIST pMessageList = NULL;
	PVAD_MAP pVadMap = NULL;


	pMessageList = ExAllocatePool(NonPagedPool, sizeof(MESSAGE_LIST));
	if (pMessageList == NULL) {
		DbgPrintEx(101, 0, "[ERROR] Failed to allocate pool for message of VAD Entry.\n");
		return FALSE;
	}
	RtlZeroMemory(pMessageList, sizeof(MESSAGE_LIST));

	pVadMap = pMessageList->Message.Buffer;
	pVadMap->Vad = (ULONG)(pNode);
	pVadMap->Level = Level;
	pVadMap->Start = (ULONG)(pNode->StartingVpn);
	pVadMap->End = (ULONG)(pNode->EndingVpn);
	pVadMap->isPrivate = ((PMMVAD)pNode)->VadFlags.PrivateMemory;
	pVadMap->Commit = ((PMMVAD)pNode)->VadFlags.CommitCharge;
	

	__try {
		if (!(((PMMVAD)pNode)->VadFlags.PrivateMemory) && (((PMMVAD)pNode)->pSubsection) && (((PMMVAD)pNode)->pSubsection->pControlArea)) {
			if (((PMMVAD)pNode)->pSubsection->pControlArea->File) {
				// MessageType 변수 재활용.
				pMessageList->Message.MessageType = ((ULONG)(((PMMVAD)pNode)->pSubsection->pControlArea->FilePointer.Object) & 0xFFFFFFF8);
				RtlCopyMemory(pVadMap->FileName, (((PFILE_OBJECT)(pMessageList->Message.MessageType))->FileName.Buffer), (((PFILE_OBJECT)(pMessageList->Message.MessageType))->FileName.Length));
			}
			else {
				RtlCopyMemory(pVadMap->FileName, L"Pagefile-backed section", 48);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Failedto get the file name.\n");
		// 파일 네임 못 읽어도 그냥 성공 처리.
	}

	pMessageList->Message.MessageType = MESSAGE_TYPE_VAD;
	
	__try{
		
		ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessageList->ListEntry), &(pExtension->MessageLock));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Queuing to MessageQueue is failed...\n");
		ExFreePool(pMessageList);
		return FALSE;
	}
	
	__try {
		KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {		// 이상하게 이 핸들러가 작동을 안하네.... 그냥 멈춘다. 데드락??
		if (GetExceptionCode() == STATUS_SEMAPHORE_LIMIT_EXCEEDED) {
			DbgPrintEx(101, 0, "[ERROR] Semaphore limit exceeded...\n");
		}
		return FALSE;
	}
	
	return TRUE;

}


// Recursion이 아닌 그냥 반복문으로 탐색.
NTSTATUS VadMapMaker(PDEVICE_EXTENSION pExtension, PVAD_MAP pResultMessage) {
	NTSTATUS ntStatus;
	LONG level = -1;
	PMMADDRESS_NODE pCurrentNode = NULL;
	BOOLEAN isBackward = FALSE;
	PMMADDRESS_NODE pParentNode = NULL;
	ULONG vadCount = 0;

	pCurrentNode = pExtension->pTargetObject->pVadRoot;
	while(TRUE){
		if (isBackward) {
			isBackward = FALSE;

			// 분기점 찾기.
			while (TRUE) {
				pParentNode = (PMMADDRESS_NODE)(((ULONG)(pCurrentNode->Parent)) & 0xFFFFFFFC);
				
				// 탐색 종료.
				if (pParentNode == pExtension->pTargetObject->pVadRoot) {
					pResultMessage->Commit = vadCount;
					pResultMessage->isPrivate = TRUE;
					return STATUS_SUCCESS;
				}

				if (pParentNode->LeftChild == pCurrentNode) {
					pCurrentNode = pParentNode;
					level--;
					break;
				}
				else if (pParentNode->RightChild == pCurrentNode) {
					pCurrentNode = pParentNode;
					level--;
				}
			}
			
			// 엔트리 등록.
			if (level >= 0) {
				if (VadEntryMaker(pCurrentNode, level, pExtension)) {
					vadCount++;
				}
				else
					return STATUS_UNSUCCESSFUL;

			}
			
			if (pCurrentNode->RightChild) {
				pCurrentNode = pCurrentNode->RightChild;
				level++;
			}
			else {
				isBackward = TRUE;
			}
		}
		else {
			if (pCurrentNode->LeftChild) {
				pCurrentNode = pCurrentNode->LeftChild;
				level++;
			}
			else {
				// 엔트리 등록.
				if (level >= 0) {
					if (VadEntryMaker(pCurrentNode, level, pExtension)) {
						vadCount++;
					}
					else
						return STATUS_UNSUCCESSFUL;

				}
				
				if (pCurrentNode->RightChild) {
					pCurrentNode = pCurrentNode->RightChild;
					level++;
				}
				else {
					isBackward = TRUE;
				}
			}
		}
	}
}


// 핸들 테이블이 한 단계라고 가정했을 때의 코드.
//NTSTATUS HandleTableMaker(PDEVICE_EXTENSION pExtension) {
//	ULONG currentEntry = 0;
//	ULONG handleCount = 0;
//	ULONG currentHandleNumber = 0;
//	PMESSAGE_LIST pMessage = NULL;
//	PHANDLE_ENTRY pHandleEntry = NULL;
//	ULONG HandleTable = 0;
//	PUNICODE_STRING pName = NULL;
//	PVOID pObjectType = NULL;
//	BOOLEAN isOnlyUnamed = FALSE;
//	UCHAR level = 0;
//
//	if (!(pExtension->pTargetObject) || !(pExtension->pTargetObject->pEprocess)) {
//		DbgPrintEx(101, 0, "[ERROR] Target Object is not set.\n");
//		return STATUS_UNSUCCESSFUL;
//	}
//
//	HandleTable = *(PULONG)((ULONG)(pExtension->pTargetObject->pEprocess) + EPROC_OFFSET_ObjectTable);
//
//	if((HandleTable >= 0x80000000) && (HandleTable < 0xFFFFF000) && (*(PULONG)(HandleTable) != 0) && (*(PULONG)(HandleTable + 0x30) != 0)){
//		currentEntry = *(PULONG)HandleTable;
//		handleCount = *(PULONG)(HandleTable + 0x30);
//
//		while (handleCount > 0) {
//			pMessage = ExAllocatePool(NonPagedPool, sizeof(MESSAGE_LIST));
//			if (pMessage == NULL) {
//				DbgPrintEx(101, 0, "[ERROR] Failed to allocate pool in HandleTableMaker()\n");
//				return STATUS_UNSUCCESSFUL;
//			}
//			RtlZeroMemory(pMessage, sizeof(MESSAGE_LIST));
//			pHandleEntry = pMessage->Message.Buffer;
//
//		
//			pHandleEntry->HandleNumber = currentHandleNumber;
//			pHandleEntry->EntryAddress = currentEntry;
//
//			__try {
//				if (currentHandleNumber == 0) {
//					pHandleEntry->GrantedAccess = *(PULONG)(HandleTable + 0x24);		//0x24 : Flags
//					pHandleEntry->Type = handleCount;
//				}
//				else {
//						// Close 된 핸들인 경우, 해당 엔트리는 그대로 위치를 차지하고 있는 상태가 된다. 
//						//	-> 대신 Object Header Pointer가 0으로......
//						//	-> HandleCount는 해당 엔트리를 제외한 채 카운트 된다.
//					if (*(PULONG)currentEntry == 0)
//					{
//						pHandleEntry->FileObject = 0xFFFFFFFFF;
//					}
//					else {
//						pHandleEntry->GrantedAccess = *(PULONG)(currentEntry + 4);
//						//(pHandleEntry->FileObject) &= 0xFFFFFFF8;
//						pHandleEntry->FileObject = ((*(PULONG)currentEntry) & 0xFFFFFFF8) + 0x18;		// HandleTable에는 Object Header 포인터가 저장됨.
//						pHandleEntry->Type = *(PULONG)((pHandleEntry->FileObject) - 0xC);		// - 0x18 + 0xC
//					
//						/*		1바이트씩...
//						+0x00c TypeIndex        : UChar
//						+ 0x00d TraceFlags : UChar
//						+ 0x00e InfoMask : UChar
//						+ 0x00f Flags : UChar
//						*/
//						pObjectType = (PVOID)ObGetObjectType(pHandleEntry->FileObject);
//						if ((pObjectType != NULL)){
//							//DbgPrintEx(101, 0, "Object Type : %ws[0x%08X]\n", ((PUNICODE_STRING)(((ULONG)pObjectType) + OBJECT_TYPE_OFFSET_Name))->Buffer, (ULONG)pObjectType);
//							//DbgPrintEx(101, 0, "    -> Query Name Proc : 0x%08X\n", *(PULONG)(((ULONG)pObjectType) + OBJECT_TYPE_OFFSET_TypeInfo + OBJECT_TYPE_INITIALIZER_OFFSET_QueryNameProcedure));
//							isOnlyUnamed = (((*(PUCHAR)(((ULONG)pObjectType) + OBJECT_TYPE_OFFSET_TypeInfo + 2)) & 0x1) == 0x1) ? TRUE : FALSE;
//							if (isOnlyUnamed)
//								DbgPrintEx(101, 0, "    -> Object Type : 0x%02X   -> Only Unnamed...\n", (UCHAR)(0xFF & (pHandleEntry->Type)));
//							else
//								DbgPrintEx(101, 0, "    -> Object Type : 0x%02X   -> Naming Available...\n", (UCHAR)(0xFF & (pHandleEntry->Type)));
//
//							pObjectType = NULL;
//						}
//							
//						switch (*(PUCHAR)(((pHandleEntry->FileObject)) - 0xC)) {
//						//case 2:  break;    // Type
//						//case 3:  break;    // Directory
//						//case 4:  break;    // SymbolicLink
//						//case 5:  break;    // Token
//						//case 6:  break;    // Job
//						//case 7:  break;    // Process
//						//case 8:  break;    // Thread
//						//case 9:  break;    // UserApcReserve
//						//case 10:  break;    // IoCompletionReserve
//						//case 11:  break;    // DebugObject
//						//case 12:  break;    // Event
//						//case 13:  break;    // EventPair
//						//case 14:  break;    // Mutant
//						//case 15:  break;    // Callback
//						//case 16:  break;    // Semaphore
//						//case 17:  break;    // Timer
//						//case 18:  break;    // Profile
//						//case 19:  break;    // KeyedEvent
//						//case 20:  break;    // WindowStation
//						//case 21:  break;    // Desktop
//						//case 22:  break;    // TpWorkerFactory
//						//case 23:  break;    // Adapter
//						//case 24:  break;    // Controller
//						//case 25:  break;    // Device
//						//case 26:  break;    // Driver
//						//case 27:  break;    // IoCompletion
//							case 28: 
//								pName = (PUNICODE_STRING)((pHandleEntry->FileObject) + 0x30);
//								break;    // File
//						//case 29:  break;    // TmTm
//						//case 30:  break;    // TmTx
//						//case 31:  break;    // TmRm
//						//case 32:  break;    // TmEn
//						//case 33:  break;    // Section
//						//case 34:  break;    // Session
//						//case 35:  break;    // Key
//						//case 36:  break;    // ALPC Port
//						//case 37:  break;    // PowerRequest
//						//case 38:  break;    // WmiGuid
//						//case 39:  break;    // EtwRegistration
//						//case 40:  break;    // EtwConsumer
//						//case 41:  break;    // FilterConnectionPort
//						//case 42:  break;    // FilterCommunicationPort
//						//case 43:  break;    // PcwObject
//						default:
//						pName = NULL;
//						break;
//						}
//
//						if ((pName != NULL) && (pName->Length > 0) && (pName->Buffer != NULL)) {
//							RtlCopyMemory(pHandleEntry->Name, pName->Buffer, pName->Length);
//						}
//						// 0x030 UNICODE_STRING
//						//		-> 핸들 테이블에 있는게 모두 FILE_OBJECT 인게 아니고, Type에 따라 다 다르다....
//						//if(((((PUNICODE_STRING)((pHandleEntry->FileObject) + 0x30))->Length) > 0) && ((((PUNICODE_STRING)((pHandleEntry->FileObject) + 0x30))->Buffer) != NULL))
//						//	RtlCopyMemory(pHandleEntry->Name, ((PUNICODE_STRING)((pHandleEntry->FileObject) + 0x30))->Buffer, ((PUNICODE_STRING)((pHandleEntry->FileObject) + 0x30))->Length);
//						handleCount--;
//					}
//				}
//				currentHandleNumber += 4;
//				currentEntry += 8;
//			}
//			__except(EXCEPTION_EXECUTE_HANDLER) {
//				DbgPrintEx(101, 0, "[ERROR] Invalid pointer In HandleTableMaker()\n");
//				DbgPrintEx(101, 0, "    -> Current Entry : %u.   0x%08X\n", currentHandleNumber, currentEntry);
//				ExFreePool(pMessage);
//				return STATUS_UNSUCCESSFUL;
//			}
//
//			pMessage->Message.MessageType = MESSAGE_TYPE_HANDLES;
//
//			__try {
//				ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessage->ListEntry), &(pExtension->MessageLock));
//				KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
//			}
//			__except (EXCEPTION_EXECUTE_HANDLER) {
//				DbgPrintEx(101, 0, "[ERROR] Failed to queue at HandleTableMaker()\n");
//				ExFreePool(pMessage);
//				return STATUS_UNSUCCESSFUL;
//			}
//		}
//	}
//	else {
//		DbgPrintEx(101, 0, "[ERROR] Invalid pointer to Handle Table...\n");
//		return STATUS_UNSUCCESSFUL;
//	}
//	return STATUS_SUCCESS;
//}


UCHAR HandleEntryMaker(ULONG currentHandleNumber, ULONG currentEntry, PDEVICE_EXTENSION pExtension) {
	PMESSAGE_LIST pMessage = NULL;
	PHANDLE_ENTRY pHandleEntry = NULL;
	PUNICODE_STRING pName = NULL;
	PVOID pObjectType = NULL;
	BOOLEAN isOnlyUnamed = FALSE;
	UCHAR result = 0;

	
	pMessage = ExAllocatePool(NonPagedPool, sizeof(MESSAGE_LIST));
	if (pMessage == NULL) {
		DbgPrintEx(101, 0, "[ERROR] Failed to allocate pool in HandleTableMaker()\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(pMessage, sizeof(MESSAGE_LIST));
	pHandleEntry = pMessage->Message.Buffer;

	pHandleEntry->HandleNumber = currentHandleNumber;
	pHandleEntry->EntryAddress = currentEntry;

	__try {
			// Close 된 핸들인 경우, 해당 엔트리는 그대로 위치를 차지하고 있는 상태가 된다. 
			//	-> 대신 Object Header Pointer가 0으로......
			//	-> HandleCount는 해당 엔트리를 제외한 채 카운트 된다.
			if (*(PULONG)currentEntry == 0)
			{
				pHandleEntry->FileObject = 0xFFFFFFFFF;
			}
			else {
				pHandleEntry->GrantedAccess = *(PULONG)(currentEntry + 4);
				pHandleEntry->FileObject = ((*(PULONG)currentEntry) & 0xFFFFFFF8) + 0x18;		// HandleTable에는 Object Header 포인터가 저장됨.
				pHandleEntry->Type = *(PULONG)((pHandleEntry->FileObject) - 0xC);		// - 0x18 + 0xC

				/*		1바이트씩...
				+0x00c TypeIndex        : UChar
				+ 0x00d TraceFlags : UChar
				+ 0x00e InfoMask : UChar
				+ 0x00f Flags : UChar
				*/
				//pObjectType = (PVOID)ObGetObjectType(pHandleEntry->FileObject);
				//if ((pObjectType != NULL)) {
				//	//DbgPrintEx(101, 0, "Object Type : %ws[0x%08X]\n", ((PUNICODE_STRING)(((ULONG)pObjectType) + OBJECT_TYPE_OFFSET_Name))->Buffer, (ULONG)pObjectType);
				//	//DbgPrintEx(101, 0, "    -> Query Name Proc : 0x%08X\n", *(PULONG)(((ULONG)pObjectType) + OBJECT_TYPE_OFFSET_TypeInfo + OBJECT_TYPE_INITIALIZER_OFFSET_QueryNameProcedure));
				//	isOnlyUnamed = (((*(PUCHAR)(((ULONG)pObjectType) + OBJECT_TYPE_OFFSET_TypeInfo + 2)) & 0x40) == 0x1) ? TRUE : FALSE;
				//	if (isOnlyUnamed)
				//		DbgPrintEx(101, 0, "    -> Object Type : 0x%02X   -> Only Unnamed...\n", (UCHAR)(0xFF & (pHandleEntry->Type)));
				//	else
				//		DbgPrintEx(101, 0, "    -> Object Type : 0x%02X   -> Naming Available...\n", (UCHAR)(0xFF & (pHandleEntry->Type)));

				//}

				////////////////////////////////////////////////////////////////////
				////////////////////////		Naming		////////////////////////
				////////////////////////////////////////////////////////////////////
				switch (*(PUCHAR)(((pHandleEntry->FileObject)) - 0xC)) {
					//case 2:  break;    // Type
					//case 3:  break;    // Directory
					//case 4:  break;    // SymbolicLink
					//case 5:  break;    // Token
					//case 6:  break;    // Job
					//case 7:  break;    // Process
					//case 8:  break;    // Thread
					//case 9:  break;    // UserApcReserve
					//case 10:  break;    // IoCompletionReserve
					//case 11:  break;    // DebugObject
					//case 12:  break;    // Event
					//case 13:  break;    // EventPair
					//case 14:  break;    // Mutant
					//case 15:  break;    // Callback
					//case 16:  break;    // Semaphore
					//case 17:  break;    // Timer
					//case 18:  break;    // Profile
					//case 19:  break;    // KeyedEvent
					//case 20:  break;    // WindowStation
					//case 21:  break;    // Desktop
					//case 22:  break;    // TpWorkerFactory
					//case 23:  break;    // Adapter
					//case 24:  break;    // Controller
					//case 25:  break;    // Device
					//case 26:  break;    // Driver
					//case 27:  break;    // IoCompletion
				case 28:
					pName = (PUNICODE_STRING)((pHandleEntry->FileObject) + 0x30);
					break;    // File
							  //case 29:  break;    // TmTm
							  //case 30:  break;    // TmTx
							  //case 31:  break;    // TmRm
							  //case 32:  break;    // TmEn
							  //case 33:  break;    // Section
							  //case 34:  break;    // Session
							  //case 35:  break;    // Key
							  //case 36:  break;    // ALPC Port
							  //case 37:  break;    // PowerRequest
							  //case 38:  break;    // WmiGuid
							  //case 39:  break;    // EtwRegistration
							  //case 40:  break;    // EtwConsumer
							  //case 41:  break;    // FilterConnectionPort
							  //case 42:  break;    // FilterCommunicationPort
							  //case 43:  break;    // PcwObject
				default:
					pName = NULL;
					break;
				}

				if ((pName != NULL) && (pName->Length > 0) && (pName->Buffer != NULL)) {
					RtlCopyMemory(pHandleEntry->Name, pName->Buffer, pName->Length);
				}
				////////////////////////////////////////////////////////////////////
				////////////////////////////////////////////////////////////////////
				////////////////////////////////////////////////////////////////////
			
				result = 1;
			}
		
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Invalid pointer In HandleTableMaker()\n");
		DbgPrintEx(101, 0, "    -> Current Entry : %u.   0x%08X\n", currentHandleNumber, currentEntry);
		ExFreePool(pMessage);
		return 0xFF;
	}

	
	////////////////////////////////////////////////////////////////////////
	////////////////////////		Queuing			////////////////////////
	////////////////////////////////////////////////////////////////////////
	pMessage->Message.MessageType = MESSAGE_TYPE_HANDLES;

	__try {
		ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessage->ListEntry), &(pExtension->MessageLock));
		KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Failed to queue at HandleEntryMaker()\n");
		ExFreePool(pMessage);
		return 0xFF;
	}

	return result;
}

// 3단계의 핸들 테이블 적용.
NTSTATUS HandleTableMaker(PDEVICE_EXTENSION pExtension) {
	ULONG currentEntry = 0;
	ULONG handleCount = 0;
	ULONG currentHandleNumber = 0;
	ULONG HandleTable = 0;
	BOOLEAN secondTable = FALSE;
	BOOLEAN topTable = FALSE;
	USHORT secondIndex = 0;
	USHORT topIndex = 0;

	//Top
	//	Middle
	//	Sub

	if (!(pExtension->pTargetObject) || !(pExtension->pTargetObject->pEprocess)) {
		DbgPrintEx(101, 0, "[ERROR] Target Object is not set.\n");
		return STATUS_UNSUCCESSFUL;
	}

	HandleTable = *(PULONG)((ULONG)(pExtension->pTargetObject->pEprocess) + EPROC_OFFSET_ObjectTable);

	if ((HandleTable >= 0x80000000) && (HandleTable < 0xFFFFF000) && (*(PULONG)(HandleTable) != 0) && (*(PULONG)(HandleTable + 0x30) != 0)) {
		handleCount = *(PULONG)(HandleTable + 0x30);
		HandleTable = *(PULONG)HandleTable;
		secondTable = (HandleTable & 0x1) ? TRUE : FALSE;
		topTable = (HandleTable & 0x2) ? TRUE : FALSE;
		
		HandleTable = HandleTable & 0xFFFFFFFC;		// HandleTable 값은 _HANDLE_TABLE 구조체의 TableCode 필드에서 플래그 뺀 값.
		currentEntry = HandleTable;
		if (secondTable)
			currentEntry = *(PULONG)currentEntry;
		if (topTable)
			currentEntry = *(PULONG)currentEntry;

		// Handle Number == 0은 미리 패스시켜두자.
		currentHandleNumber += 4;
		currentEntry += 8;

		while ( (currentEntry > 0x80000000) && (handleCount > 0)) {
			// 0x800 배수의 핸들은 Audit Entry 를 가리킨다.
			//		-> 그냥 카운팅만 증가.
			if ((currentHandleNumber % 0x800)) {
				switch (HandleEntryMaker(currentHandleNumber, currentEntry, pExtension))
				{
				case 0:	// Freed Entry
					break;
				case 1:	// Using Handle
					handleCount--;
					break;
				default:	// 실패
					return STATUS_UNSUCCESSFUL;
				}
			}
			// SubHandle Table 교체 후, 카운팅 증가.
			else {
				// Indexing...
				if (secondTable) {
					if ((++secondIndex) == 1024) {
						if (topTable) {
							secondIndex = 0;
							if ((++topIndex) == 1024) {
								DbgPrintEx(101, 0, "[ERROR] Top table's Index is above 1024.\n");
								return STATUS_UNSUCCESSFUL;
							}
						}
						else {
							DbgPrintEx(101, 0, "[ERROR] Second table's Index is above 1024 And There's not the top table.\n");
							return STATUS_UNSUCCESSFUL;
						}
					}
				}
				else {
					DbgPrintEx(101, 0, "[ERROR] SubHandle Table's Index is above 512.\n");
					return STATUS_UNSUCCESSFUL;
				}

				// Exchange currentEntry's Value
				if (topTable) {
					currentEntry = *(PULONG)(HandleTable + (topIndex * 4));
					if (currentEntry == 0) {
						DbgPrintEx(101, 0, "[ERROR] the top table's entry is NULL...\n");
						return STATUS_UNSUCCESSFUL;
					}
					currentEntry = *(PULONG)(currentEntry + (secondIndex * 4));
				}
				else if(secondTable) {
					currentEntry = *(PULONG)(HandleTable + (secondIndex * 4));
				}
						
				// Check
				if (currentEntry == 0) {
					DbgPrintEx(101, 0, "[ERROR] the second table's entry is NULL...\n");
					return STATUS_UNSUCCESSFUL;
				}
			}

			currentHandleNumber += 4;
			currentEntry += 8;
		}

		
	}
	else {
		DbgPrintEx(101, 0, "[ERROR] Handle Table is not exist...\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}



NTSTATUS WorkingSetListMaker(PDEVICE_EXTENSION pExtension, PMESSAGE_LIST pMessage) {
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	ULONG index = 0;
	PMMWSL pMmWsl = NULL;
	PULONG copied = NULL;
	ULONG i = 0;
	
	if (pExtension->pTargetObject == NULL) {
		DbgPrintEx(101, 0, "[ERROR] Invalid Parameters in WorkingSetListMaker()...\n");
		return ntStatus;
	}
	
	// EPROCESS에는 __MMSUPPROT 구조체는 포인터가 아닌 구조체 자체가 끼여있다.
	pMmWsl = (PMMWSL)(((PMMSUPPORT)((pExtension->pTargetObject->pEprocess) + EPROC_OFFSET_Vm))->VmWorkingSetList);
	if (((ULONG)pMmWsl) < 0xC0000000) {
		DbgPrintEx(101, 0, "[ERROR] Invalid VM field in EPROCESS...\n");
		return ntStatus;
	}
	
	//copied = ExAllocatePool(NonPagedPool, sizeof(ULONG) * 512);		// 프로세스 워킹셋은 최대 2기가로 설정.	-> 이게 아님. 주석참조.

	//if (copied == NULL) {
	//	DbgPrintEx(101, 0, "[ERROR] Failed to allocate pool for COPIED in WorkingSetListMaker()\n");
	//	return ntStatus;
	//}
	//RtlZeroMemory(copied, sizeof(ULONG) * 512);


	////////////////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////		 Dump the MMWSL Structure		////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////////////	 
	if (!NT_SUCCESS(ManipulateAddressTables())) {
		DbgPrintEx(101, 0, "[ERROR] Invalid Parameters in WorkingSetListMaker()...\n");
		//ExFreePool(copied);
		//copied = NULL;
	}
	else {
		__try {
			RtlCopyMemory((pMessage->Message.Buffer) + 4, pMmWsl, sizeof(ULONG) * 18);
			ntStatus = STATUS_SUCCESS;
			//pMmWsle = (PULONG)(pMmWsl->Wsle);
			//if (*pMmWsle) {
			//	do {
			//		*(copied + index) = *(pMmWsle + index);
			//		index++;
			//	} while ((index < 512) && (*(pMmWsle + index)));
			//}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] EXCEPTION occured in WorkingSetListMaker()\n");
			//ExFreePool(copied);
			//copied = NULL;
			//index = 0;
		}
		RestoreAddressTables();
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////		 Dump the Workingset Entries		////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////////////////	 
	if (NT_SUCCESS(ntStatus)) {
		ntStatus = STATUS_UNSUCCESSFUL;

		// MmWsl->LastInitializedWsle 필드 갯수만큼 긁어온다.
		index = ((PMMWSL)(pMessage->Message.Buffer + 4))->LastInitializedWsle;		
		copied = ExAllocatePool(NonPagedPool, index * sizeof(ULONG));		// 프로세스 워킹셋은 최대 2기가로 설정.	-> 이게 아님. 주석참조.
		if (copied == NULL) {
			DbgPrintEx(101, 0, "[ERROR] Failed to allocate pool for COPIED in WorkingSetListMaker()\n");
		}
		else {
			RtlZeroMemory(copied, index * sizeof(ULONG));

			if (!NT_SUCCESS(ManipulateAddressTables())) {
				DbgPrintEx(101, 0, "[ERROR] Invalid Parameters in WorkingSetListMaker()...\n");
				ExFreePool(copied);
				copied = NULL;
			}
			else {
				__try {
					if (pMmWsl->Wsle != NULL) {
						pMmWsl = (PMMWSL)(pMmWsl->Wsle);		// Reuse the value.
						RtlCopyMemory((PULONG)copied, (PULONG)pMmWsl, index * sizeof(ULONG));
						ntStatus = STATUS_SUCCESS;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrintEx(101, 0, "[ERROR] EXCEPTION occured in WorkingSetListMaker()\n");
					ExFreePool(copied);
					copied = NULL;
					index = 0;
				}
				RestoreAddressTables();
			}
		}		
	}


	////////////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////		 Queuing the Messages		////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////////
	if(NT_SUCCESS(ntStatus)) {
		*(PULONG)(pMessage->Message.Buffer) = index;
		pMessage->Message.MessageType = MESSAGE_TYPE_WORKINGSET_SUMMARY;

		__try {	
			ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessage->ListEntry), &(pExtension->MessageLock));
			KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] Failed to queue at WorkingSetListMaker() for SUMMARY\n");
			ExFreePool(pMessage);
			ExFreePool(copied);
			return STATUS_UNSUCCESSFUL;
		}
		
		// 요거 잘못됨.
		/*do {
			pMessage = NULL;
			pMessage = (PMESSAGE_LIST)ExAllocatePool(NonPagedPool, sizeof(MESSAGE_LIST));
			if (pMessage == NULL) {
				DbgPrintEx(101, 0, "[ERROR] Failed to allocate pool in WorkingSetListMaker()\n");
				break;
			}
			RtlZeroMemory(pMessage, sizeof(MESSAGE_LIST));
			RtlCopyMemory(pMessage->Message.Buffer, (PUCHAR)(((ULONG)copied) + (i * 1024)), ((1024 * (i + 1)) < (index * sizeof(ULONG)))? 1024 : ((index * sizeof(ULONG)) % 1024));
			pMessage->Message.MessageType = MESSAGE_TYPE_WORKINGSET_LIST;

			__try {
				ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessage->ListEntry), &(pExtension->MessageLock));
				KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrintEx(101, 0, "[ERROR] Failed to queue at WorkingSetListMaker() for LIST\n");
				ExFreePool(pMessage);
				break;
			}
			i++;
			
		} while ((1024 * i) < (index * sizeof(ULONG)));
*/
		ExFreePool(copied);
	}
	// 실패 시, 실패 메시지 전송.
	else {
		*(PULONG)(pMessage->Message.Buffer) = 0xFFFFFFFF;
		pMessage->Message.MessageType = MESSAGE_TYPE_WORKINGSET_SUMMARY;

		__try {
			ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessage->ListEntry), &(pExtension->MessageLock));
			KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] Failed to queue at WorkingSetListMaker() for SUMMARY\n");
			ExFreePool(pMessage);
		}
	}

	return ntStatus;
}


NTSTATUS UserMessageMaker(PDEVICE_EXTENSION pExtension, ULONG MessageType) {
	PMESSAGE_LIST pMessageList = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	//VAD_PARAMS vadParams;

	if (pExtension->pTargetObject == NULL) {
		DbgPrintEx(101, 0, "[Message Maker] Target Object is not set.\n");
		return ntStatus;
	}

	pMessageList = ExAllocatePool(NonPagedPool, sizeof(MESSAGE_LIST));
	if (!pMessageList) {
		DbgPrintEx(101, 0, "    -> [ERROR] Failed to Allocate pool for User Message.\n");
		return ntStatus;
	}
	RtlZeroMemory(pMessageList, sizeof(MESSAGE_LIST));
	
	switch (MessageType) {
	case MESSAGE_TYPE_PROCESS_INFO:
		ntStatus = ProcessInfoMaker(pExtension->pTargetObject, (PPROCESS_INFO)(pMessageList->Message.Buffer));
		break;
	case MESSAGE_TYPE_VAD:
		/*vadParams.Level = 0;
		vadParams.VadRoot = pExtension->pTargetObject->pVadRoot;
		ntStatus = KeExpandKernelStackAndCallout(VadMapMaker, &vadParams, 60);
		if (NT_SUCCESS(ntStatus)) {
			((PVAD_MAP)(pMessageList->Message.Buffer))->isShared = TRUE;
		}*/
		
		//VadMapMaker(&vadParams);

		VadMapMaker(pExtension, (PVAD_MAP)(pMessageList->Message.Buffer));
		ntStatus = STATUS_SUCCESS;		// 무조건 보내서 EOF임을 알려주고[pVadMap->Vad == 0], 
		break;								// 성공이라면 pVadMap->isShared == TRUE, pVadMap->Commit = 총 VAD 갯수.		
	case MESSAGE_TYPE_THREADS:
		break;
	case MESSAGE_TYPE_HANDLES:
		ntStatus = HandleTableMaker(pExtension);
		if (NT_SUCCESS(ntStatus)) {
			ntStatus = STATUS_UNSUCCESSFUL;		// 성공했을 땐, 미리 만들어둔 메시지 리스트 쓸모 없으므로 제거하도록 함.
		}
		else{
			((PHANDLE_ENTRY)(pMessageList->Message.Buffer))->EntryAddress = 0xFFFFFFFF;		// 실패
			pMessageList->Message.MessageType = MESSAGE_TYPE_HANDLES;
			ntStatus = STATUS_SUCCESS;
		}
		break;
	case MESSAGE_TYPE_SECURITY:
		break;
	case MESSAGE_TYPE_WORKINGSET_SUMMARY:
	case MESSAGE_TYPE_WORKINGSET_LIST:
		return WorkingSetListMaker(pExtension, pMessageList);
	default:
		DbgPrintEx(101, 0, "    -> Invalid Message Type Request.\n");
		return ntStatus;
	}

	if (NT_SUCCESS(ntStatus)) {
		pMessageList->Message.MessageType = MessageType;

		ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessageList->ListEntry), &(pExtension->MessageLock));
		KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
	}
	else {
		ExFreePool(pMessageList);
	}

	return ntStatus;
}

// 제대로 초기화 완료됐으면, 자동으로 PROCESS_INFO 메시지 만들고 큐잉.
NTSTATUS InitializeTargetObject(PDEVICE_EXTENSION pExtension, ULONG targetPID){
	ULONG pFirstEPROCESS = 0;
	ULONG pCurrentEPROCESS = 0;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PTARGET_OBJECT pTargetObject = NULL;
	BOOLEAN isDetected = FALSE;

	pFirstEPROCESS = (ULONG)IoGetCurrentProcess();
	if (pFirstEPROCESS == NULL) {
		DbgPrintEx(101, 0, "[ERROR] Failed to get the first process...\n");
		return ntStatus;
	}

	// Find Target Process
	pCurrentEPROCESS = pFirstEPROCESS;
	do {
		if (*(PULONG)(pCurrentEPROCESS + EPROC_OFFSET_UniqueProcessId) == targetPID) {
			isDetected = TRUE;
			break;
		}			
		else {
			pCurrentEPROCESS = (PEPROCESS)((*(PULONG)(pCurrentEPROCESS + EPROC_OFFSET_ActiveProcessLinks)) - EPROC_OFFSET_ActiveProcessLinks);
		}
	} while (pCurrentEPROCESS != pFirstEPROCESS);

	// 검색 결과.
	if (!isDetected) {
		DbgPrintEx(101, 0, "[ERROR] Target PID is not exist...\n");
		return ntStatus;
	}
	else {
		DbgPrintEx(101, 0, "   ::: Target Process's EPROCESS is at 0x%08X\n", pCurrentEPROCESS);
		
		// Target Object 설정. [이미 만들어진 TARGET_OBJECT가 없다는 것은 이미 체크함]
		pExtension->pTargetObject = ExAllocatePool(NonPagedPool, sizeof(TARGET_OBJECT));
		if(pExtension->pTargetObject == NULL) {
			DbgPrintEx(101, 0, "[ERROR] Failed to Allocate pool for TARGET_OBJECT...\n");
			return ntStatus;
		}
		pTargetObject = pExtension->pTargetObject;
		RtlZeroMemory(pTargetObject, sizeof(TARGET_OBJECT));
		
		pTargetObject->pEprocess = pCurrentEPROCESS;
		pTargetObject->pVadRoot = pCurrentEPROCESS + EPROC_OFFSET_VadRoot;
		pTargetObject->ProcessId = targetPID;

		RtlCopyMemory(pTargetObject->ImageFileName, (PUCHAR)(pCurrentEPROCESS + EPROC_OFFSET_ImageFileName), 15);
		
		// 필요한 User Message 만들고 큐잉.
		UserMessageMaker(pExtension, MESSAGE_TYPE_PROCESS_INFO);
		UserMessageMaker(pExtension, MESSAGE_TYPE_VAD);
		UserMessageMaker(pExtension, MESSAGE_TYPE_HANDLES);
		UserMessageMaker(pExtension, MESSAGE_TYPE_WORKINGSET_SUMMARY);
		return STATUS_SUCCESS;
	}
}

// pMessage->MessageType 이 100보다 작으면, Subsection을 얻기 위한 메시지라는 의미.
NTSTATUS GetVadDetails(ULONG type, PMESSAGE_ENTRY pMessage) {
	PMMVAD pVad = (PMMVAD)(pMessage->MessageType);
	PVAD_DETAILS pDetails = NULL;
	PSUBSECTION pCurrentSubsection = NULL;
	ULONG numberOfSubsection = 0;
	PVAD_DETAILS_SUBSECTION pSubsectionDetails = NULL;

	if (pVad == NULL) {
		DbgPrintEx(101, 0, "[WARNING] Target VAD has freed...\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (type == IOCTL_GET_VAD_DETAILS) {
		RtlZeroMemory(pMessage, sizeof(MESSAGE_ENTRY));
		pDetails = pMessage->Buffer;

		//	VAD가 없어졌을 경우 대비해...
		__try {
			pDetails->VadAddress = (ULONG)pVad;
			pDetails->VadFlags = pVad->LongFlags/*((pVad->LongFlags) & (~(pVad->VadFlags.CommitCharge)))*/;
			pDetails->StartVPN = pVad->StartingVpn;
			pDetails->EndVPN = pVad->EndingVpn;
			pDetails->VadFlags2 = pVad->LongFlags2;
			pDetails->VadFlags3 = pVad->LongFlags3;
			pDetails->FirstPrototypePte = (ULONG)(pVad->pFirstPrototypePte);
			pDetails->LastContiguousPte = (ULONG)(pVad->pLastContiguousPte);
			

			// Mapped
			if (!(pVad->VadFlags.PrivateMemory)) {
				if ((pVad->pSubsection) && (pVad->pSubsection->pControlArea)) {
					pDetails->ControlArea = (ULONG)(pVad->pSubsection->pControlArea);
					pDetails->CA_Flags = pVad->pSubsection->pControlArea->LongFlags;
					pDetails->CA_Deref_FLink = (ULONG)(pVad->pSubsection->pControlArea->DereferenceList.Flink);
					pDetails->CA_Deref_BLink = (ULONG)(pVad->pSubsection->pControlArea->DereferenceList.Blink);
					pDetails->CA_NumberOfSectionReferences = (ULONG)(pVad->pSubsection->pControlArea->NumberOfSectionReferences);
					pDetails->CA_NumberOfPfnReferences = (ULONG)(pVad->pSubsection->pControlArea->NumberOfPfnReferences);
					pDetails->CA_NumberOfMappedViews = (ULONG)(pVad->pSubsection->pControlArea->NumberOfMappedViews);
					pDetails->CA_NumberOfUserReferences = (ULONG)(pVad->pSubsection->pControlArea->NumberOfUserReferences);
					pDetails->CA_FlushInProgressCount = (ULONG)(pVad->pSubsection->pControlArea->FlushInProgressCount);
					pDetails->CA_ModifiedWriteCount = (ULONG)(pVad->pSubsection->pControlArea->ModifiedWriteCount);
					pDetails->CA_WaitingForDeletion = (ULONG)(pVad->pSubsection->pControlArea->pWaitingForDeletion);
					pDetails->CA_NumberOfSystemCacheViews = (ULONG)(pVad->pSubsection->pControlArea->NumberOfSystemCacheViews);
					pDetails->CA_WritableUserReferences = (ULONG)(pVad->pSubsection->pControlArea->WritableUserReferences);
					pDetails->CA_View_FLink = (ULONG)(pVad->pSubsection->pControlArea->ViewList.Flink);
					pDetails->CA_View_BLink = (ULONG)(pVad->pSubsection->pControlArea->ViewList.Blink);

					if (pVad->pSubsection->pControlArea->File) {
						pDetails->CA_FileObject = (ULONG)(pVad->pSubsection->pControlArea->FilePointer.Object);
						(pDetails->CA_FileObject) &= 0xFFFFFFF8;
						RtlCopyMemory(pDetails->CA_FileName, (((PFILE_OBJECT)(pDetails->CA_FileObject))->FileName.Buffer), (((PFILE_OBJECT)(pDetails->CA_FileObject))->FileName.Length));
					}
					if (pVad->pSubsection->pControlArea->pSegment) {
						pDetails->Segment = (ULONG)(pVad->pSubsection->pControlArea->pSegment);
						pDetails->SG_TotalNumberOfPtes = pVad->pSubsection->pControlArea->pSegment->TotalNumberOfPtes;
						pDetails->SG_Flags = pVad->pSubsection->pControlArea->pSegment->LongFlags;
						pDetails->SG_NumberOfCommittedPages = pVad->pSubsection->pControlArea->pSegment->NumberOfCommittedPages;
						pDetails->SG_SizeOfSegment = pVad->pSubsection->pControlArea->pSegment->SizeOfSegment;
					}

					//do {
					//	//////////////////////////////////////////////////////////////////////////////////
					//	//		-> VAD 가 해제되고 난 후 , 해당 주소에 쓰레기 값이 있는 상태에서 안걸러지고 참조 들어갈 때
					//	//		   아래 명령에서 BSOD 발생. (0Xx50 PAGE_FAULT_IN_NONPAGED_AREA)
					//	pCurrentSubsection = pCurrentSubsection->pNextSubsection;
					//	numberOfSubsection++;
					//} while (pCurrentSubsection);
					
					//while (pCurrentSubsection != NULL) {
					//	pCurrentSubsection = pCurrentSubsection->pNextSubsection;
					//	numberOfSubsection++;		
					//}
					//if (numberOfSubsection > 0) {		// 첫 번째 Subsection이 없는 경우 위에서 체크하고 들어왔는데 여기서 해봤자긴 하지만 일단 하자.
					//									// -> 아무래도 SEH가 안먹힌다..... BSOD 발생 상황이 이전 VAD Details에서 SEH 제대로 동작 후, 다음 앤트리 Details 들어갈 때 발생함. 
					//	pDetails->NumberOfSubsection = numberOfSubsection;
					//}
					//// 어쨌든 해당 VAD는 해제 후 쓰레가값이건, 오염된 상태이므로 실패처리.
					//else
					//	return STATUS_UNSUCCESSFUL;

					////////////////////////////////////////////////////////////////////////
					// 그냥 서브섹션이 하나라도 있으면, 1넣고 전송할 것!!!!!!!
					//	-> 위와 같은 원인으로, pSubsection 한 번더 체크하자.
					if ((pVad->pSubsection)) {
						if (pVad->pSubsection->pNextSubsection)
							pDetails->ASubsection.SubsectionAddress = 0xFFFFFFFF;
						else {
							pDetails->ASubsection.SubsectionAddress = (ULONG)(pVad->pSubsection);
							pDetails->ASubsection.BasePTE = pVad->pSubsection->pSubsectionBase;
							pDetails->ASubsection.Flags = pVad->pSubsection->LongFlags;
							pDetails->ASubsection.NumberOfFullSectors = pVad->pSubsection->NumberOfFullSectors;
							pDetails->ASubsection.PtesInSubsection = pVad->pSubsection->PtesInSubsection;
							pDetails->ASubsection.StartingSector = pVad->pSubsection->StartingSector;
							pDetails->ASubsection.UnusedPtes = pVad->pSubsection->UnusedPtes;
						}
					}
					else {	// 만약, 여기서 pSubsection 체크했을 때, NULL이라면 중간에 해제된것.
							//		-> 이런 경우에는, MessageType 에 0x0F로 성공.....
							DbgPrintEx(101, 0, "[ERROR] This VAD is corrupted in Progressing...\n");
							pMessage->MessageType = 0x0F;
					}
				}
				else {
					DbgPrintEx(101, 0, "This VAD is for Shared Memory, but Pointer to SEGMENT / SUBSECTION is not exist.\n");
					// 그냥 성공으로 넘기고, 거기서 체크하자. Mapped인데 정보가 없는 경우.
					//		-> 이런 경우에는, MessageType필드 값으로 0xFF
					pMessage->MessageType = 0xFF;
				}
			}
			return STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] In VAD DETAILS.\n");
			return STATUS_UNSUCCESSFUL;
		}
	}
	else if(type == IOCTL_GET_VAD_SUBSECTIONS) {
		__try {
			// irpCount 만큼 점프. [최대 5회]
			if (pMessage->Buffer[0] > 5) {
				DbgPrintEx(101, 0, "[ERROR] Invalid Parameters : irpCount...\n");
				return STATUS_UNSUCCESSFUL;
			}

			pCurrentSubsection = pVad->pSubsection;

			// irpCount 처리.
			pDetails = (PVAD_DETAILS)(((ULONG)(pMessage->Buffer[0])) * 35);
			if (pDetails != NULL) {
				while ((pCurrentSubsection != NULL) && ((((ULONG)(pDetails))--) > 0))
					pCurrentSubsection = pCurrentSubsection->pNextSubsection;

				if ((pCurrentSubsection == NULL) || (pDetails != NULL)) {
					DbgPrintEx(101, 0, "[ERROR] Some changes are occured at Subsections...\n");
					return STATUS_UNSUCCESSFUL;
				}
			}
			
			RtlZeroMemory(pMessage, sizeof(MESSAGE_ENTRY));
			pSubsectionDetails = pMessage->Buffer;

			// 한 번에 저장할 수 있는 서브섹션 갯수, 최대 35개로 잡자...
			while ((pCurrentSubsection != NULL) && (numberOfSubsection++ < 35)) {
				pSubsectionDetails->SubsectionAddress = (ULONG)pCurrentSubsection;
				pSubsectionDetails->BasePTE = pCurrentSubsection->pSubsectionBase;
				pSubsectionDetails->Flags = pCurrentSubsection->LongFlags;
				pSubsectionDetails->NumberOfFullSectors = pCurrentSubsection->NumberOfFullSectors;
				pSubsectionDetails->PtesInSubsection = pCurrentSubsection->PtesInSubsection;
				pSubsectionDetails->StartingSector = pCurrentSubsection->StartingSector;
				pSubsectionDetails->UnusedPtes = pCurrentSubsection->UnusedPtes;

				pSubsectionDetails = (PVAD_DETAILS_SUBSECTION)(((ULONG)pSubsectionDetails) + sizeof(VAD_DETAILS_SUBSECTION));
				pCurrentSubsection = pCurrentSubsection->pNextSubsection;				
			}
		
			//////////////////////////////////////////////////////////////////////////////////////////
			// 결과 : 서브 섹션이 좀 더 남았다면, 상위 2바이트 0xFFFF
			//		  하위 2바이트는 현재 저장한 갯수.
			pMessage->MessageType = numberOfSubsection;
			if (pCurrentSubsection != NULL) 
				pMessage->MessageType |= 0xFFFF0000;
			//////////////////////////////////////////////////////////////////////////////////////////
			return STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] In Subsection Details...\n");
			return STATUS_UNSUCCESSFUL;
		}
	}	
}



PUCHAR MemoryDumping(ULONG StartAddress, ULONG Size) {
	PUCHAR memoryDump = NULL;

	DbgPrintEx(101, 0, "::: Dumping the Address : 0x%08X [%X]\n", StartAddress, Size);

	// 메모리 할당을 다른 프로세스의 VAD와 PDT 상태로 해서, 프로그램 종료시 메모리 오염 뜨는듯..
	memoryDump = ExAllocatePool(NonPagedPool, Size);
	if (memoryDump == NULL) {
		DbgPrintEx(101, 0, "    -> Failed to allocate pool for dumping the memory...\n");
		return NULL;
	}	

	// Exchange the Vad & PDT
	if (StartAddress < 0x80000000) {
		if (!NT_SUCCESS(ManipulateAddressTables())) {
			ExFreePool(memoryDump);
			return NULL;
		}
		else{
			DbgPrintEx(101, 0, "    -> Succeeded to change the registers value...\n");
		}
	}

	// Locking & Dumping
	//	-> 요걸 레디보다 먼저...
	/*memoryDump = ExAllocatePool(NonPagedPool, Size);
	if (memoryDump == NULL) {
		DbgPrintEx(101, 0, "    -> Failed to allocate pool for dumping the memory...\n");
	}
	else {*/
		__try {

			RtlCopyMemory(memoryDump, (PUCHAR)StartAddress, Size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			ExFreePool(memoryDump);
			memoryDump = NULL;
			DbgPrintEx(101, 0, "    -> Failed to locking the memory...\n");
		}
		DbgPrintEx(101, 0, "    -> Succeeded to dump...\n");
//	}
	
	// Restore
	if (StartAddress < 0x80000000) {
		RestoreAddressTables();
	}

	return memoryDump;
}

NTSTATUS PatternFinder(PULONG pBuffer, ULONG ctlCode, PDEVICE_EXTENSION pExtension) {
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PUCHAR memoryDump = NULL;
	ULONG i = 0;
	PUCHAR pCurrent = NULL;
	PUCHAR tmpBuffer = NULL;
	USHORT tmpLength = 0;
	BOOLEAN isKernelMode = FALSE;
	PMESSAGE_LIST pMessage = NULL;

	memoryDump = MemoryDumping(pBuffer[0], pBuffer[1]);

	// 테스트 용도......
	//if (memoryDump) {
	//	ExFreePool(memoryDump);
	//	return STATUS_SUCCESS;
	//}
	//else {
	//	return STATUS_UNSUCCESSFUL;
	//}
	/////////////////////////////


	if (memoryDump != NULL) {
		if (pBuffer[0] > 0x7FFFFFFF)
			isKernelMode = TRUE;
		
		switch (ctlCode) {
		case IOCTL_FIND_PATTERN_UNICODE:
			// 유니코드 제한 : 문자열 길이가 256자 이내
			for (i = 0; i <= (pBuffer[1] - sizeof(UNICODE_STRING)); i++) {
				pCurrent = memoryDump + i;
				tmpLength = *(PUSHORT)pCurrent;
				tmpBuffer = (PUCHAR)(*(PULONG)(pCurrent + 4));
				
				if ((tmpLength > 0) && ((*(PUSHORT)(pCurrent + 2)) < 512) && (tmpLength <= (*(PUSHORT)(pCurrent + 2)))
					&& (tmpBuffer != NULL)) {
					if ((isKernelMode && ((ULONG)tmpBuffer > 0x7FFFFFFF)) || ((!isKernelMode) && ((ULONG)tmpBuffer <= 0x7FFFFFFF))) {
						
							// 유니코드 스트링의 길이가 100자를 넘어서면 짜르자...
							tmpBuffer = MemoryDumping((ULONG)tmpBuffer, (tmpLength > 200) ? 200 : tmpLength);
							pMessage = ExAllocatePool(NonPagedPool, sizeof(MESSAGE_LIST));
							if (pMessage == NULL) {
								// 할당 실패 시, 그냥 검색 중지 후 종료.
								DbgPrintEx(101, 0, "[ERROR] Failed to allocate pool in Pattern Finder...\n ");
								if (tmpBuffer != NULL)
									ExFreePool(tmpBuffer);
								ExFreePool(memoryDump);
								return ntStatus;
							}
							else {
								RtlZeroMemory(pMessage, sizeof(MESSAGE_LIST));
								pMessage->Message.MessageType = MESSAGE_TYPE_FINDER_UNICODE;
								// UNICODE_STRING 구조체라 추정되는 8바이트 메모리 덤프부터 복사.
								RtlCopyMemory(pMessage->Message.Buffer, pCurrent, 8);

								// 해당 UNICODE_STRING의 Buffer 필드의 메모리 덤프 복사.
								//	-> tmpBuffer 가 NULL이라면, 해당 주소의 메모리 덤프 실패라는 뜻.
								if (tmpBuffer) {
									RtlCopyMemory((pMessage->Message.Buffer) + 8, tmpBuffer, (tmpLength > 200) ? 200 : (ULONG)tmpLength);
									ExFreePool(tmpBuffer);
								}

								// Queuing...
								__try {
									ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessage->ListEntry), &(pExtension->MessageLock));
								}
								__except (EXCEPTION_EXECUTE_HANDLER) {
									DbgPrintEx(101, 0, "[ERROR] Failed to queue a message at Pattern Finder...\n");
									ExFreePool(pMessage);

									// 이 경우는 그냥 검색 종료.
									ExFreePool(memoryDump);
									return ntStatus;
								}

								__try {
									KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
								}
								__except (EXCEPTION_EXECUTE_HANDLER) {
									DbgPrintEx(101, 0, "[ERROR] Failed to release the semaphore at Pattern Finder.\n");
									// 이 경우는 그냥 진행.

								}
							}
						
					}
				}
			}
			ntStatus = STATUS_SUCCESS;
			break;
		default:
			break;
		}


		ExFreePool(memoryDump);
	}
	
	return ntStatus;
}


ULONG GetMemoryDump(ULONG ctlCode, PMMVAD pVad, PUCHAR buffer) {
	PUCHAR dumpStartAddress = 0;
	ULONG dumpLength = 0;
	UCHAR secondType = buffer[0];
	PUCHAR dumpBuffer = NULL;

	////////////////////////////////////////// VAD 가 해제됐는지 확인하는 플래그 찾으면 검사후 들어갈 것.
	if (pVad != NULL) {
		switch (ctlCode) {
		case IOCTL_MEMORY_DUMP_RANGE:
			dumpStartAddress = (PUCHAR)pVad;
			dumpLength = *(PULONG)(buffer + 1);
			break;
		case IOCTL_MEMORY_DUMP_PAGE:
			dumpStartAddress = (PUCHAR)pVad;
			dumpLength = 4096;
			break;
		case IOCTL_MEMORY_DUMP_VAD:
			dumpStartAddress = (PUCHAR)pVad;
			dumpLength = sizeof(MMVAD);
			break;
		case IOCTL_MEMORY_DUMP_ULONG_FLAGS:
			if (secondType == 0)
				dumpStartAddress = (PUCHAR)&(pVad->LongFlags);
			else if (secondType == 2)
				dumpStartAddress = (PUCHAR)&(pVad->LongFlags2);
			else if (secondType == 3)
				dumpStartAddress = (PUCHAR)&(pVad->LongFlags3);

			dumpLength = 4;
			break;
		case IOCTL_MEMORY_DUMP_CA:
			if ((pVad->pSubsection) && (pVad->pSubsection->pControlArea)) {
				dumpStartAddress = (PUCHAR)(pVad->pSubsection->pControlArea);
				dumpLength = sizeof(CONTROL_AREA);
			}
			break;
		case IOCTL_MEMORY_DUMP_SEGMENT:
			if ((pVad->pSubsection) && (pVad->pSubsection->pControlArea) && (pVad->pSubsection->pControlArea->pSegment)) {
				dumpStartAddress = (PUCHAR)(pVad->pSubsection->pControlArea->pSegment);
				dumpLength = sizeof(SEGMENT);
			}
			break;
		case IOCTL_MEMORY_DUMP_SUBSECTION:
			if ((pVad->pSubsection) && (secondType > 0)) {		// 첫 번째 서브섹션을 1로 본다.
				dumpStartAddress = (PUCHAR)(pVad->pSubsection);
				while (--secondType) {
					dumpStartAddress = (PUCHAR)(((PMSUBSECTION)dumpStartAddress)->pNextSubsection);
					if (dumpStartAddress == NULL) // 만약, 타겟 서브 섹션에 가기 전에 이미 NULL이라면 Failed 처리.
						break;
				}
				dumpLength = sizeof(SUBSECTION);
			}
			break;
		default:
			dumpLength = 0;
			break;
		}
	}

	if ((dumpStartAddress != NULL) && (dumpLength != 0)) {
		RtlZeroMemory(buffer, 4100);
		__try {
			dumpBuffer = MemoryDumping((ULONG)dumpStartAddress, dumpLength);
			if (dumpBuffer == NULL) {
				return 0;
			}
			else {
				*(PULONG)buffer = (ULONG)dumpStartAddress;
				RtlCopyMemory(buffer + 4, dumpBuffer, dumpLength);
				ExFreePool(dumpBuffer);
				return (dumpLength + 4);
			}
			//  이제 모든 덤프는 MemoryDumping()을 거치도록 변경....
			//	*(PULONG)buffer = (ULONG)dumpStartAddress;
			//	RtlCopyMemory(buffer + 4, dumpStartAddress, dumpLength);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] Failed to Dump [Exception Code : 0x%08X].\n", GetExceptionCode());
		}
	}

	return 0;
}

NTSTATUS ManipulateMemory(PUCHAR pBuffer) {
	PVOID startAddress = NULL;
	ULONG length = 0;

	startAddress = (PVOID)*(PULONG)pBuffer;
	length = *(PULONG)(pBuffer + 4);

	__try {
		RtlCopyMemory(startAddress, pBuffer + 8, length);
		DbgPrintEx(101, 0, "Manipulate Succeeded...\n");
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Failed to manipulate memory...\n");
		DbgPrintEx(101, 0, "    -> CODE : 0x%08X\n", GetExceptionCode());
		return STATUS_UNSUCCESSFUL;
	}

}

// MessageType = address
///// RETURN VALUE /////
//		MessageType 0x1 : Valid PDPE
//		MessageType 0x10 : Valid PDE
//		MessageType 0x100 : Valid PTE
//		MessageType 0x80000000 : SUCCESS
NTSTATUS GetPFNDetails(PTARGET_OBJECT pTargetObject, PMESSAGE_ENTRY buffer) {
	ULONG virtualAddress = buffer->MessageType;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	USHORT index = 0;
	PPFN_DETAILS pDetails = NULL;
	ULONG pfnDatabase = 0;
	ULONG targetPfn = 0;
	PHYSICAL_ADDRESS pa;

	if ((virtualAddress == 0) || (pTargetObject == NULL)) {
		DbgPrintEx(101, 0, "[ERROR] TARGET_OBJECT is not set...\n");
		return ntStatus;
	}
	pDetails = buffer->Buffer;
	RtlZeroMemory(buffer, sizeof(MESSAGE_ENTRY));
	if (!NT_SUCCESS(ManipulateAddressTables())) {
		DbgPrintEx(101, 0, "[ERROR] Failed to Ready for sniff...\n");
		return ntStatus;
	}
	pfnDatabase = *(PULONG)(*(PULONG)(((ULONG)MmGetVirtualForPhysical) + OFFSET_PFN_DATABASE_IN_MmGetVirtualForPhysical));
	DbgPrintEx(101, 0, "[[[[ PFN DATABASE : 0x%X\n", pfnDatabase);
	
	__try {
		pDetails->DirBase = *(PULONG)((pTargetObject->pEprocess) + KPROC_OFFSET_DirectoryTableBase);
		pa.QuadPart = pDetails->DirBase;
		pDetails->PDPTAddress = MmGetVirtualForPhysical(pa);

		index = ((virtualAddress & 0xC0000000) >> 30);
		pDetails->PDPEAddress = (pDetails->PDPTAddress) + (index * 8);
		pDetails->PDPEValue = *(PLARGE_INTEGER)(pDetails->PDPEAddress);
		pDetails->PDTAddress = VA_FOR_PAGE_DIRECTORY_TABLE + (index * 4096);		// PDT의 가상 주소.
		pDetails->PTAddress = VA_FOR_PAGE_TABLE + (index * 4096 * 512);			// 필요한 PDT의 PDE[0]의 PTE[0] 가상 주소.

		if (((pDetails->PDPEValue.LowPart) & 0x1) == 0x1) {
			buffer->MessageType |= 0x1;

			targetPfn = (ULONG)(((pDetails->PDPEValue.QuadPart) & 0xFFFFFF000) >> 12);
			RtlCopyMemory(pDetails->PDTPfnDatabase, (PVOID)((targetPfn * LENGTH_OF_PFN_ENTRY) + pfnDatabase), LENGTH_OF_PFN_ENTRY);
			
			index = ((virtualAddress & 0x3FE00000) >> 21);
			pDetails->PDEAddress = (pDetails->PDTAddress) + (index * 8);
			pDetails->PDEValue = *(PLARGE_INTEGER)(pDetails->PDEAddress);
			pDetails->PTAddress = (pDetails->PTAddress) + (index * 4096);			// 필요한 PDT의 필요한 PDE의 가상 주소.

			if (((pDetails->PDEValue.LowPart) & 0x1) == 0x1) {
				buffer->MessageType |= 0x10;
	
				targetPfn = (ULONG)(((pDetails->PDEValue.QuadPart) & 0xFFFFFF000) >> 12);
				RtlCopyMemory(pDetails->PTPfnDatabase, (PVOID)((targetPfn * LENGTH_OF_PFN_ENTRY) + pfnDatabase), LENGTH_OF_PFN_ENTRY);

				index = ((virtualAddress & 0x001FF000) >> 12);
				pDetails->PTEAddress = (pDetails->PTAddress) + (index * 8);
				pDetails->PTEValue = *(PLARGE_INTEGER)(pDetails->PTEAddress);

				if (((pDetails->PTEValue.LowPart) & 0x1) == 0x1) {
					buffer->MessageType |= 0x100;

					targetPfn = (ULONG)(((pDetails->PTEValue.QuadPart) & 0xFFFFFF000) >> 12);
					RtlCopyMemory(pDetails->PagePfnDatabase, (PVOID)((targetPfn * LENGTH_OF_PFN_ENTRY) + pfnDatabase), LENGTH_OF_PFN_ENTRY);

					pDetails->PhysicalAddress.QuadPart = (virtualAddress & 0xFFF);
					pDetails->PhysicalAddress.QuadPart = (pDetails->PhysicalAddress.QuadPart) + ((pDetails->PTEValue.QuadPart) & 0xFFFFFF000);

				}
			}
		}
		ntStatus = STATUS_SUCCESS;
		buffer->MessageType |= 0x10000000;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] In GetPFNDetails...\n");	
	}

	RestoreAddressTables();
	return ntStatus;
}

NTSTATUS ControlDispatch(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	ULONG ctlCode = 0;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION irpStack = NULL;
	PVOID pBuffer = NULL;
	KIRQL oldIrql;
	PDEVICE_EXTENSION pExtension = NULL;

	irpStack = IoGetCurrentIrpStackLocation(pIrp);
	pExtension = pDeviceObject->DeviceExtension;

	ctlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	switch (ctlCode) {
	case IOCTL_QUIT_COMMUNICATION:
		KeAcquireSpinLock(&(pExtension->PendingIrpLock), &oldIrql);
		if (IsListEmpty(&(pExtension->PendingIrpQueue))) {
			DbgPrintEx(101, 0, "[WARNING] the Pending Queue is empty.\n");
		}
		else {
			//	pBuffer 변수 쓸 일 없으니 활용.
			pBuffer = RemoveHeadList(&(pExtension->PendingIrpQueue));
			if (pBuffer) {
				pBuffer = CONTAINING_RECORD(pBuffer, IRP, Tail.Overlay.ListEntry);
			}
		}
		KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);

		if (pBuffer) {
			((PIRP)pBuffer)->IoStatus.Status = STATUS_CANCELLED;
			((PIRP)pBuffer)->IoStatus.Information = 0;
			IoCompleteRequest((PIRP)pBuffer, IO_NO_INCREMENT);
			DbgPrintEx(101, 0, "The pending IRP is cancelled...\n");
		}

		// 애플리케이션의 커뮤니케이션 스레드를 종료시키더라도, 드라이버의 커뮤니케이션 스레드는 살아있고, 메시지 큐는 유지된다.
		//ListCleaner(&(pExtension->MessageQueue), &(pExtension->MessageLock));

		// 요건 걍 무조건 성공으로 완료시키자.
		ntStatus = STATUS_SUCCESS;
		pIrp->IoStatus.Information = 0;
		break;
	case IOCTL_GET_VAD_MAP:
		pIrp->IoStatus.Information = 0;
		if ((pExtension->pTargetObject != NULL))
			ntStatus = UserMessageMaker(pExtension, MESSAGE_TYPE_VAD);
		break;
	case IOCTL_GET_VAD_DETAILS:
	case IOCTL_GET_VAD_SUBSECTIONS:
		pBuffer = MmGetSystemAddressForMdl(pIrp->MdlAddress);
		if ((pBuffer == NULL) || (MmGetMdlByteCount(pIrp->MdlAddress) != sizeof(MESSAGE_ENTRY))) {
			DbgPrintEx(101, 0, "[ERROR] Invalid Parameters...\n");
		}
		else{
			ntStatus = GetVadDetails(ctlCode, pBuffer);
			if (NT_SUCCESS(ntStatus))
				pIrp->IoStatus.Information = sizeof(MESSAGE_ENTRY);
		}
		break;
	case IOCTL_GET_PFN_DETAILS:
		pBuffer = MmGetSystemAddressForMdl(pIrp->MdlAddress);
		pIrp->IoStatus.Information = 0;

		if ((pBuffer == NULL) || (MmGetMdlByteCount(pIrp->MdlAddress) != sizeof(MESSAGE_ENTRY))) {
			DbgPrintEx(101, 0, "[ERROR] Invalid Parameters...\n");
		}
		else{
			ntStatus = GetPFNDetails(pExtension->pTargetObject, pBuffer);
			if (NT_SUCCESS(ntStatus))
				pIrp->IoStatus.Information = sizeof(MESSAGE_ENTRY);
		}
		break;
	case IOCTL_SELECT_TARGET:
		pBuffer = pIrp->AssociatedIrp.SystemBuffer;
		pIrp->IoStatus.Information = 0;
		if ((pBuffer == NULL) || ((irpStack->Parameters.DeviceIoControl.InputBufferLength) != 4)) {
			DbgPrintEx(101, 0, "[ERROR] Invalid Parameters...\n");
		}
		else if (pExtension->pTargetObject){
			DbgPrintEx(101, 0, "[ERROR] Target Object is already set.\n");
		}
		else {
			DbgPrintEx(101, 0, "Target Process ID : %u\n", *(PULONG)pBuffer);
			ntStatus = InitializeTargetObject(pExtension, *(PULONG)pBuffer);
		}
		break;
	case IOCTL_UNSELECT_TARGET:
		if (!(pExtension->pTargetObject)) {
			DbgPrintEx(101, 0, "[ERROR] Target Object is not exist.\n");
		}
		else {
			// Communication Thread가 현재 IRP를 기다리고 있는 경우, 깨워서 다시 세마포어 대기로 돌아가도록 한다.
			if (pExtension->isWaitingIRP) {
				pExtension->isWaitingIRP = FALSE;
				KeSetEvent(&(pExtension->WaitingIRPEvent), 0, FALSE);
			}

			// TARGET_OBJECT 해제.
			ExFreePool(pExtension->pTargetObject);
			pExtension->pTargetObject = NULL;

			// 현재 타겟에 대한 메시지 큐를 비운다.
			ListCleaner(&(pExtension->MessageQueue), &(pExtension->MessageLock));
			ntStatus = STATUS_SUCCESS;
		}
		pIrp->IoStatus.Information = 0;
		break;
	case IOCTL_MEMORY_DUMP_PAGE:
	case IOCTL_MEMORY_DUMP_VAD:
	case IOCTL_MEMORY_DUMP_ULONG_FLAGS:
	case IOCTL_MEMORY_DUMP_CA:
	case IOCTL_MEMORY_DUMP_SEGMENT:
	case IOCTL_MEMORY_DUMP_SUBSECTION:
	case IOCTL_MEMORY_DUMP_RANGE:
		if ((pIrp->AssociatedIrp.SystemBuffer == NULL) || (*(PULONG)(pIrp->AssociatedIrp.SystemBuffer) == 0) || (pIrp->MdlAddress == NULL) || (irpStack->Parameters.DeviceIoControl.OutputBufferLength != 4100)) {
			DbgPrintEx(101, 0, "[ERROR] Invalid Parameters.\n");
			pIrp->IoStatus.Information = 0;
		}
		else {
			pIrp->IoStatus.Information = GetMemoryDump(ctlCode, (PMMVAD)(*(PULONG)(pIrp->AssociatedIrp.SystemBuffer)), MmGetSystemAddressForMdl(pIrp->MdlAddress));
			if (pIrp->IoStatus.Information != 0)
				ntStatus = STATUS_SUCCESS;
		}
		break;
	case IOCTL_FIND_PATTERN_UNICODE:
		pBuffer = pIrp->AssociatedIrp.SystemBuffer;
		if ((pBuffer != NULL) && (irpStack->Parameters.DeviceIoControl.InputBufferLength == 8)) {
			ntStatus = PatternFinder(pBuffer, ctlCode, pExtension);
		}
		pIrp->IoStatus.Information = 0;
		break;
	case IOCTL_MANIPULATE_MEMORY:
		pBuffer = pIrp->AssociatedIrp.SystemBuffer;
		if (pBuffer == NULL) {
			DbgPrintEx(101, 0, "[ERROR] Invalid Parameters.\n");
		}
		else 
			ntStatus = ManipulateMemory(pBuffer);
		pIrp->IoStatus.Information = 0;
		break;


		////////////////////////////////////////////////		 아래는 콘솔 테스트용.
		/*	case IOCTL_REQUEST_DATA:
		DbgPrintEx(101, 0, "[IOCTL] Request Data.\n");
		pBuffer = pIrp->AssociatedIrp.SystemBuffer;
		if ((pBuffer == NULL) || (irpStack->Parameters.DeviceIoControl.InputBufferLength != sizeof(REQUEST_DATA))) {
			DbgPrintEx(101, 0, "    -> Invalid Parameters...\n");
		}
		else {
			ntStatus = RetrieveData(pBuffer->Pid, pBuffer->VirtualAddress, &retrievedData);
			if (NT_SUCCESS(ntStatus)) {
				DbgPrintEx(101, 0, "    -> Retrieved : %d\n", retrievedData);
				RtlZeroMemory(pBuffer, sizeof(REQUEST_DATA));
				*(PULONG)pBuffer = retrievedData;
				pIrp->IoStatus.Information = 4;
			}
			else
				pIrp->IoStatus.Information = 0;
		}
		break;*/
	default:
		break;
	}


	pIrp->IoStatus.Status = ntStatus;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;
}

// 무조건 펜딩시켜 큐로......
NTSTATUS ReadDispatch(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	PDRIVER_CANCEL oldCancelRoutine = NULL;
	PDEVICE_EXTENSION pExtension = NULL;
	KIRQL oldIrql;

	/*if ((pIrp->AssociatedIrp.SystemBuffer == NULL) || (irpStack->Parameters.Read.Length != sizeof(MESSAGE_ENTRY))) {*/
		
	if ((pIrp->MdlAddress == NULL) || (MmGetSystemAddressForMdl(pIrp->MdlAddress) == NULL) || (MmGetMdlByteCount(pIrp->MdlAddress) != sizeof(MESSAGE_ENTRY))) {
		DbgPrintEx(101, 0, "[ERROR] Invalid Parameters is READ Dispatcher.\n");
		
		pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		pIrp->IoStatus.Information = 0;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return STATUS_UNSUCCESSFUL;
	}

	pExtension = pDeviceObject->DeviceExtension;
	KeAcquireSpinLock(&(pExtension->PendingIrpLock), &oldIrql);
	IoMarkIrpPending(pIrp);
	InsertTailList(&(pExtension->PendingIrpQueue), &(pIrp->Tail.Overlay.ListEntry));
	oldCancelRoutine = IoSetCancelRoutine(pIrp, MyCancelRoutine);
	if (oldCancelRoutine == NULL) {
		if (pIrp->Cancel) {
			oldCancelRoutine = IoSetCancelRoutine(pIrp, NULL);
			if (oldCancelRoutine == NULL) {
				KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);
				return STATUS_PENDING;
			}
			else {
				RemoveEntryList(&(pIrp->Tail.Overlay.ListEntry));
				KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);

				pIrp->IoStatus.Status = STATUS_CANCELLED;
				pIrp->IoStatus.Information = 0;
				IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				return STATUS_CANCELLED;
			}
		}
		else {
			// 보통 여기로 오는데, 여기 해제작업 없이 넘어갔더니 BSOD 0x4A 뜬다.
			//		-> 시스템 콜 이후 유저 모드로 넘어갈 때 IRQL이 PASSIVE_LEVEL 이상이면 뜨는 BSOD
			KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);
		}
	}
	else {
		KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);
	}

	pIrp->IoStatus.Status = STATUS_PENDING;
	pIrp->IoStatus.Information = 0;

	//DbgPrintEx(101, 0, "IRP Pending....\n");
	if (pExtension->isWaitingIRP) {
	//	DbgPrintEx(101, 0, "    -> Event is set.\n");
		pExtension->isWaitingIRP = FALSE;
		KeSetEvent(&(pExtension->WaitingIRPEvent), 0, FALSE);
	}
//	KeSetEvent(&(pExtension->WaitingIRPEvent), 0, FALSE);

	return STATUS_PENDING;
}

VOID CommunicationThread(PDEVICE_EXTENSION pExtension) {
	KIRQL oldIrql;
	PMESSAGE_LIST pMessageList = NULL;
	PVOID pTmp = NULL;
	PIRP pIrp = NULL;
	
	DbgPrintEx(101, 0, "::: Communication Thread started...\n");

	while (TRUE) {
		KeWaitForSingleObject(&(pExtension->CommunicationSemapohore), Executive, KernelMode, FALSE, NULL);
		if (pExtension->bTerminateThread) {
			DbgPrintEx(101, 0, "::: Terminate Communication Thread.\n");
			PsTerminateSystemThread(STATUS_SUCCESS);
			return;
		}
		
		KeAcquireSpinLock(&(pExtension->MessageLock), &oldIrql);
		if (!IsListEmpty(&(pExtension->MessageQueue))) {
			pMessageList = RemoveHeadList(&(pExtension->MessageQueue));
			KeReleaseSpinLock(&(pExtension->MessageLock), oldIrql);

			if (pMessageList == NULL)
				continue;
		}
		else {
			KeReleaseSpinLock(&(pExtension->MessageLock), oldIrql);
			DbgPrintEx(101, 0, "[ERROR] Message list is empty at communication thread waked up.\n");
		}

		KeAcquireSpinLock(&(pExtension->PendingIrpLock), &oldIrql);
		if (IsListEmpty(&(pExtension->PendingIrpQueue))) {
			pExtension->isWaitingIRP = TRUE;
			KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);

			KeResetEvent(&(pExtension->WaitingIRPEvent));
			KeWaitForSingleObject(&(pExtension->WaitingIRPEvent), Executive, KernelMode, FALSE, NULL);
			
			KeAcquireSpinLock(&(pExtension->PendingIrpLock), &oldIrql);
			if (!IsListEmpty(&(pExtension->PendingIrpQueue))) {
				pTmp = RemoveHeadList(&(pExtension->PendingIrpQueue));
			}
			KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);
			
		}
		else {
			pTmp = RemoveHeadList(&(pExtension->PendingIrpQueue));
			KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);
		}
	
		// pTmp 가 있다면 어쨋든 펜딩 IRP가 있다는거, 
		// 없으면 스레드 종료나 타겟 UNSELECT로 인해 TARGET_OBJECT가 해제된 경우이므로
		//		-> 메세지 해제 후 다시 세마포어 대기.
		if (pTmp) {
			pIrp = CONTAINING_RECORD(pTmp, IRP, Tail.Overlay.ListEntry);

			// 먼저 취소될 가능성이 있나????????????? 이거 말곤 BSOD 가능성 전무... 일단 처리.
			if ((pIrp != NULL) && !(pIrp->Cancel)) {
				__try {
					pTmp = MmGetSystemAddressForMdl(pIrp->MdlAddress);

					// 여기서 BSOD 발생!!!!! [0x7E SYSTEM_THREAD_EXCEPTION_NOT_HANDLED -> MEMORY_ACCESS_VIOLATION]
					RtlCopyMemory(pTmp, &(pMessageList->Message), sizeof(MESSAGE_ENTRY));
					pIrp->IoStatus.Status = STATUS_SUCCESS;
					pIrp->IoStatus.Information = sizeof(MESSAGE_ENTRY);
					IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrintEx(101, 0, "[ERROR] Already freed IRP in Communication Thread...\n");
					// 그냥 진행.
				}
				
			}
			
			pIrp = NULL;
			pTmp = NULL;
		}
		

		ExFreePool(pMessageList);
		pMessageList = NULL;
	}
}

NTSTATUS InitializeCommunicationThread(PDEVICE_EXTENSION pExtension) {
	HANDLE hThread = NULL;
	NTSTATUS ntStatus;
	
	KeInitializeSemaphore(&(pExtension->CommunicationSemapohore), 0, MAXLONG);
	KeInitializeEvent(&(pExtension->WaitingIRPEvent), NotificationEvent, FALSE);
	pExtension->bTerminateThread = FALSE;
	ntStatus = PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, NULL, NULL, CommunicationThread, pExtension);
	if (NT_SUCCESS(ntStatus)) {
		ntStatus = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &(pExtension->CommunicationThread), NULL);
		ZwClose(hThread);
	}
	
	return ntStatus;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING regPath) {
	NTSTATUS ntStatus;
	ULONG i = 0;
	UNICODE_STRING deviceName;
	UNICODE_STRING linkName;
	PDEVICE_EXTENSION pExtension = NULL;

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		pDriverObject->MajorFunction[i] = DispatchRoutine;
	pDriverObject->DriverUnload = OnUnload;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlDispatch;
	pDriverObject->MajorFunction[IRP_MJ_READ] = ReadDispatch;

	RtlInitUnicodeString(&deviceName, nameBuffer);
	ntStatus = IoCreateDevice(pDriverObject, sizeof(DEVICE_EXTENSION), &deviceName, SIN_DEV_MEM, 0, TRUE, &pMyDevice);
	if (NT_SUCCESS(ntStatus)) {
		RtlInitUnicodeString(&linkName, linkBuffer);
		ntStatus = IoCreateSymbolicLink(&linkName, &deviceName);
		if (NT_SUCCESS(ntStatus)) {
			pExtension = pDriverObject->DeviceObject->DeviceExtension;
			RtlZeroMemory(pExtension, sizeof(DEVICE_EXTENSION));
			ntStatus = InitializeCommunicationThread(pExtension);
			if (NT_SUCCESS(ntStatus)) {
				InitializeListHead(&(pExtension->PendingIrpQueue));
				InitializeListHead(&(pExtension->MessageQueue));
				KeInitializeSpinLock(&(pExtension->PendingIrpLock));
				KeInitializeSpinLock(&(pExtension->MessageLock));

				pDriverObject->DeviceObject->Flags |= DO_DIRECT_IO;
				DbgPrintEx(101, 0, "Driver loaded...\n");

				// MemoryExplorer 프로세스의 EPROCESS 내 ProcessWorkingsetShared 플래그 올려보자.
				////	-> 여기서 EPROCESS 따면, System 프로세스의 컨텍스트이다.
				//tmp = (ULONG)PsGetCurrentProcess();
				//if (tmp != 0) {
				//	DbgPrintEx(101, 0, "[[[   %s   ]]]\n", (PUCHAR)(tmp + EPROC_OFFSET_ImageFileName));
				//	tmp = (ULONG)(*(PUCHAR)(tmp + 0x288));
				//	DbgPrintEx(101, 0, "::: flag : 0x%X\n", tmp);
				//}
		/*		if (NT_SUCCESS(InitializeTargetObject(pExtension, 4))) {
					DbgPrintEx(101, 0, "%s %08X %u %08X\n", pExtension->pTargetObject->ImageFileName, pExtension->pTargetObject->pVadRoot, pExtension->pTargetObject->ProcessId, pExtension->pTargetObject->pEprocess);
				}*/
				return ntStatus;
			}
			
		}
		IoDeleteDevice(pDriverObject->DeviceObject);
	}
	DbgPrintEx(101, 0, "Loading failed...\n");

	return ntStatus;
}