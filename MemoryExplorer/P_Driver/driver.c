/*
	Copy in 2017/11/08 for GITHUB
		When I'm making the routine "WorkingSetListMaker()"

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

#define VA_FOR_PAGE_DIRECTORY_TABLE			(ULONG)0xC0600000		// x86 PAE [x86 : 0xC0300000]
#define VA_FOR_PAGE_TABLE					(ULONG)0xC0000000


#pragma pack(1)
typedef struct _HISTORY_OBJECT {
	LIST_ENTRY ListEntry;
	ULONG StartAddress;
	ULONG Length;
	PVOID Buffer;
}HISTORY_OBJECT, *PHISTORY_OBJECT;

typedef struct _TARGET_OBJECT {
	ULONG ProcessId;
	ULONG pEprocess;
	ULONG pVadRoot;
	BOOLEAN bHistory;
	LIST_ENTRY HistoryHead;
}TARGET_OBJECT, *PTARGET_OBJECT;

typedef struct _SNIFF_OBJECT {
	ULONG backedEthread;
	ULONG backedEprocess;
	ULONG backedCR3;
	PMDL pUsingMdl;
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

PVOID NTAPI ObGetObjectType(PVOID pObject);

NTSTATUS ManipulateAddressTables(PDEVICE_EXTENSION pExtension) {
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	ULONG backedCR3 = 0;
	ULONG backedEprocess = 0;
	ULONG backedEthread = 0;

	// Just Remove, Create new one.
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



	////////////////////////////////////////////////////////////////////////////
	///////////////////////////			Backup			////////////////////////
	////////////////////////////////////////////////////////////////////////////
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
			
			// Backup the register CR3.
			mov eax, cr3;
			mov backedCR3, eax;

			pop eax;
		}

		// For preventing the target process from termination. 
		//		-> If failed, regard as already terminated.
		ntStatus = ObReferenceObjectByPointer((PVOID)backedEprocess, GENERIC_ALL, NULL, KernelMode);
		if (!NT_SUCCESS(ntStatus)) {
			ExFreePool(pExtension->pSniffObject);
			DbgPrintEx(101, 0, "[ERROR] Failed to increase the current Process' reference count.\n");
			DbgPrintEx(101, 0, "    -> Maybe the process had terminated...\n");
			return ntStatus;
		}

		pExtension->pSniffObject->backedEprocess = backedEprocess;
		pExtension->pSniffObject->backedCR3 = backedCR3;
		pExtension->pSniffObject->backedEthread = backedEthread;


		////////////////////////////////////////////////////////////////////////////
		////////////////////////		Manipulation		////////////////////////
		////////////////////////////////////////////////////////////////////////////
		
		// Change the current thread's KPROCESS.
		*(PULONG)((pExtension->pSniffObject->backedEthread) + KTHREAD_OFFSET_KPROCESS) = pExtension->pTargetObject->pEprocess;


		// Manipulate the register CR3.
		backedCR3 = *(PULONG)((pExtension->pTargetObject->pEprocess) + KPROC_OFFSET_DirectoryTableBase);
		//	-> Note it!!! NOT "EPROC_OFFSET_PageDirectoryPte"
	
		__asm {
			push eax;
			
			mov eax, backedCR3;
			mov cr3, eax;

			pop eax;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Failed to backup & manipulate the tables...\n");

		ExFreePool(pExtension->pSniffObject);
		pExtension->pSniffObject = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(101, 0, "   ::: Current Process : %s\n", (PUCHAR)((pExtension->pSniffObject->backedEprocess) + EPROC_OFFSET_ImageFileName));
	DbgPrintEx(101, 0, "       -> Manipulated to : %s\n", (PUCHAR)((pExtension->pTargetObject->pEprocess) + EPROC_OFFSET_ImageFileName));
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
		
			// Restore the backup thread's KPROCESS.
			*(PULONG)(backedEthread + KTHREAD_OFFSET_KPROCESS) = backedEprocess;

			// Restore the register CR3.
			// Only, the current thread is same with backup.
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
			
			// for TEST...
			if (!isRestored) {
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

		// Decrease the Reference count that had been increased.
		ObDereferenceObject(backedEprocess);

		ExFreePool(pExtension->pSniffObject);
		pExtension->pSniffObject = NULL;
		return;
	}

}

PVOID LockAndMapMemory(ULONG StartAddress, ULONG Length, LOCK_OPERATION Operation) {
	PVOID mappedAddress = NULL;
	PDEVICE_EXTENSION pExtension = pMyDevice->DeviceExtension;

	// Exchange the Vad & PDT
	if (pExtension && (NT_SUCCESS(ManipulateAddressTables(pExtension)))) {

		// Allocate the MDL.
		pExtension->pSniffObject->pUsingMdl = MmCreateMdl(NULL, (PVOID)StartAddress, (SIZE_T)Length);
		if ((pExtension->pSniffObject->pUsingMdl) != NULL) {

			// Lock the MDL.
			__try {
				MmProbeAndLockPages(pExtension->pSniffObject->pUsingMdl, KernelMode, Operation);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				IoFreeMdl(pExtension->pSniffObject->pUsingMdl);
				pExtension->pSniffObject->pUsingMdl = NULL;
			}

			// Mapping to System Address.
			if ((pExtension->pSniffObject->pUsingMdl) != NULL) {
				mappedAddress = MmMapLockedPages(pExtension->pSniffObject->pUsingMdl, KernelMode);
				if (mappedAddress) {
					pExtension->pSniffObject->pUsingMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
					return mappedAddress;
				}
				else {
					DbgPrintEx(101, 0, "    -> Failed to map to System Address.\n");
					IoFreeMdl(pExtension->pSniffObject->pUsingMdl);
					pExtension->pSniffObject->pUsingMdl = NULL;
				}
			}
			else
				DbgPrintEx(101, 0, "    -> Failed to lock the memory...\n");
		}

		// Failed.
		RestoreAddressTables();
	}

	return mappedAddress;
}

VOID UnMapAndUnLockMemory(PVOID mappedAddress) {
	PDEVICE_EXTENSION pExtension = pMyDevice->DeviceExtension;

	if (pExtension && pExtension->pSniffObject) {
		if (pExtension->pSniffObject->pUsingMdl) {

			// Unmap.
			if ((pExtension->pSniffObject->pUsingMdl->MdlFlags) & MDL_MAPPED_TO_SYSTEM_VA) {
				MmUnmapLockedPages(mappedAddress, pExtension->pSniffObject->pUsingMdl);
			}
			
			// Unlock the MDL.
			__try {
				MmUnlockPages(pExtension->pSniffObject->pUsingMdl);

				// Free the MDL.
				IoFreeMdl(pExtension->pSniffObject->pUsingMdl);
				pExtension->pSniffObject->pUsingMdl = NULL;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
//				DbgPrintEx(101, 0, "[ERROR] Failed to unlock the MDL...\n");
				// In this case, just proceed...
			}

		}

		RestoreAddressTables();
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
		pExtension->bTerminateThread = TRUE; 
		
		if (pExtension->isWaitingIRP) {
			pExtension->isWaitingIRP = FALSE;
			KeSetEvent(&(pExtension->WaitingIRPEvent), 0, FALSE);
		}
		
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

VOID MyCancelRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	PKSPIN_LOCK pLock = NULL;
	KIRQL oldIrql;

	// Release the global cancel lock.
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

		// for TEST...
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


// Recursive Version...
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
				// Reuse the variable "MessageType".
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
		// Just process it as success.
	}

	pMessageList->Message.MessageType = MESSAGE_TYPE_VAD;
	
	__try{		
		ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessageList->ListEntry), &(pExtension->MessageLock));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(101, 0, "[ERROR] Failed to q`ueue in MessageQueue...\n");
		ExFreePool(pMessageList);
		return FALSE;
	}
	
	__try {
		KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {		// Why not the handler is executed??  Just BSOD....
//		if (GetExceptionCode() == STATUS_SEMAPHORE_LIMIT_EXCEEDED) {	// GetExceptionCode()'s return value is not that type....
//			DbgPrintEx(101, 0, "[ERROR] Exceeds the Semaphore limit...\n");
//		}

		return FALSE;
	}
	
	return TRUE;

}


// Just Repetitive statement. Not Recursive
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

			// Find the branch point.
			while (TRUE) {
				pParentNode = (PMMADDRESS_NODE)(((ULONG)(pCurrentNode->Parent)) & 0xFFFFFFFC);
				
				// Finishing Search.
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
			
			// Making entry.
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
				// Making entry.
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
			// Closed handle...
			//	-> Object Header Pointer is to be Zero.
			//	-> this entry is not counted to HandleCount .
			if (*(PULONG)currentEntry == 0)
			{
				pHandleEntry->FileObject = 0xFFFFFFFFF;
			}
			else {
				pHandleEntry->GrantedAccess = *(PULONG)(currentEntry + 4);
				pHandleEntry->FileObject = ((*(PULONG)currentEntry) & 0xFFFFFFF8) + 0x18;		// Object Header Pointer is stored in HanldeTable.
				pHandleEntry->Type = *(PULONG)((pHandleEntry->FileObject) - 0xC);		// - 0x18 + 0xC


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

// There are 3 levels of Handle table...	[Top, Middle, Sub]
NTSTATUS HandleTableMaker(PDEVICE_EXTENSION pExtension) {
	ULONG currentEntry = 0;
	ULONG handleCount = 0;
	ULONG currentHandleNumber = 0;
	ULONG HandleTable = 0;
	BOOLEAN secondTable = FALSE;
	BOOLEAN topTable = FALSE;
	USHORT secondIndex = 0;
	USHORT topIndex = 0;

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
		
		HandleTable = HandleTable & 0xFFFFFFFC;		// Included 2-bits flags.
		currentEntry = HandleTable;
		if (secondTable)
			currentEntry = *(PULONG)currentEntry;
		if (topTable)
			currentEntry = *(PULONG)currentEntry;

		// Handle Number == 0 is not in here.
		currentHandleNumber += 4;
		currentEntry += 8;

		while ( (currentEntry > 0x80000000) && (handleCount > 0)) {
			// The handle index of Multiples of 0x800 is the Audit Entry.
			//		-> Just Increase the count.
			if ((currentHandleNumber % 0x800)) {
				switch (HandleEntryMaker(currentHandleNumber, currentEntry, pExtension))
				{
				case 0:	// Freed Entry
					break;
				case 1:	// Using Handle
					handleCount--;
					break;
				default:	
					return STATUS_UNSUCCESSFUL;
				}
			}
			// Exchange the SubHandle Table & Increase the count.
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
	ULONG count = 0;
	PMMWSL pMmWsl = NULL;
	PUCHAR copied = NULL;
	ULONG i = 0;
	PVOID mappedAddress = NULL;
	
	if (pExtension->pTargetObject == NULL) {
		DbgPrintEx(101, 0, "[ERROR] Invalid Parameters in WorkingSetListMaker()...\n");
		return ntStatus;
	}
	
	// IN the EPROCESS, the __MMSUPPROT structure is included. Not the pointer.
	pMmWsl = (PMMWSL)(((PMMSUPPORT)((pExtension->pTargetObject->pEprocess) + EPROC_OFFSET_Vm))->VmWorkingSetList);
	if (((ULONG)pMmWsl) < 0xC0000000) {
		DbgPrintEx(101, 0, "[ERROR] Invalid VM field in EPROCESS...\n");
		return ntStatus;
	}
	

	////////////////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////		 Dump the MMWSL Structure		////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////////////	 
	mappedAddress = LockAndMapMemory((ULONG)pMmWsl, sizeof(ULONG) * 18, IoReadAccess);
	if (mappedAddress == NULL) {
		DbgPrintEx(101, 0, "[ERROR] Invalid Parameters in WorkingSetListMaker()...\n");
	}
	else {
		__try {
			RtlCopyMemory((pMessage->Message.Buffer) + 4, mappedAddress, sizeof(ULONG) * 18);
			ntStatus = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] EXCEPTION occured in WorkingSetListMaker()\n");
		}
		UnMapAndUnLockMemory(mappedAddress);
		mappedAddress = NULL;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////		 Dump the Workingset Entries		////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////////////////	 
	if (NT_SUCCESS(ntStatus)) {
		ntStatus = STATUS_UNSUCCESSFUL;

		count = (((PMMWSL)(pMessage->Message.Buffer + 4))->LastInitializedWsle) + 1;
		copied = ExAllocatePool(NonPagedPool, count * sizeof(ULONG));
		if (copied == NULL) {
			DbgPrintEx(101, 0, "[ERROR] Failed to allocate pool for COPIED in WorkingSetListMaker()\n");
		}
		else {
			RtlZeroMemory(copied, count * sizeof(ULONG));

			mappedAddress = LockAndMapMemory(((PMMWSL)((pMessage->Message.Buffer) + 4))->Wsle, count * sizeof(ULONG), IoReadAccess);
			if (mappedAddress == NULL) {
				DbgPrintEx(101, 0, "[ERROR] Invalid Parameters in WorkingSetListMaker()...\n");
				ExFreePool(copied);
				copied = NULL;
			}
			else {
				__try {
					RtlCopyMemory((PULONG)copied, mappedAddress, count * sizeof(ULONG));
					ntStatus = STATUS_SUCCESS;
					
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrintEx(101, 0, "[ERROR] EXCEPTION occured in WorkingSetListMaker()\n");
				}

				UnMapAndUnLockMemory(mappedAddress);

				if (!NT_SUCCESS(ntStatus)) {
					ExFreePool(copied);
					copied = NULL;
					count = 0;
				}
			}
		}		
	}


	////////////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////		 Queuing the Messages		////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////////
	if(NT_SUCCESS(ntStatus)) {
		*(PULONG)(pMessage->Message.Buffer) = count;
		pMessage->Message.MessageType = MESSAGE_TYPE_WORKINGSET_SUMMARY;

		__try {	
			ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessage->ListEntry), &(pExtension->MessageLock));
			KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] Failed to queue in WorkingSetListMaker() for SUMMARY\n");
			ExFreePool(pMessage);
			ExFreePool(copied);
			return STATUS_UNSUCCESSFUL;
		}
		
		/////////////////////////		BSOD occured... BAD_POOL_HEADER
		//		-> It is CommunicationThread()'s fault... NOT here...
		// count -> byte
		count = count * sizeof(ULONG);
		  
		for (i = 0; i <= count; i += 1024) {
			pMessage = NULL;
			pMessage = (PMESSAGE_LIST)ExAllocatePool(NonPagedPool, sizeof(MESSAGE_LIST));
			if (pMessage == NULL) {
				DbgPrintEx(101, 0, "[ERROR] Failed to allocate pool in WorkingSetListMaker()\n");
				ntStatus = STATUS_UNSUCCESSFUL;
				break;
			}
			RtlZeroMemory(pMessage, sizeof(MESSAGE_LIST));
			
			pMessage->Message.MessageType = MESSAGE_TYPE_WORKINGSET_LIST;
			if((i + 1024) > count)
				RtlCopyMemory(pMessage->Message.Buffer, copied + i, count % 1024);
			else
				RtlCopyMemory(pMessage->Message.Buffer, copied + i, 1024);

			__try {
				ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessage->ListEntry), &(pExtension->MessageLock));
				KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrintEx(101, 0, "[ERROR] Failed to queue in WorkingSetListMaker() for LIST\n");
				ExFreePool(pMessage);
				ntStatus = STATUS_UNSUCCESSFUL;
				break;
			}
		}
		
		ExFreePool(copied);
	}
	else {
		*(PULONG)(pMessage->Message.Buffer) = 0xFFFFFFFF;
		pMessage->Message.MessageType = MESSAGE_TYPE_WORKINGSET_SUMMARY;

		__try {
			ExInterlockedInsertTailList(&(pExtension->MessageQueue), &(pMessage->ListEntry), &(pExtension->MessageLock));
			KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(101, 0, "[ERROR] Failed to queue in WorkingSetListMaker() for SUMMARY\n");
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
		// for Recursive version...
		/*vadParams.Level = 0;
		vadParams.VadRoot = pExtension->pTargetObject->pVadRoot;
		ntStatus = KeExpandKernelStackAndCallout(VadMapMaker, &vadParams, 60);
		if (NT_SUCCESS(ntStatus)) {
			((PVAD_MAP)(pMessageList->Message.Buffer))->isShared = TRUE;
		}*/
		
		//VadMapMaker(&vadParams);

		VadMapMaker(pExtension, (PVAD_MAP)(pMessageList->Message.Buffer));
		ntStatus = STATUS_SUCCESS;		// EOF : [pVadMap->Vad == 0], 
		break;								// If succeed, pVadMap->isShared : TRUE, pVadMap->Commit : Total count of VADs.		
	case MESSAGE_TYPE_THREADS:
		break;
	case MESSAGE_TYPE_HANDLES:
		ntStatus = HandleTableMaker(pExtension);
		if (NT_SUCCESS(ntStatus)) {
			ntStatus = STATUS_UNSUCCESSFUL;		// if suceed, remove the entry created.
		}
		else{
			((PHANDLE_ENTRY)(pMessageList->Message.Buffer))->EntryAddress = 0xFFFFFFFF;		// Failed
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

// targetPID's first byte is the flags for History Function.
NTSTATUS InitializeTargetObject(PDEVICE_EXTENSION pExtension, ULONG targetPID){
	ULONG pFirstEPROCESS = 0;
	ULONG pCurrentEPROCESS = 0;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PTARGET_OBJECT pTargetObject = NULL;
	BOOLEAN isDetected = FALSE;
	UCHAR flags = 0;

	pFirstEPROCESS = (ULONG)IoGetCurrentProcess();
	if (pFirstEPROCESS == NULL) {
		DbgPrintEx(101, 0, "[ERROR] Failed to get the first process...\n");
		return ntStatus;
	}

	// Separate Flags frome targetPID.
	flags = (UCHAR)((targetPID & 0xFF000000) >> 24);
	targetPID &= 0x00FFFFFF;

	// Find the Target Process.
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

	// Result of the search.
	if (!isDetected) {
		DbgPrintEx(101, 0, "[ERROR] Target PID is not exist...\n");
		return ntStatus;
	}
	else {
		DbgPrintEx(101, 0, "   ::: Target Process's EPROCESS is at 0x%08X\n", pCurrentEPROCESS);
		
		// Set the Target Object. 
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
		if (flags & 0x80) {
			InitializeListHead(&(pTargetObject->HistoryHead));
			pTargetObject->bHistory = TRUE;
		}
	
		UserMessageMaker(pExtension, MESSAGE_TYPE_PROCESS_INFO);
		UserMessageMaker(pExtension, MESSAGE_TYPE_VAD);
		UserMessageMaker(pExtension, MESSAGE_TYPE_HANDLES);
		UserMessageMaker(pExtension, MESSAGE_TYPE_WORKINGSET_SUMMARY);

		return STATUS_SUCCESS;
	}
}

//if "pMessage->MessageType" is lower than 100, it is the message for get the Subsections
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
					//	//		-> After the VAD is freed, 해당 주소에 쓰레기 값이 있는 상태에서 안걸러지고 참조 들어갈 때
					//	//		   아래 명령에서 BSOD occured : [0x50 PAGE_FAULT_IN_NONPAGED_AREA]
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
					// There are any Subsections, just put 1 and Return.
					//	-> By the same reason, One more check th pSubsection.
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
					else {	// if pSubsection is NULL hrer, it had been freed at the middle of this Method.
							//		-> In this case, Store 0x0f in MessageType and Process it as success.
							DbgPrintEx(101, 0, "[ERROR] This VAD is corrupted in Progressing...\n");
							pMessage->MessageType = 0x0F;
					}
				}
				else {
					DbgPrintEx(101, 0, "This VAD is for Shared Memory, but Pointer to SEGMENT / SUBSECTION is not exist.\n");
					// If it is Mapped but no values, Just Process it as success and handle it in application. 
					//		-> In this case, Store 0xFF in MessageType.
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
			// Jump as many as the irpCount. [Max 5]
			if (pMessage->Buffer[0] > 5) {
				DbgPrintEx(101, 0, "[ERROR] Invalid Parameters : irpCount...\n");
				return STATUS_UNSUCCESSFUL;
			}

			pCurrentSubsection = pVad->pSubsection;

			// Process the irpCount.
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

			// Maximum 35 subsections in a Message.
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
			// Result : More Subsections, Most significant 2 bytes : 0xFFFF
			//		    Lower 2 bytes : the count of the stored entries.
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

PUCHAR MemoryDumping(ULONG StartAddress, ULONG Length) {
	PUCHAR memoryDump = NULL;
	PVOID mappedAddress = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	DbgPrintEx(101, 0, "::: Dumping the Address : 0x%08X [%X]\n", StartAddress, Length);

	// Allocate the Pool before corrupt the current VAD & PDT.
	memoryDump = ExAllocatePool(NonPagedPool, Length);
	if (memoryDump == NULL) {
		DbgPrintEx(101, 0, "    -> Failed to allocate pool for dumping the memory...\n");
	}	
	else {
		RtlZeroMemory(memoryDump, Length);

		mappedAddress = LockAndMapMemory(StartAddress, Length, IoReadAccess);
		if (mappedAddress != NULL){
			__try {
				RtlCopyMemory(memoryDump, mappedAddress, Length);
				ntStatus = STATUS_SUCCESS;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				ntStatus = STATUS_UNSUCCESSFUL;
			}
		
			UnMapAndUnLockMemory(mappedAddress);
		}
	}

	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(101, 0, "[ERROR] Failed to copy.\n");

		ExFreePool(memoryDump);
		memoryDump = NULL;
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

	// for TEST......
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
			// LIMIT : the length of UNICODE_STRING < 256
			for (i = 0; i <= (pBuffer[1] - sizeof(UNICODE_STRING)); i++) {
				pCurrent = memoryDump + i;
				tmpLength = *(PUSHORT)pCurrent;
				tmpBuffer = (PUCHAR)(*(PULONG)(pCurrent + 4));
				
				if ((tmpLength > 0) && ((*(PUSHORT)(pCurrent + 2)) < 512) && (tmpLength <= (*(PUSHORT)(pCurrent + 2)))
					&& (tmpBuffer != NULL)) {
					if ((isKernelMode && ((ULONG)tmpBuffer > 0x7FFFFFFF)) || ((!isKernelMode) && ((ULONG)tmpBuffer <= 0x7FFFFFFF))) {
						
							// if the length is above 100, Trucate it...
							tmpBuffer = MemoryDumping((ULONG)tmpBuffer, (tmpLength > 200) ? 200 : tmpLength);
							pMessage = ExAllocatePool(NonPagedPool, sizeof(MESSAGE_LIST));
							if (pMessage == NULL) {
								// if fails to allocate, Just finish.
								DbgPrintEx(101, 0, "[ERROR] Failed to allocate pool in Pattern Finder...\n ");
								if (tmpBuffer != NULL)
									ExFreePool(tmpBuffer);
								ExFreePool(memoryDump);
								return ntStatus;
							}
							else {
								RtlZeroMemory(pMessage, sizeof(MESSAGE_LIST));
								pMessage->Message.MessageType = MESSAGE_TYPE_FINDER_UNICODE;

								// if detect the 8 bytes data assumed as UNICODE_STRING, Dump it.
								RtlCopyMemory(pMessage->Message.Buffer, pCurrent, 8);

								// Dump the contents of assumed UNICODE_STRING's Buffer.
								//		-> if tmpBuffer is NULL, failed the dump.
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

									// In this case, just finishing search.
									ExFreePool(memoryDump);
									return ntStatus;
								}

								__try {
									KeReleaseSemaphore(&(pExtension->CommunicationSemapohore), 0, 1, FALSE);
								}
								__except (EXCEPTION_EXECUTE_HANDLER) {
									DbgPrintEx(101, 0, "[ERROR] Failed to release the semaphore at Pattern Finder.\n");
									// In this case, just proceed.

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
			if ((pVad->pSubsection) && (secondType > 0)) {		// the First Subsection's index is 1.
				dumpStartAddress = (PUCHAR)(pVad->pSubsection);
				while (--secondType) {
					dumpStartAddress = (PUCHAR)(((PMSUBSECTION)dumpStartAddress)->pNextSubsection);
					if (dumpStartAddress == NULL) // if already NULL before detect the target subsection, Processit as Fail.
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

		dumpBuffer = MemoryDumping((ULONG)dumpStartAddress, dumpLength);
		if (dumpBuffer == NULL) {
			return 0;
		}
		else {
			*(PULONG)buffer = (ULONG)dumpStartAddress;
			__try {
				RtlCopyMemory(buffer + 4, dumpBuffer, dumpLength);
				ExFreePool(dumpBuffer);
				dumpBuffer = NULL;
				return (dumpLength + 4);
			}
			__except(EXCEPTION_EXECUTE_HANDLER) {
//				DbgPrintEx(101, 0, "[ERROR] Failed to Dump [Exception Code : 0x%08X].\n", GetExceptionCode());
			}
		}
	}

	ExFreePool(dumpBuffer);
	return 0;
}

NTSTATUS ManipulateMemory(ULONG StartAddress, ULONG Length, PUCHAR pBuffer) {
	PVOID mappedAddress = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PLIST_ENTRY pHistoryhead = NULL;
	PHISTORY_OBJECT pHistory = NULL;

	if ((StartAddress == 0) || (Length == 0) || (Length > 4096)) {
		DbgPrintEx(101, 0, "[ERROR] Invalid Parameters in ManipulateMemory()...\n");
		return ntStatus;
	}
	
	if (((PDEVICE_EXTENSION)(pMyDevice->DeviceExtension))->pTargetObject->bHistory) {
		pHistory = ExAllocatePool(NonPagedPool, sizeof(HISTORY_OBJECT));
		if (pHistory == NULL) {
			DbgPrintEx(101, 0, "[ERROR] Failed to allocate Pool for HISTORY_OBJECT.\n");
			return ntStatus;
		}
		RtlZeroMemory(pHistory, sizeof(HISTORY_OBJECT));

		pHistory->Buffer = ExAllocatePool(NonPagedPool, Length);
		if (pHistory->Buffer == NULL) {
			DbgPrintEx(101, 0, "[ERROR] Failed to allocate Pool for History buffer.\n");
			ExFreePool(pHistory);
			return ntStatus;
		}
		RtlZeroMemory(pHistory->Buffer, Length);

		pHistoryhead = &(((PDEVICE_EXTENSION)(pMyDevice->DeviceExtension))->pTargetObject->HistoryHead);
	}

	mappedAddress = LockAndMapMemory(StartAddress, Length, IoWriteAccess);
	if (mappedAddress != NULL) {
		__try {
			// Store the History.
			if (pHistory != NULL)
				RtlCopyMemory(pHistory->Buffer, mappedAddress, Length);

			// Manipulate.
			RtlCopyMemory(mappedAddress, pBuffer, Length);

			DbgPrintEx(101, 0, "Manipulation Succeeded...\n");
			ntStatus = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
//			DbgPrintEx(101, 0, "[ERROR] Failed to manipulate memory...\n");
//			DbgPrintEx(101, 0, "    -> CODE : 0x%08X\n", GetExceptionCode());
		}

		UnMapAndUnLockMemory(mappedAddress);

		if (pHistory != NULL) {
			if (NT_SUCCESS(ntStatus)) {
				pHistory->StartAddress = StartAddress;
				pHistory->Length = Length;
				InsertTailList(pHistoryhead, &(pHistory->ListEntry));
			}
			else {
				ExFreePool(pHistory->Buffer);
				ExFreePool(pHistory);
			}
		}
	}
	
	return ntStatus;
}

// MessageType : address
////////	RETURN VALUE	////////////
//		MessageType 0x1 : Valid PDPE
//		MessageType 0x10 : Valid PDE
//		MessageType 0x100 : Valid PTE
//		MessageType 0x80000000 : SUCCESS
/////////////////////////////////////////
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

	if (!NT_SUCCESS(ManipulateAddressTables(pMyDevice->DeviceExtension))) {
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
		pDetails->PDTAddress = VA_FOR_PAGE_DIRECTORY_TABLE + (index * 4096);		// the virtual address for PDT.
		pDetails->PTAddress = VA_FOR_PAGE_TABLE + (index * 4096 * 512);			// the virtual address for the PTE[0] of PDE[0] of the Relevant PDT.

		if (((pDetails->PDPEValue.LowPart) & 0x1) == 0x1) {
			buffer->MessageType |= 0x1;

			targetPfn = (ULONG)(((pDetails->PDPEValue.QuadPart) & 0xFFFFFF000) >> 12);
			RtlCopyMemory(pDetails->PDTPfnDatabase, (PVOID)((targetPfn * LENGTH_OF_PFN_ENTRY) + pfnDatabase), LENGTH_OF_PFN_ENTRY);
			
			index = ((virtualAddress & 0x3FE00000) >> 21);
			pDetails->PDEAddress = (pDetails->PDTAddress) + (index * 8);
			pDetails->PDEValue = *(PLARGE_INTEGER)(pDetails->PDEAddress);
			pDetails->PTAddress = (pDetails->PTAddress) + (index * 4096);			// the virtual address for the relevant PDE of the relevant PDT.

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
			//	Reuse the variable "pBuffer".
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

		// In this request, Unconditionally Success.
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
			// Communication Thread is waiting for IRP, Wake up and go back to the State of KeReleaseSemaphore.
			if (pExtension->isWaitingIRP) {
				pExtension->isWaitingIRP = FALSE;
				KeSetEvent(&(pExtension->WaitingIRPEvent), 0, FALSE);
			}

			// Reuse the variable "ntStatus".
			ntStatus = (NTSTATUS)(*(PULONG)(pIrp->AssociatedIrp.SystemBuffer));

			// Restore the manipulations.
			if (pExtension->pTargetObject->bHistory) {
				pExtension->pTargetObject->bHistory = FALSE;

					while (!IsListEmpty(&(pExtension->pTargetObject->HistoryHead))) {
						pBuffer = (PVOID)RemoveTailList(&(pExtension->pTargetObject->HistoryHead));
						if (pBuffer) {

							// Restore.
							//	-> It doesn't matter, Succeed or not.
							if ((ULONG)ntStatus == 1)
								ManipulateMemory(((PHISTORY_OBJECT)pBuffer)->StartAddress, ((PHISTORY_OBJECT)pBuffer)->Length, (PUCHAR)(((PHISTORY_OBJECT)pBuffer)->Buffer));

							// Free.
							ExFreePool(((PHISTORY_OBJECT)pBuffer)->Buffer);
							ExFreePool((PHISTORY_OBJECT)pBuffer);
							pBuffer = NULL;
						}
					}			
			}			

			// Free the TARGET_OBJECT.
			ExFreePool(pExtension->pTargetObject);
			pExtension->pTargetObject = NULL;
			
			// Empty the message queue for the current target.
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
			ntStatus = ManipulateMemory(*(PULONG)pBuffer, *(((PULONG)pBuffer) + 1), (PUCHAR)(((PULONG)pBuffer) + 2));
	
		pIrp->IoStatus.Information = 0;
		break;
	default:
		break;
	}


	pIrp->IoStatus.Status = ntStatus;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;
}

// Unconditionally, Send to Pending Queue...
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
			// if not release in this branch, BSOD 0x4A may occur.
			//		-> when returning to User-Mode after SYSTEM CALL, if the IRQL is higher than the PASSIVE_LEVEL, the BSOD occurs.
			KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);
		}
	}
	else {
		KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);
	}

	pIrp->IoStatus.Status = STATUS_PENDING;
	pIrp->IoStatus.Information = 0;

	if (pExtension->isWaitingIRP) {
		pExtension->isWaitingIRP = FALSE;
		KeSetEvent(&(pExtension->WaitingIRPEvent), 0, FALSE);
	}

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
		if (!IsListEmpty(&(pExtension->MessageQueue)))
			pMessageList = RemoveHeadList(&(pExtension->MessageQueue));		
		KeReleaseSpinLock(&(pExtension->MessageLock), oldIrql);

		if (pMessageList == NULL) {
			DbgPrintEx(101, 0, "[ERROR] Message list is empty when communication thread waked up.\n");

			// I had forgotten it...	-> It had led to BSOD : BAD_POOL_HEADER
			continue;
		}
		else {
			KeAcquireSpinLock(&(pExtension->PendingIrpLock), &oldIrql);
			if (IsListEmpty(&(pExtension->PendingIrpQueue))) {
				pExtension->isWaitingIRP = TRUE;
				KeReleaseSpinLock(&(pExtension->PendingIrpLock), oldIrql);
				
				KeResetEvent(&(pExtension->WaitingIRPEvent));
				KeWaitForSingleObject(&(pExtension->WaitingIRPEvent), Executive, KernelMode, FALSE, NULL);
				
				if (pExtension->bTerminateThread) {
					DbgPrintEx(101, 0, "::: Terminate Communication Thread.\n");
					ExFreePool(pMessageList);
					PsTerminateSystemThread(STATUS_SUCCESS);
					return;
				}
					
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

			// if pTmp is not NULL, a Pending IRP exist. 
			// If no Pending IRP exists, TARGET_OBJECT had been freed by unselecting target process.
			//		-> In this case, Free message and go back to the state of waiting seamphore.
			if (pTmp) {
				pIrp = CONTAINING_RECORD(pTmp, IRP, Tail.Overlay.ListEntry);

				// 먼저 취소될 가능성이 있나????????????? 이거 말곤 BSOD 가능성 전무... 일단 처리.
				if ((pIrp != NULL) && !(pIrp->Cancel)) {
					__try {
						pTmp = MmGetSystemAddressForMdl(pIrp->MdlAddress);

						// BSOD had occured!!!!! [0x7E SYSTEM_THREAD_EXCEPTION_NOT_HANDLED -> MEMORY_ACCESS_VIOLATION]
						RtlCopyMemory(pTmp, &(pMessageList->Message), sizeof(MESSAGE_ENTRY));
						pIrp->IoStatus.Status = STATUS_SUCCESS;
						pIrp->IoStatus.Information = sizeof(MESSAGE_ENTRY);
						IoCompleteRequest(pIrp, IO_NO_INCREMENT);
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
						DbgPrintEx(101, 0, "[ERROR] Already freed IRP in Communication Thread...\n");
						// Just Proceed.
					}
				}

				pIrp = NULL;
				pTmp = NULL;
			}

			ExFreePool(pMessageList);
			pMessageList = NULL;
		}
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