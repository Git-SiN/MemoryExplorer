/*
    [문제] 폼 닫을 때 0A BSOD 발생 문제는 driver에서 해결보자....
        또 다른 문제는 Select 버튼 누를 때 PID로 프로세스 받아올 때 예상치 못한 예외가 발생한다.
             -> 일단 주석처리 해놨고, MessageBox로 확인해본 결과 PID는 제대로 파싱된다.

    //////////////////////////////////////////////////////////////////////////////////////////
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct MESSAGE_ENTRY
    {
        public uint MessageType;
        public byte[] Buffer;

        public MESSAGE_ENTRY(int length)
        {
            MessageType = 0;
            Buffer = new byte[length];
            Buffer.Initialize();
        }
    }
    //////////////////////////////////////////////////////////////////////////////////////////
    //  -> 요렇게 짜면 SizeOf()가 8이 된다..............................
    byte[] 가 포인터로 잡히네 


    [문제] Idle 프로세스와 System 프로세스를 Select하면, 액세스 위반 에러로 인해 드라이버로 넘어가기 전에 유저 단에서 이미 차단됐었다.
         -> 드라이버로 보내기 전에 Select 된 프로세스가 살아있는지 검사할 때 시스템 프로세스의 정보는 못보도록 보호되나 보다.
             -> 이미 관리자 권한으로 실행했음에도 불구하고..................

            [해결] 어짜피 프로세스가 죽었으면 드라이버에서 EPROCESS를 찾을 수 없으니, 검사하지 말고 그냥 보내자.

    !!!!!!!!!!!!!!  배열을 넘길 때는 ref 없애야 한다.

    [진행] 메모리 덤프 떠오는 것까지 완료.
            -> 덤프 수정 기능 넣자!!!!!!!!!!!!!!!!!!!!!!!
                -> 그 다음 플래그 값 대입해 보면서 확인 후 조건식 첨가.

    [진행] 메모리 수정하는 것까지 완료.
         -> 이제 플래그 값 하나씩 체크해보고, 파싱 구문 완성할 것.
         
         
         */


using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;


namespace MemoryExplorer
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct MESSAGE_ENTRY
    {
        public uint MessageType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        public byte[] Buffer;
        //public byte[] Buffer;

        //public MESSAGE_ENTRY(int length)
        //{
        //    MessageType = 0;
        //    Buffer = new byte[length];
        //    Buffer.Initialize();
        //} -> 요거 4바이트로 잡힘 
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct PROCESS_INFO
    {
        public uint Eprocess;
        public uint DirectoryTableBase;
        public uint ProcessId;
        public uint HandleTable;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string ImageFullName;
        public uint Peb;
        public uint VadRoot;
        public uint ThreadListHead;
    }

    [StructLayout(LayoutKind.Sequential, CharSet =CharSet.Unicode, Pack = 1)]
    public struct VAD_MAP
    {
        public uint Vad;
        public uint Start;
        public uint End;
        public uint Commit;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string FileName;
        public byte Level;
        public bool isPrivate;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    public struct HANDLE_ENTRY
    {
        public uint HandleNumber;
        public uint EntryAddress;
        public uint FileObject;
        public uint GrantedAccess;
        public uint Type;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Name;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    public struct FINDER_ENTRY
    {
        public uint Length;
        public uint Address;
        public uint Address2;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 104)]  
        public string Contents;
    }

    //[StructLayout(LayoutKind.Sequential, CharSet= CharSet.None, Pack = 1)]
    //public struct WORKINGSET_SUMMARY
    //{
    //    public uint Count;
    //    public uint FirstFree;  //Uint4B
    //    public uint FirstDynamic;  //Uint4B
    //    public uint LastEntry;  //Uint4B
    //    public uint NextSlot;  //Uint4B
    //    public uint Wsle;  //Ptr32 _MMWSLE
    //    public uint LowestPagableAddress;  //Ptr32 Void
    //    public uint LastInitializedWsle;  //Uint4B
    //    public uint NextAgingSlot;  //Uint4B
    //    public uint NumberOfCommittedPageTables;  //Uint4B
    //    public uint VadBitMapHint;  //Uint4B
    //    public uint NonDirectCount;  //Uint4B
    //    public uint LastVadBit;  //Uint4B
    //    public uint MaximumLastVadBit;  //Uint4B
    //    public uint LastAllocationSizeHint;  //Uint4B
    //    public uint LastAllocationSize;  //Uint4B
    //    public uint NonDirectHash;  //Ptr32 _MMWSLE_NONDIRECT_HASH
    //    public uint HashTableStart;  //Ptr32 _MMWSLE_HASH
    //    public uint HighestPermittedHashAddress;  //Ptr32 _MMWSLE_HASH
    //}

    enum MESSAGE_TYPE : uint {
        Failed,
        ProcessInfo,
        Vad,
        Threads,
        Security,
        Handles,
        Object_Unicode,
        WorkingSetSummary,
        WorkingSetList,
        Pattern_Unicode,
        Pattern_String,
        End_Of_Finder			
    }

    public partial class fMain : Form
    {
        /// <summary>
        /// IOCTL
        /// </summary>
        private const byte IOCTL_QUIT_COMMUNICATION = 0x81;
        private const byte IOCTL_SELECT_TARGET = 0x02;
        private const byte IOCTL_UNSELECT_TARGET = 0x03;
        private const byte IOCTL_GET_VAD_MAP = 0x41;

        private const byte IOCTL_MEMORY_DUMP_PAGE = 0x60;
        private const byte IOCTL_MEMORY_DUMP_VAD = 0x61;
        private const byte IOCTL_MEMORY_DUMP_ULONG_FLAGS = 0x62;
        private const byte IOCTL_MEMORY_DUMP_CA = 0x63;
        private const byte IOCTL_MEMORY_DUMP_SEGMENT = 0x64;
        private const byte IOCTL_MEMORY_DUMP_SUBSECTION = 0x65;

        private const byte IOCTL_MEMORY_DUMP_RANGE = 0x70;

        const byte IOCTL_FIND_OBJECT_UNICODE = 0x90;

        const byte IOCTL_FIND_PATTERN_UNICODE = 0xA0;
        const byte IOCTL_FIND_PATTERN_STRING = 0xA1;
        const byte IOCTL_FIND_PATTERN_SINGLELIST = 0xA2;
        const byte IOCTL_FIND_PATTERN_DOUBLELIST = 0xA3;

        const byte IOCTL_FIND_POINTER_UNICODE = 0xB0;
        const byte IOCTL_FIND_POINTER_STRING = 0xB1;

        const byte IOCTL_FIND_VALUE_UNICODE = 0xB5;
        const byte IOCTL_FIND_VALUE_STRING = 0xB6;
        const byte IOCTL_FIND_VALUE_NUMERIC = 0xB7;


        internal const string dllName = "MemoryExplorer.dll";
        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern byte ConnectToKernel();
        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern byte DisConnect();
        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern void CancelPendingIrp();
        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern byte ReadMessage(ref MESSAGE_ENTRY buffer);
        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.None, SetLastError = true)]
        private static extern byte SendControlMessage(byte control, uint message);
        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.None, SetLastError = true)]
        private static extern uint GetMemoryDump(byte type, uint startAddress, byte[] buffer);


        string[] WorkingSetSummaryName = new string[]
        {
            "Count",
            "FirstFree",  //Uint4B
            "FirstDynamic",  //Uint4B
            "LastEntry",  //Uint4B
            "NextSlot",  //Uint4B
            "Wsle",  //Ptr32 _MMWSLE
            "LowestPagableAddress",  //Ptr32 Void
            "LastInitializedWsle",  //Uint4B
            "NextAgingSlot",  //Uint4B
            "NumberOfCommittedPageTables",  //Uint4B
            "VadBitMapHint",  //Uint4B
            "NonDirectCount",  //Uint4B
            "LastVadBit",  //Uint4B
            "MaximumLastVadBit",  //Uint4B
            "LastAllocationSizeHint",  //Uint4B
            "LastAllocationSize",  //Uint4B
            "NonDirectHash",  //Ptr32 _MMWSLE_NONDIRECT_HASH
            "HashTableStart",  //Ptr32 _MMWSLE_HASH
            "HighestPermittedHashAddress"  //Ptr32 _MMWSLE_HASH
        };

        string[] ObjectType = new string[]
        {
            "",
            "",
            "Type",
            "Directory",
            "SymbolicLink",
            "Token",
            "Job",
            "Process",
            "Thread",
            "UserApcReserve",
            "IoCompletionReserve",
            "DebugObject",
            "Event",
            "EventPair",
            "Mutant",
            "Callback",
            "Semaphore",
            "Timer",
            "Profile",
            "KeyedEvent",
            "WindowStation",
            "Desktop",
            "TpWorkerFactory",
            "Adapter",
            "Controller",
            "Device",
            "Driver",
            "IoCompletion",
            "File",
            "TmTm",
            "TmTx",
            "TmRm",
            "TmEn",
            "Section",
            "Session",
            "Key",
            "ALPC Port",
            "PowerRequest",
            "WmiGuid",
            "EtwRegistration",
            "EtwConsumer",
            "FilterConnectionPort",
            "FilterCommunicationPort",
            "PcwObject"
    };





        delegate void AppendListCallback(ListView targetList, string[] entry);
        Thread CommunicationThread = null;
        bool quitCommunicationThread = false;
        private VadForm vadForm = null;

        internal byte[] memoryDump = new byte[4100];     // 최대 1페이지. + 첫 4바이트는 시작 주소.
        internal uint dumpStartAddress = 0;
        internal uint dumpLength = 0;

        private List<uint[]> workingSetList = new List<uint[]>();
        private List<ListViewItem> foundList = new List<ListViewItem>();
        private MESSAGE_TYPE foundType = MESSAGE_TYPE.Failed;
        private uint workingSetListCount = 0;
        
       // internal bool memoryManipulated = false;
        internal bool isErrorInVadDetails = false;
        internal bool refreshWholeVadMap = false;
        //internal bool isErrorInFinder = false;        // ShowDialog()로 했을 때는 메인 폼이 멈춰서 이런 식으로 값넘김이 안되는듯
        private bool isManipulated = false;

        /// <summary>
        /// Condition Configuration
        /// </summary>
        internal uint conditionStart = 0;
        internal uint conditionSize = 0;
        internal uint conditionLevel = 0;
        internal uint conditionString = 0;


        public fMain()
        {
            InitializeComponent();
        }

        private void fMain_Load(object sender, EventArgs e)
        {
            if (!InitDevice())
            {
                Dispose();
                Close();
            }
            else
            {
                if (!GetProcessList())
                {
                    bSelect.Text = "Refresh";
                }
                else
                {
                    CommunicationThread = new Thread(CommunicationFunction);
                    CommunicationThread.Start();
                    if((CommunicationThread == null) || ((CommunicationThread.ThreadState & System.Threading.ThreadState.Running) != System.Threading.ThreadState.Running))
                    {
                        MessageBox.Show("Starting Communication Thread is failed.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    
                }
                // 어짜피 드라이버 내에서 내가 프로세스 리스트 뽑는 방식이, 스텔스 프로세스 못찾음............
                //Thread queryThread = new Thread(QueryProcessList);
                //queryThread.Start();
                //queryThread.Join();
                
            }
        }


        /// <summary>
        /// Byte 배열에서 구조체 형식으로 추출
        /// </summary>
        internal object ByteToStructure(byte[] buffer, Type type, uint arrayCount = 0)
        {
            if (type == null)
                return null;
            
            int typeLength = Marshal.SizeOf(type);          
            

            IntPtr buff = Marshal.AllocHGlobal(typeLength); // 구조체의 크기만큼 비관리 메모리 영역에 메모리를 할당한다.
            Marshal.Copy(buffer, (int)(arrayCount * typeLength), buff, typeLength); // 배열에 저장된 데이터를 위에서 할당한 메모리 영역에 복사한다.
            object obj = Marshal.PtrToStructure(buff, type); // 복사된 데이터를 구조체 객체로 변환한다.
            
            Marshal.FreeHGlobal(buff); // 비관리 메모리 영역에 할당했던 메모리를 해제함            

            if (Marshal.SizeOf(obj) != typeLength)
            {
                return null; // 크기가 다르면 null 리턴
            }

            return obj; // 구조체 리턴

        }

        private void HandleTableMaker(HANDLE_ENTRY buffer)
        {
            if (buffer.HandleNumber == 4)
            {
                // Handle Table 정보인 경우.
                   //   -> Type : handle count
                   //   -> GrantedAccess : Flags
           //         tabControl1.TabPages[4].Text = ("Handles [" + buffer.Type.ToString() + "]");
                lHandles.Items.Clear();
            }
            else if(buffer.HandleNumber == 0xFFFFFFFF)
            {
                tabControl1.TabPages[4].Text = "Handles";
                lHandles.Items.Clear();
                MessageBox.Show("Failed to get the Handle table.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            string[] entry = new string[lHandles.Columns.Count];

            entry[0] = String.Format("0x{0:X}", buffer.HandleNumber);
            entry[1] = String.Format("0x{0:X8}", buffer.EntryAddress);
            if(buffer.FileObject == 0xFFFFFFFF)
            {
                entry[2] = " - ";
                entry[3] = "  ##  Free";
                entry[4] = " - ";
                entry[5] = " - ";
                    
            }
            else{
                byte type = (byte)((buffer.Type) & 0x000000FF);
                if ((type > 1) && (type < 44))
                    entry[2] = ObjectType[type];

                if (buffer.Name.Length > 0)
                    entry[3] = buffer.Name;


                entry[4] = String.Format("0x{0:X8}", buffer.FileObject);
                entry[5] = String.Format("0x{0:X8}", buffer.GrantedAccess);
            }

            AppendList(lHandles, entry);
            
        }


        private void VadMapMaker(VAD_MAP buffer)
        {
            if(buffer.Vad == 0)
            {
                // 무조건 보내서 EOF임을 알려주고[pVadMap->Vad == 0], 
                // 성공이라면 pVadMap->isShared == TRUE, pVadMap->Commit = 총 VAD 갯수.
                if (buffer.isPrivate)
                {
                    tabControl1.TabPages[1].Text += ("[" + buffer.Commit.ToString() + "]");
                    if (isErrorInVadDetails)
                        isErrorInVadDetails = false;
                }
                else
                {
                    DialogResult result = MessageBox.Show("Failed to get the whole VAD MAP.\n Try Later", "Error", MessageBoxButtons.RetryCancel, MessageBoxIcon.Error);
                    if(result == DialogResult.Retry)
                    {
                        lMap.Items.Clear();
                        if(SendControlMessage(IOCTL_GET_VAD_MAP, (uint)0) == 0)
                        {
                            MessageBox.Show("SendControlMessage() is failed", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                    return;
                }

            }
            else
            {
                string[] entry = new string[lMap.Columns.Count];

                entry[0] = String.Format("0x{0:X8}", buffer.Vad);
                entry[1] = String.Format("{0}", buffer.Level);
                entry[2] = String.Format("{0:X}", buffer.Start);
                entry[3] = String.Format("{0:X}", buffer.End);
                entry[4] = String.Format("{0}", buffer.Commit);
                if (buffer.isPrivate)
                    entry[5] = String.Format("Private");
                else
                    entry[5] = String.Format("Mapped");

                if (buffer.FileName.Length > 0)
                    entry[6] = buffer.FileName;

                AppendList(lMap, entry);
            }
        }

        private void ProcessInfoMaker(PROCESS_INFO buffer)
        {
            lInfo.Items.Clear();

            string[] entry = new string[2];

            if (buffer.ImageFullName.Length > 0)
            {
                entry[0] = "Image File Name";
                entry[1] = buffer.ImageFullName;
                AppendList(lInfo, entry);
            }
            if (buffer.ProcessId != 0)
            {
                entry[0] = "Process ID";
                entry[1] = String.Format("{0}", buffer.ProcessId);
                AppendList(lInfo, entry);
            }
            if (buffer.Eprocess != 0)
            {
                entry[0] = "EPROCESS";
                entry[1] = String.Format("0x{0:X8}", buffer.Eprocess);
                AppendList(lInfo, entry);
            }
            if (buffer.Peb != 0)
            {
                entry[0] = "PEB";
                entry[1] = String.Format("0x{0:X8}", buffer.Peb);
                AppendList(lInfo, entry);
            }
            if (buffer.HandleTable != 0)
            {
                entry[0] = "Handle Table";
                entry[1] = String.Format("0x{0:X8}", buffer.HandleTable);
                AppendList(lInfo, entry);
            }
            if (buffer.ThreadListHead != 0)
            {
                entry[0] = "Thread List Head";
                entry[1] = String.Format("0x{0:X8}", buffer.ThreadListHead);
                AppendList(lInfo, entry);
            }
            if (buffer.DirectoryTableBase != 0)
            {
                entry[0] = "Directory Table Base";
                entry[1] = String.Format("0x{0:X8}", buffer.DirectoryTableBase);
                AppendList(lInfo, entry);
            }
            if (buffer.VadRoot != 0)
            {
                entry[0] = "VAD Root";
                entry[1] = String.Format("0x{0:X8}", buffer.VadRoot);
                AppendList(lInfo, entry);
            }
        }

        private void FinderListing(uint type, FINDER_ENTRY buffer)
        {
            if (type == (uint)(MESSAGE_TYPE.End_Of_Finder)){
                // Address2 : The Number of the failed page. 
                //    -> 0 : No Failed.
                if (buffer.Address2 > 0)
                {
                    //First, Keep the received Items.
                    MessageBox.Show("Failed to search the whole target range.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                foundType = (MESSAGE_TYPE)(buffer.Length);
                lFinder.VirtualListSize = foundList.Count;
                return;
            }
            else
            {
                if ((buffer.Length > 0) && (buffer.Contents.Length > 0))
                {

                    //foundList.Add(buffer);

                    string[] entry = new string[lFinder.Columns.Count];
                    entry[0] = (foundList.Count + 1).ToString();

                    switch (type)
                    {
                        case (uint)(MESSAGE_TYPE.Object_Unicode):
                            entry[1] = String.Format("0x{0:X8}", buffer.Address2);
                            entry[2] = String.Format("0x{0:X4}", (buffer.Length & 0xFFFF));
                            entry[3] = String.Format("0x{0:X4}", (buffer.Length >> 16));     // UNICODE_STRING::MaximumLength
                            entry[4] = String.Format("0x{0:X8}", buffer.Address);
                            entry[5] = buffer.Contents;
                            if ((entry[5].Length * 2) < (buffer.Length & 0xFFFF))
                                entry[5] += "[+]";
                            break;
                        case (uint)(MESSAGE_TYPE.Pattern_Unicode):
                        case (uint)(MESSAGE_TYPE.Pattern_String):
                            entry[1] = String.Format("0x{0:X8}", buffer.Address);
                            entry[2] = String.Format("0x{0:X4}", buffer.Length);
                            entry[3] = buffer.Contents;

                            // Connected to the next page.
                            if ((buffer.Address2 & 0x80000000) == 0x80000000)
                                entry[2] += "[C]";

                            // Over 100.
                            if ((buffer.Address2 & 0x1) == 0x1)
                                entry[3] += "[+]";

                            break;
                        default:
                            return;
                    }
                    //AppendList(lFinder, entry);

                    foundList.Add(new ListViewItem(entry));
                }
            }            
        }

        private ListViewItem MakeVirtualItemForWorkingSet(int i)
        {
            string[] tmp = new string[3];
            uint value = workingSetList[i / 256][i % 256];

            tmp[0] = String.Format("0x{0:X4}", i);
            if (value > 0)
            {
                if ((value & 0x1) == 0)
                {
                    tmp[1] = " ## Free   ";
                    tmp[1] += String.Format("Next : 0x{0:X5}   ", ((value & 0xFFFFF000) >> 12));
                    tmp[1] += String.Format("Prev : 0x{0:X}", ((value & 0xFFE) >> 1));       // Just same 11Bit with Previous Free Entry...
                }
                else
                {
                    tmp[1] = String.Format("VPN : 0x{0:X5}   ", ((value & 0xFFFFF000) >> 12));
                    tmp[1] += String.Format("Age : {0}   ", ((value & 0xE00) >> 9));
                    tmp[1] += String.Format("Protection : 0x{0:X}", ((value & 0x1F0) >> 4));
                    if ((value & 0x40) != 0)
                    {
                        tmp[1] += String.Format("   [Direct");
                        if ((value & 0x20) != 0)
                            tmp[1] += String.Format(", Hashed");
                        tmp[1] += "]";
                    }
                    else
                    {
                        if ((value & 0x20) != 0)
                            tmp[1] += String.Format("   [Hashed]");
                    }                        
                }
                tmp[2] = String.Format("0x{0:X8}", value);
            }
            else
            {
                tmp[1] = "!!! ERROR !!!";
                tmp[2] = "!!! ERROR !!!";
            }
            return new ListViewItem(tmp);
        }

        private void WorkingSetMaker(MESSAGE_ENTRY buffer) {

            uint i = 0;

            switch ((uint)(buffer.MessageType))
            {
                case (uint)(MESSAGE_TYPE.WorkingSetList):
                    uint[] list = new uint[256];
                    
                    for (i = 0; i < 256; i++)
                    {
                        list[i] = (uint)(ByteToStructure(buffer.Buffer, typeof(uint), i));
                        if (list[i] == 0)
                            break;

                        workingSetListCount++;
                    }

                    if (list[0] != 0)
                    {
                        workingSetList.Add(list);
                        lWorkingSetList.VirtualListSize = (int)workingSetListCount;
                    }

                    ////        -> Change to VIRTUAL MODE.
                    //entry = new string[lWorkingSetList.Columns.Count];
                    //uint value = 0;
                    //int lastIndex = 0;

                    //if (lWorkingSetList.Items.Count > 0)
                    //    lastIndex = lWorkingSetList.Items.Count;
                    //while(i < 256)
                    //{
                    //    value = (uint)(ByteToStructure(buffer.Buffer, typeof(uint), i));
                    //    i++;

                    //    if (value == 0)
                    //        break;

                    //    if (value % 2 == 0)
                    //        continue;

                    //    entry[0] = String.Format("0x{0:X4}", i + lastIndex);
                    //    entry[1] = String.Format("0x{0:X8}", value);
                    //    entry[2] = String.Format("0x{0:X8}", value);

                    //    lWorkingSetList.Items.Add(new ListViewItem(entry));

                    //}
                    break;
                case (uint)(MESSAGE_TYPE.WorkingSetSummary):
                    lWorkingSetSummary.Items.Clear();
                    lWorkingSetList.Items.Clear();
                    workingSetList.Clear();
                    workingSetListCount = 0;
                    lWorkingSetList.VirtualListSize = 0;


                    string[] entry = new string[lWorkingSetSummary.Columns.Count];
                    for (i = 0; i < WorkingSetSummaryName.Length; i++)
                    {
                        entry[0] = WorkingSetSummaryName[i];
                        entry[1] = String.Format("0x{0:X8}", (uint)(ByteToStructure(buffer.Buffer, typeof(uint), i)));

                        lWorkingSetSummary.Items.Add(new ListViewItem(entry));
                    }
                    break;
                default:
                    return;
            }
        }

        private void CommunicationFunction()
        {
            MESSAGE_ENTRY buffer;
            while (!quitCommunicationThread)
            {
                buffer = new MESSAGE_ENTRY();

                if (ReadMessage(ref buffer) == 1)
                {
                    try
                    {
                        switch (buffer.MessageType)
                        {
                            case (uint)(MESSAGE_TYPE.Failed):
                                MessageBox.Show("Error occured in Driver", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                                break;
                            case (uint)(MESSAGE_TYPE.ProcessInfo):
                                ProcessInfoMaker((PROCESS_INFO)(ByteToStructure(buffer.Buffer, typeof(PROCESS_INFO))));
                                break;
                            case (uint)(MESSAGE_TYPE.Vad):
                                VadMapMaker((VAD_MAP)(ByteToStructure(buffer.Buffer, typeof(VAD_MAP))));
                                break;
                            case (uint)(MESSAGE_TYPE.Handles):
                                HandleTableMaker((HANDLE_ENTRY)(ByteToStructure(buffer.Buffer, typeof(HANDLE_ENTRY))));
                                break;
                            case (uint)(MESSAGE_TYPE.Object_Unicode):
                            case (uint)(MESSAGE_TYPE.Pattern_Unicode):
                            case (uint)(MESSAGE_TYPE.Pattern_String):
                            case (uint)(MESSAGE_TYPE.End_Of_Finder):
                                FinderListing(buffer.MessageType, (FINDER_ENTRY)(ByteToStructure(buffer.Buffer, typeof(FINDER_ENTRY))));
                                break;
                            case (uint)(MESSAGE_TYPE.WorkingSetSummary):
                            case (uint)(MESSAGE_TYPE.WorkingSetList):
                                WorkingSetMaker(buffer);
                                break;
                            default:
                                MessageBox.Show("Invalid Message Type.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                                break;
                        }
                    }
                    catch (FileNotFoundException)
                    {
                        MessageBox.Show("Converting to structure is failed" + "[" + (MESSAGE_TYPE)(buffer.MessageType) + "].", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        continue;
                    }
                }
                else
                {
                    if (!quitCommunicationThread)
                    {
                        MessageBox.Show("Error occured in Communication Thread.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);

                        return;
                    }                        
                }
            }
            quitCommunicationThread = false;
            return; 
        }

        private bool GetProcessList()
        {
            cProcesses.Items.Clear();
            cProcesses.Text = "";

            Process[] processList = Process.GetProcesses();
            if (processList.Length > 1)
            {
                foreach (Process currentEntry in processList)
                {
                    if(currentEntry.Id != 0)
                        cProcesses.Items.Add(currentEntry.ProcessName + " [" + currentEntry.Id.ToString() + "]");
                }

                cProcesses.Sorted = true;
                return true;
            }
            else
            {
                MessageBox.Show("Failed to refresh.\nTry Again.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
                
            
        }


        private bool InitDevice()
        {
            int errCode = 0;

            if (!(File.Exists("loader.dll")))
            {
                MessageBox.Show("[ loader.dll ] is not found", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            else {
                if (!(File.Exists(dllName)))
                {
                    MessageBox.Show("[ " + dllName + " ] is not found", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return false;
                }
                else {
                    if (ConnectToKernel() == 0)
                    {
                        errCode = Marshal.GetLastWin32Error();

                        if (errCode == 5)
                            MessageBox.Show("Restart this program with ADMINISTRATOR Account.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        else
                            MessageBox.Show("Connecting to Kernel is failed [" + String.Format("ErrCode : {0:d}", errCode) + "]", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return false;
                    }
                    else
                        return true;
                }
            }

            
        }

        private void AppendList(ListView targetList, string[] entry)
        {
            if (targetList.InvokeRequired)
            {
                AppendListCallback d = new AppendListCallback(AppendList);
                this.Invoke(d, new object[] { targetList, entry });     // 아무리 파라미터가 한 개라도, object[]로 감싸야 한다.
            }
            else
            {
                ListViewItem current = targetList.Items.Add(new ListViewItem(entry));
                
            }
        }

        private void fMain_FormClosing(object sender, FormClosingEventArgs e)
        {
            if((CommunicationThread != null) && ((CommunicationThread.ThreadState & System.Threading.ThreadState.Running) == System.Threading.ThreadState.Running)){
                quitCommunicationThread = true;
                CancelPendingIrp();
            }

            if (DisConnect() == 1)
            {
                Dispose();
                Close();
            }

        }

        private void bSelect_Click(object sender, EventArgs e)
        {
            uint targetPID = 0;

            if (bSelect.Text == "Select")
            {
                if(cProcesses.SelectedItem == null)
                {
                    MessageBox.Show("Select target process.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    cProcesses.DroppedDown = true;
                    cProcesses.Focus();
                    return;
                }
                else
                {
                    targetPID = (Convert.ToUInt32(cProcesses.Text.Split(new char[] { '[', ']' })[1]));

                    lMap.Items.Clear();
                    tabControl1.TabPages[1].Text = "VAD Map";

                    if (bUseHistory.Checked)
                        targetPID |= 0x80000000;

                    if (SendControlMessage(IOCTL_SELECT_TARGET, targetPID) == 1){
                        bSelect.BackColor = Color.LightCoral;
                        bSelect.Text = "UnSelect";
                        cProcesses.Enabled = false;
                    }
                    else
                    {
                        MessageBox.Show("SendControlMessage() is failed.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
            else if(bSelect.Text == "Refresh")
            {

                if (GetProcessList())
                {
                    bSelect.Text = "Select";
                }
            }
            else
            {       
                // Unselect with Colors.LightCoral
                // Select whether restore corruption or not.
                if (isManipulated)
                {
                    DialogResult result = MessageBox.Show("If manipulated remains, System Crash may occur.\r\nRestore it?", "Warning", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                    if (result == DialogResult.Yes)
                        targetPID = 1;

                    isManipulated = false;
                }

                lFinder.VirtualListSize = 0;
                foundList.Clear();
                lFinder.Items.Clear();
                lFinder.Columns.Clear();

                lWorkingSetSummary.Items.Clear();
 
                lWorkingSetList.VirtualListSize = 0;
                lWorkingSetList.Items.Clear();
                workingSetListCount = 0;
                workingSetList.Clear();

                // First, Keep it.
                //lDump.VirtualListSize = 0;
                //lDump.Items.Clear();

                if (SendControlMessage(IOCTL_UNSELECT_TARGET, targetPID) == 0)
                {
                    MessageBox.Show("TARGET_OBJECT in Driver is not exist.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }

                // 이게 실패할 경우는, 드라이버에 TARGET_OBJECT 가 없는 경우 뿐. 
                //       -> 어디선가 동기화가 잘못된거니, 그냥 애플리케이션도 UNSELCT 상태인 것으로 만들자.
                bSelect.BackColor = SystemColors.Control;
                bSelect.Text = "Select";
                cProcesses.Enabled = true;
            }
        }

        private void bRefresh_Click(object sender, EventArgs e)
        {
            if (cProcesses.Enabled)
            {
                if (!GetProcessList())
                {
                    bSelect.Text = "Refresh";
                }
            }
            else {
                MessageBox.Show("Refresh after unselect current process.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
        }

        private void bRestartThread_Click(object sender, EventArgs e)
        {
            if((CommunicationThread.ThreadState & System.Threading.ThreadState.Running) == System.Threading.ThreadState.Running)
            {
                quitCommunicationThread = true;
                if(SendControlMessage(IOCTL_QUIT_COMMUNICATION, 0) == 1){
                    MessageBox.Show("Communication Thread is Terminated.");
                }
                else
                {
                    MessageBox.Show("Failed to quit Thread.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }

            CommunicationThread = new Thread(CommunicationFunction);
            CommunicationThread.Start();
            if((CommunicationThread.ThreadState & System.Threading.ThreadState.Running) != System.Threading.ThreadState.Running)
            {
                MessageBox.Show("Failed to start the communication Thread.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
        }

        private void lMap_SelectedIndexChanged(object sender, EventArgs e)
        {
            if((lMap.SelectedItems.Count == 1) && (!isErrorInVadDetails) && (lMap.SelectedItems[0].BackColor != Color.LightCoral))
            {
                uint selectedVad = 0;
                try
                {
                   selectedVad = uint.Parse((lMap.SelectedItems[0].SubItems[0].Text.Remove(0, 2)), System.Globalization.NumberStyles.HexNumber);
                }
                catch(Exception)
                {
                    MessageBox.Show("Convert Error.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if ((vadForm == null) || (vadForm.IsDisposed))
                {
                    vadForm = new VadForm(selectedVad, this, 0);
                    vadForm.Show();
                }
                else
                {
                    //while (!(vadForm.isProcessing))
                    //    Thread.Sleep(10);
                    if(!(vadForm.isProcessing))
                        vadForm.ChangeVad(selectedVad);

                    // 여기서 에러 발생이란, 해당 VAD가 해제됐음을 의미.
                       //   -> 에러 발생한 VAD 표시만 하고 넘어갔으나, 연쇄적인 해제 VAD 발생.
                       //       -> 그냥 에러가 한 번이라도 발생하면, 전체 VAD Entry 새로 받아오자.
                       //           -> 그냥 선택하는 걸로.....
                    if (isErrorInVadDetails)
                    {
                        if (refreshWholeVadMap){
                            refreshWholeVadMap = false;

                            lMap.Items.Clear();
                            tabControl1.TabPages[1].Text = "VAD Map";
                            if (SendControlMessage(IOCTL_GET_VAD_MAP, 0) == 0)
                            {
                                MessageBox.Show("Failed to communicate with Driver.\nTry later...", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                        }
                        else
                        {
                            isErrorInVadDetails = false;

                            lMap.SelectedItems[0].BackColor = Color.LightCoral;
                        }
                    }
                }
            }
        }

        private void MovedForm(object sender, EventArgs e)
        {
            if((this.WindowState == FormWindowState.Normal) && (vadForm != null) && !(vadForm.IsDisposed))
            {
                vadForm.MovingForm();
            }
        }


        ////////////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////       Dump        ////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////
        internal string ToAscii_HEX(Byte data)  // Output Ver.Hex 일 때의 변환
        {
            if (data >= 0x20 && data <= 0x7E)
                return string.Format(" {0}", (char)data);
            else
                return " .";
        }

        // memoryDump[] 의 첫 4바이트는 덤프의 시작 주소.
        private ListViewItem MakeVirtualItemForDump(int i)
        {
            string[] tmp = new string[3];

            tmp[0] = string.Format("{0:X8}", dumpStartAddress + (i * 0x10));
            for (int j = 0; j < 16; j++)
            {
                if (j == 8)
                    tmp[1] += "  ";
                tmp[1] += string.Format(" {0:X2}", memoryDump[(i * 16) + j + 4]);
                tmp[2] += ToAscii_HEX(memoryDump[(i * 16) + j + 4]);
                if ((i * 16) + j + 1 == dumpLength)
                    break;
            }
            return new ListViewItem(tmp);
        }

        internal void ShowMemoryDump(uint address, byte type, byte secondType)
        {
            memoryDump.Initialize();

            if ((address != 0) && (type != 0))
            {
                // secondType은 0이건 아니건, 일단 넣자.
                memoryDump[0] = secondType;

                // Range인 경우.   // &memoryDump[1]을 PULONG으로 해서 length값 넣자.
                if(type == IOCTL_MEMORY_DUMP_RANGE)
                {
                    memoryDump[1] = (byte)(dumpLength & 0x000000FF);
                    memoryDump[2] = (byte)((dumpLength & 0x0000FF00) >> 8);
                    memoryDump[3] = (byte)((dumpLength & 0x00FF0000) >> 16);
                    memoryDump[4] = (byte)((dumpLength & 0xFF000000) >> 24);
                }

                dumpLength = GetMemoryDump(type, address, memoryDump);
                if(dumpLength == 0)
                {
                    dumpStartAddress = 0;
                    dumpLength = 0;
                    MessageBox.Show("Can't get the dump data.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    // memoryDump[]의 첫 4바이트는 덤프 시작 주소.
                    dumpStartAddress = memoryDump[0];
                    dumpStartAddress += (uint)(memoryDump[1] << 8);
                    dumpStartAddress += (uint)(memoryDump[2] << 16);
                    dumpStartAddress += (uint)(memoryDump[3] << 24);

                    dumpLength = dumpLength - 4;

                    uint line = dumpLength / 16;
                    if (dumpLength % 16 != 0)
                        line++;

                    lDump.VirtualListSize = (int)line;
                    lDump.Refresh();
                    tabControl1.SelectedIndex = 5;
                    return;
                }                    
            }

            ////////////////////////     Failed...
            lDump.VirtualListSize = 0;
            lDump.Items.Clear();
            return;
        }

        private void lDump_RetrieveVirtualItem(object sender, RetrieveVirtualItemEventArgs e)
        {
            if(lDump.VirtualListSize > 0)
            {
                try
                {
                    e.Item = MakeVirtualItemForDump(e.ItemIndex);
                }
                catch
                {
                    lDump.VirtualListSize = 0;
                    lDump.Items.Clear();
                }
            }
        }

        private void bManipulate_Click(object sender, EventArgs e)
        {
            if (lDump.SelectedIndices.Count == 0)
            {
                MessageBox.Show("Select a line.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            ListViewItem selected = lDump.Items[lDump.SelectedIndices[0]];
            uint address = 0;
            uint count = 0;
            try
            {
                address = uint.Parse(selected.SubItems[0].Text, System.Globalization.NumberStyles.HexNumber);
                count = (uint)(selected.SubItems[1].Text.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)).Length;
            }
            catch (Exception err)
            {
                MessageBox.Show(err.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            Form manipulateForm = null;
            if (((ToolStripMenuItem)sender).Text == "by Direct")
            {
                manipulateForm = new Editor(this, address, count);

            }
            else if (((ToolStripMenuItem)sender).Text == "by Editor")
            {
                manipulateForm = new IndirectInput(this, address, dumpLength + dumpStartAddress - address, selected.SubItems[1].Text.Trim());
            }
            else
                return;


            if (!isManipulated)
            {
                MessageBox.Show("If manipulate, System Crash may occur.\r\nFirst, Save All Work In Progress.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                isManipulated = true;
            }

            DialogResult result = manipulateForm.ShowDialog();
            if (result == DialogResult.OK)
            {
                ShowMemoryDump(dumpStartAddress, IOCTL_MEMORY_DUMP_RANGE, 0);
             }
            else
            {
                return;
            }

        }

        private void bObjectUnicode_Click(object sender, EventArgs e)
        {
            if(bSelect.Text != "UnSelect")
            {
                MessageBox.Show("First, Select a Target Process.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            
            lFinder.VirtualListSize = 0;
            foundList.Clear();
            lFinder.Items.Clear();
            lFinder.Columns.Clear();

            lFinder.Columns.Add("", 30);
            lFinder.Columns.Add("Address", 100);
            lFinder.Columns.Add("Length", 80);
            lFinder.Columns.Add("MaxL", 80);
            lFinder.Columns.Add("Buffer", 100);
            lFinder.Columns.Add("Contents", 400);


            ConditionConfiguration configForm = new ConditionConfiguration(this, IOCTL_FIND_OBJECT_UNICODE, "Finder");
            DialogResult result = configForm.ShowDialog();

            if (result == DialogResult.OK)
            {
                conditionStart = configForm.returnStart;
                conditionSize = configForm.returnSize;
                conditionLevel = configForm.returnLevel;

                tabControl1.SelectedIndex = 6;
            }
            else if(result == DialogResult.Cancel)
            {
                return;
            }
            else if(result == DialogResult.Abort)
            {
                MessageBox.Show("Selected Range of Memory is not allocated or ACCESS_VIOLATION...", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void bDump_Click(object sender, EventArgs e)
        {
            if (tDump.Text.Trim().Length > 0)
            {
                uint vpn = 0;

                try
                {
                    vpn = uint.Parse(tDump.Text.Trim(), System.Globalization.NumberStyles.HexNumber);
                }
                catch
                {
                    MessageBox.Show("Input a Virtual Page Number in HEX.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    tDump.Focus();
                    tDump.SelectAll();
                    return;
                }

                ShowMemoryDump(vpn * 4096, IOCTL_MEMORY_DUMP_PAGE, 0);
            }
            else
            {
                MessageBox.Show("Input a Virtual Page Number in HEX.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                tDump.Focus();
                tDump.SelectAll();
                return;
            }
        }

        private void tDump_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)13)   // Enter 의 키 코드
            {
                this.bDump_Click(this, null);
            }
        }


        private void addressTranslatorToolStripMenuItem_Click(object sender, EventArgs e)
        {
    
            if (bSelect.Text == "UnSelect")
            {
                ConditionConfiguration configForm = new ConditionConfiguration(this, 0, "Translator");
                DialogResult result = configForm.ShowDialog();

                if (result == DialogResult.OK)
                {
                    conditionStart = configForm.returnStart;

                    if ((vadForm == null) || (vadForm.IsDisposed))
                    {
                        vadForm = new VadForm(conditionStart, this, 1);
                        vadForm.Show();
                    }
                    else
                    {
                        vadForm.ChangeVirtualAddress(conditionStart);
                        vadForm.Focus();
                    }
                        
                }
                else
                    return;

            }
            else
            {
                MessageBox.Show("First, Select a Target Process.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

        }

        private void lWorkingSetList_RetrieveVirtualItem(object sender, RetrieveVirtualItemEventArgs e)
        {
            if(lWorkingSetList.VirtualListSize > 0)
            {
                try
                {
                    e.Item = MakeVirtualItemForWorkingSet(e.ItemIndex);
                }
                catch
                {

                    lWorkingSetList.VirtualListSize = 0;
                    workingSetListCount = 0;
                    workingSetList.Clear();
                    lWorkingSetList.Items.Clear();
                }
            }
        }

        private void lWorkingSetList_SelectedIndexChanged(object sender, EventArgs e)
        {
            if(this.bSelect.Text == "UnSelect")
            {
                if (lWorkingSetList.SelectedIndices.Count == 1)
                {
                    ListViewItem selected = lWorkingSetList.Items[lWorkingSetList.SelectedIndices[0]];
                    if (selected.SubItems[1].Text.Contains("VPN"))
                    {
                        uint vpn = 0;
                        try
                        {
                            vpn = uint.Parse(selected.SubItems[2].Text.Split(new char[] { 'x' })[1], System.Globalization.NumberStyles.HexNumber);
                            vpn = (vpn & 0xFFFFF000);
                        }
                        catch (Exception)
                        {
                            return;
                        }

                        if ((vadForm == null) || (vadForm.IsDisposed))
                        {
                            vadForm = new VadForm(vpn, this, 1);
                            vadForm.Show();
                        }
                        else
                        {
                            if (!(vadForm.isProcessing))
                            {
                                vadForm.ChangeVirtualAddress(vpn);
                                //vadForm.Focus();
                            }
                        }
                    }
                }
            }            
        }

        private void tabControl1_SelectedIndexChanged(object sender, EventArgs e)
        {
            string tab = tabControl1.TabPages[tabControl1.SelectedIndex].Text.Split(new char[] { ' ' })[0];

            switch (tab)
            {
                case "VAD":
                    lMap.Focus();
                    break;
                case "Dump":
                    tDump.Focus();
                    tDump.SelectAll();
                    break;
                case "Handles":
                    lHandles.Focus();
                    break;
                default:
                    return;
            }


        }

        private void bPatternString_Click(object sender, EventArgs e)
        {
            if (bSelect.Text != "UnSelect")
            {
                MessageBox.Show("First, Select a Target Process.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            byte type = 0;
            switch (((ToolStripMenuItem)sender).Text)
            {
                case "Ascii String":
                    type = IOCTL_FIND_PATTERN_STRING;
                    break;
                case "Unicode String":
                    type = IOCTL_FIND_PATTERN_UNICODE;
                    break;
                default:
                    return;
            }

            lFinder.VirtualListSize = 0;
            foundList.Clear();
            lFinder.Items.Clear();
            lFinder.Columns.Clear();

            lFinder.Columns.Add("", 30);
            lFinder.Columns.Add("Address", 100);
            lFinder.Columns.Add("Length", 80);
            lFinder.Columns.Add("Contents", 400);
            
            ConditionConfiguration configForm = new ConditionConfiguration(this, type, "Finder");
            DialogResult result = configForm.ShowDialog();
            
            if (result == DialogResult.OK)
            {
                conditionStart = configForm.returnStart;
                conditionSize = configForm.returnSize;
                conditionLevel = configForm.returnLevel;
                
                tabControl1.SelectedIndex = 6;
            }
            else if (result == DialogResult.Cancel)
            {
                return;
            }
            else if (result == DialogResult.Abort)
            {
                MessageBox.Show("Selected Range of Memory is not allocated or ACCESS_VIOLATION...", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void bValueString_Click(object sender, EventArgs e)
        {

            if (bSelect.Text != "UnSelect")
            {
                MessageBox.Show("First, Select a Target Process.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            byte type = 0;
            switch (((ToolStripMenuItem)sender).Text)
            {
                case "Ascii String":
                    type = IOCTL_FIND_VALUE_STRING;
                    break;
                case "Unicode String":
                    type = IOCTL_FIND_VALUE_UNICODE;
                    break;
                default:
                    return;
            }

            lFinder.VirtualListSize = 0;
            foundList.Clear();
            lFinder.Items.Clear();
            lFinder.Columns.Clear();

            lFinder.Columns.Add("", 30);
            lFinder.Columns.Add("Address", 100);
            lFinder.Columns.Add("Length", 80);
            lFinder.Columns.Add("Contents", 400);
            

            ConditionConfiguration configForm = new ConditionConfiguration(this, type, "Finder");
            DialogResult result = configForm.ShowDialog();

            if (result == DialogResult.OK)
            {
                conditionStart = configForm.returnStart;
                conditionSize = configForm.returnSize;
                conditionLevel = configForm.returnLevel;

                tabControl1.SelectedIndex = 6;
            }
            else if (result == DialogResult.Cancel)
            {
                return;
            }
            else if (result == DialogResult.Abort)
            {
                MessageBox.Show("Selected Range of Memory is not allocated or ACCESS_VIOLATION...", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private ListViewItem MakeVirtualItemForFinder(int index)
        {
            //FINDER_ENTRY buffer = foundList[index];
            //string[] entry = new string[lFinder.Columns.Count];
            //entry[0] = (index + 1).ToString();

            //switch ((uint)foundType)
            //{
            //    case (uint)(MESSAGE_TYPE.Object_Unicode):
            //        entry[1] = String.Format("0x{0:X8}", buffer.Address2);
            //        entry[2] = String.Format("0x{0:X4}", (buffer.Length & 0xFFFF));
            //        entry[3] = String.Format("0x{0:X4}", (buffer.Length >> 16));     // UNICODE_STRING::MaximumLength
            //        entry[4] = String.Format("0x{0:X8}", buffer.Address);
            //        //entry[5] = buffer.Contents;
            //        //if ((entry[5].Length * 2) < (buffer.Length & 0xFFFF))
            //        //    entry[5] += "[+]";
            //        break;
            //    case (uint)(MESSAGE_TYPE.Pattern_Unicode):
            //    case (uint)(MESSAGE_TYPE.Pattern_String):
            //        entry[1] = String.Format("0x{0:X8}", buffer.Address);
            //        entry[2] = String.Format("0x{0:X4}", buffer.Length);
            //        entry[3] = buffer.Contents;

            //        // Connected to the next page.
            //        if ((buffer.Address2 & 0x80000000) == 0x80000000)
            //            entry[2] += "[C]";

            //        // Over 100.
            //        if ((buffer.Address2 & 0x1) == 0x1)
            //            entry[3] += "[+]";

            //        break;
            //    default:
            //        break;
            //}

            //// For Test.......
            //// entry[1] = lFinder.VirtualListSize.ToString();

            //return new ListViewItem(entry);
            
            return (foundList[index]);
        }

        private void lFinder_RetrieveVirtualItem(object sender, RetrieveVirtualItemEventArgs e)
        {
            if (lFinder.VirtualListSize > 0)
            {
                try
                {
                    e.Item = MakeVirtualItemForFinder(e.ItemIndex);
                }
                catch (Exception eerr)
                {
                    MessageBox.Show(eerr.ToString(), e.ItemIndex.ToString(), MessageBoxButtons.OK, MessageBoxIcon.Error);
                    lFinder.VirtualListSize = 0;
                    foundList.Clear();
                    lFinder.Items.Clear();
                }
            }
           
        }
        

        // END
    }
}
