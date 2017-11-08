/*

    [주의]

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
        public struct MESSAGE_ENTRY
        {
        public uint MessageType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        public byte[] Buffer;
        }
            -> 이런 형식의 구조체를 생성할 경우에, 애플리케이션 단에서 Buffer 배열에 값을 넣어야 할 경우.
               할당부터 따로 해주고 넣어야 한다.

                message.Buffer = new byte[1024];        // 애플리케이션 내에서 값 넣기 전엔, 항상 할당부터....
                message.Buffer.Initialize();
                message.Buffer[0] = (byte)(details.NumberOfSubsection);
        
            -> 할당하지 않고 값 대입 시, 
                " 개체 참조가 개체의 인스턴스로 설정되지 않았습니다." 오류 발생함.


*/




using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace MemoryExplorer
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.None, Pack = 1)]
    public struct VAD_DETAILS_SUBSECTION
    {
        public uint SubsectionAddress;
        public uint BasePTE;
        public uint PtesInSubsection;
        public uint UnusedPtes;
        public uint Flags;
        public uint StartingSector;
        public uint NumberOfFullSectors;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.None, Pack = 1)]
    public struct PFN_DETAILS
    {
        public uint DirBase;
        public uint PDPTAddress;
        public uint PDPEAddress;
        public ulong PDPEValue;
        public uint PDTAddress;
        public uint PDEAddress;
        public ulong PDEValue;
        public uint PTAddress;
        public uint PTEAddress;
        public ulong PTEValue;
        //public ulong PhysicalAddress;     // 나누자...
        public uint LOPhysicalAddress;
        public uint HIPhysicalAddress;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 28)]
        byte[] PDTPfnDatabase;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 28)]
        byte[] PTPfnDatabase;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 28)]
        byte[] PagePfnDatabase;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    public struct VAD_DETAILS{
        public uint VadAddress;
        public uint StartVPN;
        public uint EndVPN;
        public uint VadFlags;
        public uint VadFlags3;
        public uint VadFlags2;
        public uint FirstPrototypePte;
        public uint LastContiguousPte;
        public uint ControlArea;
        public uint CA_Flags;
        public uint CA_Deref_FLink;
        public uint CA_Deref_BLink;
        public uint CA_NumberOfSectionReferences;
        public uint CA_NumberOfPfnReferences;
        public uint CA_NumberOfMappedViews;
        public uint CA_NumberOfUserReferences;
        public uint CA_FlushInProgressCount;
        public uint CA_ModifiedWriteCount;
        public uint CA_WaitingForDeletion;
        public uint CA_NumberOfSystemCacheViews;
        public uint CA_WritableUserReferences;
        public uint CA_View_FLink;
        public uint CA_View_BLink;
        public uint CA_FileObject;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string CA_FileName;
        public uint Segment;
        public uint SG_TotalNumberOfPtes;
        public uint SG_Flags;
        public uint SG_NumberOfCommittedPages;  
        public ulong SG_SizeOfSegment;
        public VAD_DETAILS_SUBSECTION ASubsection;     // 서브 섹션이 한 개 이상이면 SubsectionAddress 가 0xFFFFFFFF
    }

    
    public partial class VadForm : Form
    {
        [DllImport(fMain.dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern byte GetAddressDetails(byte type, ref MESSAGE_ENTRY buffer);
        

        private const byte IOCTL_GET_PFN_DETAILS = 0x21;

        private const byte IOCTL_MEMORY_DUMP_PAGE = 0x60;
        private const byte IOCTL_MEMORY_DUMP_VAD = 0x61;
        private const byte IOCTL_MEMORY_DUMP_ULONG_FLAGS = 0x62;
        private const byte IOCTL_MEMORY_DUMP_CA = 0x63;
        private const byte IOCTL_MEMORY_DUMP_SEGMENT = 0x64;
        private const byte IOCTL_MEMORY_DUMP_SUBSECTION = 0x65;

        private const byte IOCTL_GET_VAD_MAP = 0x41;
        private const byte IOCTL_GET_VAD_DETAILS = 0x42;
        private const byte IOCTL_GET_VAD_SUBSECTIONS = 0x43;

        private fMain mainForm = null;
        private uint selectedVAD = 0;
        private uint selectedVirtualAddress = 0;
        private bool autoMoving = true;
        private byte mode = 0;
        internal volatile bool isProcessing = false;

        string[] CA_Flags = new string[26]
        {
            "BeingDeleted" ,
            "BeingCreated" ,
            "BeingPurged" ,
            "NoModifiedWriting" ,
            "FailAllIo" ,
            "Image" ,
            "Based" ,
            "File" ,
            "Networked" ,
            "Rom" ,
            "PhysicalMemory" ,
            "CopyOnWrite" ,
            "Reserve" ,
            "Commit" ,
            "Accessed" ,
            "WasPurged" ,
            "UserReference" ,
            "GlobalMemory" ,
            "DeleteOnClose" ,
            "FilePointerNull" ,
            "GlobalOnlyPerSession" ,
            "SetMappedFileIoComplete" ,
            "CollidedFlush" ,
            "NoChange" ,
            " " ,
            "UserWritable" ,
        };

        private string[] PTE_Flags = new string[12]{
            "Valid",
            "Write",
            "Owner",
            "Write Through",
            "Cache Disabled",
            "Accessed",
            "Dirty",
            "Large Page",
            "Global",
            "Software field [Copy-On-Write]",
            "Software field [Prototype PTE]",
            "Software field [Write]"
            };

        //Valid[0] : 해당 변환이 물리 메모리 내의 페이지로 매핑되는지
        //Write[1] : 쓰기 가능한 페이지 인지를 MMU에게 알려준다.
        //Owner[2] : 유저 모드 코드가 접근할 수 있는 페이지인지, 커널 모드 전용인지 알려준다.
        //Write Through[3] : 페이지를 Write-through나 Write - Combined(프로세서가 페이지 속성 테이블을 지원한다면)로 표시한다.
        //보통 비디오 프레임 버퍼 메모리를 매핑할 때 사용함.
        //Cache Disabled[4] : 이 페이지에 대한 CPU 캐싱을 비활성화함.
        //Accessed[5] : 페이지가 접근되었다.
        //Dirty[6] : 페이지에 쓰기 작업이 일어났다.
        //[PED에서]
        //Large Page[7] : 해당 PDE가 4MB 페이지를 매핑함을 나타낸다. (PAE에서는 2MB)
        //Global[8] : 변환이 모든 프로세스에 적용된다.
        //예를 들어 변환 버프 플러시는 이 PTE에 영향을 주지 않음.
        //Copy-on-write[9] : 해당 페이지는 Copy-on-write를 사용한다.
        //Prototype PTE[10] : 해당 PTE는 prototype PTE이다.
        //섹션 객체와 연결된 공유 메모리를 가리키는 템플릿으로 사용되는 PTE.
        //Write[11]
        //9 10 11 : Software


        public VadForm()
        {
            InitializeComponent();
        }
        public VadForm(uint address, fMain f, byte m)
        {
            InitializeComponent();

            if (address == 0)
            {
                MessageBox.Show("Invalid Params.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Dispose();
                Close();
            }
            else
            {
                mainForm = f;
                mode = m;

                if (mode == 0)
                    selectedVAD = address;
                else if (mode == 1)
                    selectedVirtualAddress = address;
                else
                {
                    Dispose();
                    Close();
                }

                if (mainForm.WindowState == FormWindowState.Normal)
                {
                    this.Location = new Point(f.Location.X + f.Width + 1, f.Location.Y);
                    this.Height = f.Height;
                }

            }
        }

        internal void MovingForm()
        {
            if ((mainForm.WindowState == FormWindowState.Normal) && (autoMoving))
            {
                this.Location = new Point(mainForm.Location.X + mainForm.Width + 1, mainForm.Location.Y);
                this.Height = mainForm.Height;
            }

        }

        private void VadForm_Load(object sender, EventArgs e)
        {
            if (mode == 0)
            {
                this.Text = String.Format("VAD - 0x{0:X8}", selectedVAD);
                ChangeVad(selectedVAD);
            }
            else if (mode == 1)
            {
                this.Text = String.Format("Virtual Address : 0x{0:X8}", selectedVirtualAddress);
                ChangeVirtualAddress(selectedVirtualAddress);
            }
            else
                return;
                
        }

        private void VadDetailSubsectionParser(VAD_DETAILS_SUBSECTION currentSubsection, int index, byte irpCount)
        {
            index = index + (irpCount * 35);
            tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add("subsection_" + (index + 1).ToString(), String.Format("Subsection {0} : 0x{1:X8}", (index + 1), currentSubsection.SubsectionAddress));
            
            tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[index].Nodes.Add(String.Format("Starting Sector : 0x{0:X}", currentSubsection.StartingSector));
            tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[index].Nodes.Add(String.Format("Number Of Full Sectors : 0x{0:X}", currentSubsection.NumberOfFullSectors));
            tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[index].Nodes.Add(String.Format("Base PTE : 0x{0:X8}", currentSubsection.BasePTE));
            tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[index].Nodes.Add(String.Format("Number of Ptes in Subsection : 0x{0:X}", currentSubsection.PtesInSubsection));
            tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[index].Nodes.Add(String.Format("Unused Ptes : 0x{0:X}", currentSubsection.UnusedPtes));

            string vadFlags = "";
            for (int i = 0; i < 32; i++)
            {
                //    USHORT SubsectionAccessed : 1;
                //    USHORT Protection : 5;
                //    USHORT StartingSector4132 : 10;
                //    USHORT SubsectionStatic : 1;
                //    USHORT GlobalMemory : 1;
                //    USHORT DirtyPages : 1;
                //    USHORT Spare : 1;
                //    USHORT SectorEndOffset : 12;
                if ((i == 12) || (i == 13) || (i == 14) || (i == 15) || (i == 16) || (i == 26) || (i == 31))
                    vadFlags += " ";
                vadFlags += ((((currentSubsection.Flags) & (0x80000000 >> i)) == 0) ? "0" : "1");
            }
            tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[index].Nodes.Add("subsectionFlags_" + (index + 1).ToString(), "Flags :  " + vadFlags);

            vadFlags = "";
            if (((currentSubsection.Flags) & 0x00040000) == 0x00040000)
                vadFlags += "DirtyPages  ";
            if (((currentSubsection.Flags) & 0x00020000) == 0x00020000)
                vadFlags += "GlobalMemory  ";
            if (((currentSubsection.Flags) & 0x00010000) == 0x00010000)
                vadFlags += "Static  ";
            if (((currentSubsection.Flags) & 0x00000001) == 0x00000001)
                vadFlags += "Accessed";

            if (vadFlags.Length > 0)
            {
                tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[index].Nodes[(tVirtual.Nodes[(tVirtual.Nodes.Count) - 1]
                    .Nodes[index].Nodes.Count) - 1].Nodes.Add(vadFlags);
            }

            uint protectionBits = (((currentSubsection.Flags) & 0x0000FFC0) >> 6);
            tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[index].Nodes[(tVirtual.Nodes[(tVirtual.Nodes.Count) - 1]
          .Nodes[index].Nodes.Count) - 1].Nodes.Add(String.Format("Starting Sector4132 : 0x{0:X}", protectionBits));

            protectionBits = (((currentSubsection.Flags) & 0xFFF00000) >> 20);
            tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[index].Nodes[(tVirtual.Nodes[(tVirtual.Nodes.Count) - 1]
                .Nodes[index].Nodes.Count) - 1].Nodes.Add(String.Format("Sector End Offset : 0x{0:X}", protectionBits));

            protectionBits = (((currentSubsection.Flags) & 0x0000003E) >> 1);
            tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[index].Nodes[(tVirtual.Nodes[(tVirtual.Nodes.Count) - 1]
                .Nodes[index].Nodes.Count) - 1].Nodes.Add(String.Format("Protection : 0x{0:X}", protectionBits));
        }

        private void VadDetailParser(byte[] buffer)
        {
            VAD_DETAILS details;
            tVirtual.Nodes.Clear();

            try
            {
                details = (VAD_DETAILS)mainForm.ByteToStructure(buffer, typeof(VAD_DETAILS));

                ////////////////////////////////        VAD         ////////////////////////////////    Node 0
                tVirtual.Nodes.Add("vad", String.Format("VAD : 0x{0:X8}", details.VadAddress));

                tVirtual.Nodes[0].Nodes.Add("startVPN", String.Format("Start VPN : {0,5:X}", details.StartVPN));
                tVirtual.Nodes[0].Nodes.Add("endVPN", String.Format("  End VPN : {0,5:X}", details.EndVPN));
                tVirtual.Nodes[0].Nodes.Add(String.Format("First Prototype PTE : 0x{0:X8}", details.FirstPrototypePte));
                tVirtual.Nodes[0].Nodes.Add(String.Format("Last Contiguous PTE : 0x{0:X8}", details.LastContiguousPte));

                //////////////////////////////      VAD->VADFlags       ///////////////////////////////
                string vadFlags = "";
                for (int i = 0; i < 32; i++)
                {
                    if ((i == 1) || (i == 3) || (i == 8) || (i == 9) || (i == 12) || (i == 13))
                        vadFlags += " ";
                    vadFlags += ((((details.VadFlags) & (0x80000000 >> i)) == 0) ? "0" : "1");
                }
                tVirtual.Nodes[0].Nodes.Add("vadFlags_0", "VAD Flags :  " + vadFlags);

                vadFlags = "";
                if ((details.VadFlags & 0x80000000) == 0x80000000)
                {
                    vadFlags = "PrivateMemory";
                    tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add(vadFlags);
                }
                // ViewShare 랑 ViewUnmap은 VadFlags2 의 Inherit에 의해 좌우됨.

                vadFlags = "";
                uint protectionBits = ((details.VadFlags) & 0x07000000);   // Protection Bits
                switch (protectionBits >> 24)
                {
                    case 0:
                        vadFlags = "NO_ACCESS";
                        break;
                    case 1:
                        vadFlags = "READONLY";
                        break;
                    case 2:
                        vadFlags = "EXECUTE";
                        break;
                    case 3:
                        vadFlags = "EXECUTE_READ";
                        break;
                    case 4:
                        vadFlags = "READWRITE";
                        break;
                    case 5:
                        vadFlags = "WRITECOPY";
                        break;
                    case 6:
                        vadFlags = "EXECUTE_READ_WRITE";
                        break;
                    case 7:
                        vadFlags = "EXECUTE_WRITECOPY";
                        break;
                    default:
                        break;
                }

                // 위의 플래그 값 중 하나라도 켜져 있으면, 아래 플래그까지 적용함.
                if (protectionBits != 0)
                {
                    protectionBits = ((details.VadFlags) & 0x18000000);
                    switch (protectionBits >> 27)
                    {
                        case 1:
                            vadFlags += " NOCACHE";
                            break;
                        case 2:
                            vadFlags += " GUARD";
                            break;
                        case 3:
                            vadFlags += " WRITECOMBINE";
                            break;
                        default:
                            break;
                    }

                }
                if (vadFlags.Length > 0)
                    tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add(vadFlags);


                // MemCommit
                if ((details.VadFlags & 0x800000) == 0x800000)
                {
                    tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("MemCommit");
                }

                // VAdType
                protectionBits = ((details.VadFlags) & 0x700000);
                if (protectionBits != 0)
                {
                    switch (protectionBits >> 20)
                    {
                        case 1:
                            vadFlags = "PhysicalMapping";
                            break;
                        case 2:
                            vadFlags = "ImageMap";
                            break;
                        case 3:
                            vadFlags = "AWE";
                            break;
                        case 4:
                            vadFlags = "WriteWatch";
                            break;
                        case 5:
                            vadFlags = "LargePages";
                            break;
                        case 6:
                            vadFlags = "RotatePhys";
                            break;
                        default:
                            vadFlags = "";
                            break;
                    }
                    if (vadFlags.Length > 0)
                        tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add(vadFlags);
                }

                // NoCh
                if ((details.VadFlags & 0x80000) == 0x80000)
                {
                    tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("NoChange");
                }

                // Commit Charge
                tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add(String.Format("Commit Charge : {0}", ((details.VadFlags) & 0x7FFFF)));
                ////////////////////////////////////////////////////////////////////////////////////////


                //////////////////////////////      VAD->VADFlags3       ///////////////////////////////
                vadFlags = "";
                for (int i = 0; i < 32; i++)
                {
                    //       struct _MMVAD_FLAGS3
                    //       {
                    //           ULONG PreferredNode : 6;
                    //           ULONG Teb : 1;
                    //           ULONG Spare : 1;
                    //           ULONG SequentialAccess : 1;
                    //           ULONG LastSequentialTrim : 15;
                    //           ULONG Spare2 : 8;
                    //       }
                    if ((i == 8) || (i == 23) || (i == 24) || (i == 25) || (i == 26))
                        vadFlags += " ";
                    vadFlags += ((((details.VadFlags3) & (0x80000000 >> i)) == 0) ? "0" : "1");
                }
                tVirtual.Nodes[0].Nodes.Add("vadFlags_3", "VAD Flags3 :  " + vadFlags);
       
                protectionBits = ((details.VadFlags3) & 0x0000003F);
                if (protectionBits != 0)
                    tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add(String.Format("Preferred Node : 0x{0:X}", protectionBits));
                protectionBits = (((details.VadFlags3) & 0x00FFFE00) >> 9);
                if (protectionBits != 0)
                    tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add(String.Format("Last Sequential Trim : 0x{0:X}", protectionBits));

                vadFlags = "";
                if ((details.VadFlags3 & 0x00000100) == 0x00000100)
                    vadFlags += "SequentialAccess  ";
                if ((details.VadFlags3 & 0x00000040) == 0x00000040)
                    vadFlags += "Teb  ";
                if (vadFlags.Length > 0)
                    tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add(vadFlags);
                ////////////////////////////////////////////////////////////////////////////////////////



                //////////////////////////////      VAD->VADFlags2       ///////////////////////////////
                vadFlags = "";
                for (int i = 0; i < 32; i++)
                {
                    // 모든 플래그 값들은 VadFlags의 NoChange 비트가 셋팅되어 있다면, 무시된다.
                    //   struct _MMVAD_FLAGS2
                    //   {
                    //       ULONG FileOffset : 24;
                    //       ULONG SecNoChange : 1;
                    //       ULONG OneSecured : 1;
                    //       ULONG MultipleSecured : 1;
                    //       ULONG Spare3 : 1;  // 무시
                    //       ULONG LongVad : 1; // 무시
                    //       ULONG ExtendableFile : 1;
                    //       ULONG Inherit : 1;     // 해당 비트가 셋팅되어 있다면 ViewShare, 아니면 ViewUnmap
                    //       ULONG CopyOnWrite : 1;
                    //   }
                    if ((i == 1) || (i == 2) || (i == 3) || (i == 4) || (i == 5) || (i == 6) || (i == 7) || (i == 8))
                        vadFlags += " ";
                    vadFlags += ((((details.VadFlags2) & (0x80000000 >> i)) == 0) ? "0" : "1");
                }
                tVirtual.Nodes[0].Nodes.Add("vadFlags_2", "VAD Flags2 :  " + vadFlags);

                // VadFlags2 관련해서는 Dirver.c 주석 참조.
                if ((((details.VadFlags) & 0x80000000) == 0x80000000) && (((details.VadFlags) & 0x00080000) == 0))
                {
                    tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("ViewUnmap");
                    tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("File Offset : 0");
                }
                else{
                    if ((details.VadFlags2 & 0x80000000) == 0x80000000)
                        tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("CopyOnWrite");

                    // Inherit
                    if ((details.VadFlags2 & 0x40000000) == 0x40000000)
                        tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("ViewShare");
                    else
                        tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("ViewUnmap");

                    if ((details.VadFlags2 & 0x20000000) == 0x20000000)
                        tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("ExtendableFile");
                    if ((details.VadFlags2 & 0x04000000) == 0x04000000)
                        tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("MultipleSecured");
                    if ((details.VadFlags2 & 0x02000000) == 0x02000000)
                        tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("OneSecured");
                    if ((details.VadFlags2 & 0x01000000) == 0x01000000)
                        tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add("SecNoChange");

                    protectionBits = (details.VadFlags2 & 0x00FFFFFF);
                    // if(protectionBits != 0) // 0이라도 출력하자.
                    tVirtual.Nodes[0].Nodes[(tVirtual.Nodes[0].Nodes.Count) - 1].Nodes.Add(String.Format("File Offset : 0x{0:X}", protectionBits));
                }                
                ////////////////////////////////////////////////////////////////////////////////////////
                

                ////////////////////////////////        CA       ////////////////////////////////   Node 1
                if ((details.ControlArea) != 0)
                {
                    tVirtual.Nodes.Add("controlArea", String.Format("Control Area : 0x{0:X8}", details.ControlArea));

                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("Derefernce List FLink : 0x{0:X8}", details.CA_Deref_FLink));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("Derefernce List BLink : 0x{0:X8}", details.CA_Deref_BLink));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("Section Ref : 0x{0:X}", details.CA_NumberOfSectionReferences));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("Pfn Ref : 0x{0:X}", details.CA_NumberOfPfnReferences));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("Mapped Views : 0x{0:X}", details.CA_NumberOfMappedViews));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("User Ref : 0x{0:X}", details.CA_NumberOfUserReferences));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("Waiting for Deletion : 0x{0:X8}", details.CA_WaitingForDeletion));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("Flush Count : 0x{0:X}", details.CA_FlushInProgressCount));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("Modified Write Count : 0x{0:X}", details.CA_ModifiedWriteCount));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("System Cache Views : 0x{0:X}", details.CA_NumberOfSystemCacheViews));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("Writable User Ref : 0x{0:X}", details.CA_WritableUserReferences));              
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("View List FLink : 0x{0:X8}", details.CA_View_FLink));
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("View List BLink : 0x{0:X8}", details.CA_View_BLink));

                    /////////////////////////////////////       File        /////////////////////////////////////
                    if ((details.CA_FileObject) == 0)
                        tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add("Pagefile-backed section");
                    else
                    {
                        tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add(String.Format("File Object : 0x{0:X8}", details.CA_FileObject));
                        tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[(tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Count) - 1].Nodes.Add("File Name : " + details.CA_FileName);
                    }
                    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      
                    /////////////////////////////////////       CA Flags        /////////////////////////////////////
                    tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Add("controlAreaFlags", String.Format("Flags : 0x{0:X8}", details.CA_Flags));
                    protectionBits = 0x00000001;
                    vadFlags = "";
                    for (int i = 0; i < 26; i++)
                    {
                        if ((((details.CA_Flags) & (protectionBits << i))) != 0)
                            vadFlags += (CA_Flags[i] + "  ");
                    }
                    if (vadFlags.Length > 0)
                        tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[(tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Count) - 1].Nodes.Add(vadFlags);

                    // PreferredNode : 6;
                    protectionBits = (((details.CA_Flags) & 0xFC000000) >> 26);
                    if (protectionBits != 0)
                        tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes[(tVirtual.Nodes[(tVirtual.Nodes.Count) - 1].Nodes.Count) - 1].Nodes.Add(String.Format("Preferred Node : 0x{0:X}", protectionBits));
                    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
                }
                ////////////////////////////////////////////////////////////////////////////////////////


                ////////////////////////////////        Segment      ////////////////////////////////
                if ((details.Segment) != 0)
                    tVirtual.Nodes.Add("segment", String.Format("Segment : 0x{0:X8}", details.Segment));
                ////////////////////////////////////////////////////////////////////////////////////////


                ////////////////////////////////        Subsections     ////////////////////////////////
                if ((details.ASubsection.SubsectionAddress) != 0) {
                    // Subsection이 하나인 경우.
                    if ((details.ASubsection.SubsectionAddress) != 0xFFFFFFFF)
                    {
                        tVirtual.Nodes.Add("Subsections : Total 1");
                        VadDetailSubsectionParser(details.ASubsection, 0, 0);
                    }
                    // Subsection이 둘 이상이면, 새로 IRP 전송.
                    else
                    {
                        byte irpCount = 0;
                        int numberOfSubsection = 0;
                        tVirtual.Nodes.Add("totalSubsections", "Subsections : Total ");

                        MESSAGE_ENTRY message = new MESSAGE_ENTRY();
                        message.Buffer = new byte[1024];        // 애플리케이션 내에서 값 넣기 전엔, 항상 할당부터....

                        do
                        {
                            message.MessageType = selectedVAD;
                            message.Buffer.Initialize();
                            message.Buffer[0] = irpCount;       // buffer[0]로 irpCount 전달.

                            if (GetAddressDetails(IOCTL_GET_VAD_SUBSECTIONS, ref message) == 1)
                            {
                                // 결과 : 서브 섹션이 더 남아서 한 번 더 IRP 전송해야 한다면, 상위 2바이트 0xFFFF
                                //		  하위 2바이트는 현재 저장한 갯수.
                                numberOfSubsection = (((int)(message.MessageType)) & 0x0000FFFF);

                                for (int i = 0; i < numberOfSubsection; i++)
                                    VadDetailSubsectionParser((VAD_DETAILS_SUBSECTION)mainForm.ByteToStructure(message.Buffer, typeof(VAD_DETAILS_SUBSECTION), (uint)i), i, irpCount);
                            }
                            else
                            {
                                MessageBox.Show("Failed to get some Subsections.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                                return;
                            }
                        } while ((((message.MessageType) & 0xFFFF0000) == 0xFFFF0000) && ((++irpCount) < 5));        // 최대 5번만...
              
                        if (irpCount == 0)
                            tVirtual.Nodes.Find("totalSubsections", true)[0].Text += (numberOfSubsection.ToString());
                        else if (irpCount < 5)
                            tVirtual.Nodes.Find("totalSubsections", true)[0].Text += String.Format("{0}", ((irpCount - 1) * 35) + numberOfSubsection);
                        else
                        {
                            MessageBox.Show("Too many subsections\n   -> Truncated...", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            tVirtual.Nodes.Find("totalSubsections", true)[0].Text += String.Format("{0}++", (35 * 5));
                            return;
                        }                            
                    }
                }
                ////////////////////////////////////////////////////////////////////////////////////////
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
        }
        private void PfnDetailsParsing(byte[] buffer, ushort validFlag)
        {
            PFN_DETAILS details;
            ushort nFlags = 0;
            string sFlags = "";

            try
            {
                details = (PFN_DETAILS)mainForm.ByteToStructure(buffer, typeof(PFN_DETAILS));
            }
            catch
            {
                MessageBox.Show("Failed to parse PFNDetails.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            tPhysical.Nodes.Add(String.Format("PDPT is at Physical Address 0x0'{0:X8}", details.DirBase));
            //////////////////////////////////////////////////////////////////////////////////////////////
            ///////////////////////////////////////          PDPT            /////////////////////////////
            //////////////////////////////////////////////////////////////////////////////////////////////
            tPhysical.Nodes.Add(String.Format("Page Directory Pointer Table : 0x{0:X8}", details.PDPTAddress));
            tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Add(String.Format("Entry[{0}] : 0x{1:X8}", ((selectedVirtualAddress & 0xC0000000) >> 30), details.PDPEAddress));

            (details.DirBase) += (((selectedVirtualAddress & 0xC0000000) >> 30) * 8);
            tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Add(String.Format("Physical Address : 0x0'{0:X8}", details.DirBase));

            tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Add(String.Format("Contains : {0:X16}", details.PDPEValue));

            if ((validFlag & 0x1) == 0x1)
            {
                tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                    .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1].Nodes.Add(String.Format("PFN : 0x{0:X6}", (uint)((details.PDPEValue & 0xFFFFFF000) >> 12)));

                nFlags = (ushort)(details.PDPEValue & 0xFFF);
                for (int i = 11; i >= 0; i--)
                {
                    if ((nFlags & (1 << i)) != 0)
                    {
                        sFlags += "1 ";
                    }
                    else
                        sFlags += "0 ";
                }
                tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                    .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1].Nodes.Add("Flags : " + sFlags);
                sFlags = "";

                for (int i = 11; i >= 0; i--)
                {
                    if ((nFlags & (1 << i)) != 0)
                    {
                        tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                            .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                            .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                            .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                            .Nodes.Count - 1].Nodes.Add(PTE_Flags[i]);
                    }
                }
                //////////////////////////////////////////////////////////////////////////////////////////////////////


                //////////////////////////////////////////////////////////////////////////////////////////////
                ///////////////////////////////////////          PDT            /////////////////////////////
                //////////////////////////////////////////////////////////////////////////////////////////////
                tPhysical.Nodes.Add(String.Format("Page Directory Table : 0x{0:X8}", details.PDTAddress));
                tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Add(String.Format("Entry[{0}] : 0x{1:X8}", ((selectedVirtualAddress & 0x3FE00000) >> 21), details.PDEAddress));

                (details.PDPEValue) &= 0xFFFFFFFFFFFFF000;
                (details.PDPEValue) += (details.PDEAddress & 0xFFF);
                sFlags = "0x";
                sFlags += String.Format("{0:X}'", (uint)((details.PDPEValue) >> 32));
                sFlags += String.Format("{0:X8}", (uint)(details.PDPEValue & 0xFFFFFFFF));
                tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Add("Physical Address : " + sFlags);
                sFlags = "";
                tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Add(String.Format("Contains : {0:X16}", details.PDEValue));

                if ((validFlag & 0x10) == 0x10)
                {
                    tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                        .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                        .Nodes.Add(String.Format("PFN : 0x{0:X6}", (uint)((details.PDEValue & 0xFFFFFF000) >> 12)));

                    nFlags = (ushort)(details.PDEValue & 0xFFF);
                    for (int i = 11; i >= 0; i--)
                    {
                        if ((nFlags & (1 << i)) != 0)
                        {
                            sFlags += "1 ";
                        }
                        else
                            sFlags += "0 ";
                    }
                    tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                        .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                        .Nodes.Add("Flags : " + sFlags);
                    sFlags = "";

                    for (int i = 11; i >= 0; i--)
                    {
                        if ((nFlags & (1 << i)) != 0)
                        {
                            tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                                .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                                .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                                .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                                .Nodes.Count - 1].Nodes.Add(PTE_Flags[i]);
                        }
                    }
                    //////////////////////////////////////////////////////////////////////////////////////////////////////


                    //////////////////////////////////////////////////////////////////////////////////////////////
                    ///////////////////////////////////////          PT            /////////////////////////////
                    //////////////////////////////////////////////////////////////////////////////////////////////
                    tPhysical.Nodes.Add(String.Format("Page Table : 0x{0:X8}", details.PTAddress));
                    tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Add(String.Format("Entry[{0}] : 0x{1:X8}", ((selectedVirtualAddress & 0x001FF000) >> 12), details.PTEAddress));

                    (details.PDEValue) &= 0xFFFFFFFFFFFFF000;
                    (details.PDEValue) += (details.PTEAddress & 0xFFF);
                    sFlags = "0x";
                    sFlags += String.Format("{0:X}'", (uint)((details.PDEValue) >> 32));
                    sFlags += String.Format("{0:X8}", (uint)(details.PDEValue & 0xFFFFFFFF));
                    tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Add("Physical Address : " + sFlags);
                    sFlags = "";

                    tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                        .Nodes.Add(String.Format("Contains : {0:X16}", details.PTEValue));

                    if ((validFlag & 0x100) == 0x100)
                    {
                        tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                            .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                            .Nodes.Add(String.Format("PFN : 0x{0:X6}", (uint)((details.PTEValue & 0xFFFFFF000) >> 12)));

                        nFlags = (ushort)(details.PTEValue & 0xFFF);
                        for (int i = 11; i >= 0; i--)
                        {
                            if ((nFlags & (1 << i)) != 0)
                            {
                                sFlags += "1 ";
                            }
                            else
                                sFlags += "0 ";
                        }
                        tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                            .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                            .Nodes.Add("Flags : " + sFlags);
                        sFlags = "";

                        for (int i = 11; i >= 0; i--)
                        {
                            if ((nFlags & (1 << i)) != 0)
                            {
                                tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                                    .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                                    .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                                    .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                                    .Nodes.Count - 1].Nodes.Add(PTE_Flags[i]);
                            }
                        }
                        //////////////////////////////////////////////////////////////////////////////////////////////////////

                        sFlags = String.Format("{0:X}", details.HIPhysicalAddress);
                        if (sFlags.Length > 0)
                            sFlags += "'";
                        sFlags += String.Format("{0:X8}", (details.LOPhysicalAddress & 0xFFFFF000) + (selectedVirtualAddress & 0xFFF));

                        tPhysical.Nodes.Add("Physical Address : 0x" + sFlags);
                        return;
                    }
                    else
                    {
                        details.PDPEValue = details.PTEValue;
                        sFlags = "PTE";
                    }
                }
                else
                {
                    details.PDPEValue = details.PDEValue;
                    sFlags = "PDE";
                }
            }
            else
                sFlags = "PDPE";
            ////////////////////////////////////////////////////////////////////////////////
            //////////////////////////////      Invalid PTE     ////////////////////////////
            ////////////////////////////////////////////////////////////////////////////////
            // Invalid Entry에 포함된 값은 임시로 details.PDPEValue에 저장.
            InvalidPageEntryParsing(details.PDPEValue, (tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1]
                          .Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes[tPhysical.Nodes[tPhysical.Nodes.Count - 1].Nodes.Count - 1].Nodes.Count - 1]
                          .Nodes.Add("INVALID " + sFlags)).Parent);
            
            return;
        }

        private void InvalidPageEntryParsing(ulong contains, TreeNode ParentNode)
        {

        }

        internal void ChangeVirtualAddress(uint v)
        {            
            if (v != 0)
            {
                selectedVirtualAddress = v;
                this.Text = String.Format("Virtual Address : 0x{0:X8}", selectedVirtualAddress);


                tPhysical.Nodes.Clear();

                MESSAGE_ENTRY buffer = new MESSAGE_ENTRY();
                buffer.MessageType = selectedVirtualAddress;
                if (GetAddressDetails(IOCTL_GET_PFN_DETAILS, ref buffer) == 1)
                {
                    if(((buffer.MessageType) & 0x10000000) == 0x10000000)
                        PfnDetailsParsing(buffer.Buffer, (ushort)((buffer.MessageType) & 0xFFF));
                    else
                    {
                        MessageBox.Show("Failed to get PFN Info.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }
                else
                {
                    MessageBox.Show("Failed to get data for this V.A.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    
                }

                tabControl1.SelectedIndex = 1;
            }
            else
                return;
                

        }

        internal void ChangeVad(uint v)
        {
            /////////////////////////////////// 동기화 문제가 아닐수도!~!??       -> 이거 Private 영역인 경우, pSection에 있는 쓰레기 값 떄문에
            if (!isProcessing)
            {
                isProcessing = true;
                string selected = null;

                if (v != 0)
                {
                    selectedVAD = v;
                    this.Text = String.Format("VAD - 0x{0:X8}", selectedVAD);
                }
                else
                {
                    // v == 0 이면, ManipulateMemory로 인한 Refresh
                    selected = tVirtual.SelectedNode.Name;
                }


                tVirtual.Nodes.Clear();
                MESSAGE_ENTRY buffer = new MESSAGE_ENTRY();
                buffer.MessageType = selectedVAD;
                if (GetAddressDetails(IOCTL_GET_VAD_DETAILS, ref buffer) == 1)
                {
                    if(buffer.MessageType == 0)
                    {
                        VadDetailParser(buffer.Buffer);
                        tVirtual.ExpandAll();
                        
                        tabControl1.SelectedIndex = 0;
                    }
                    else if(buffer.MessageType == 0x0F)
                    {
                        mainForm.isErrorInVadDetails = true;
                        if (DialogResult.OK == MessageBox.Show("This VAD is corrupted in Progressing.\nThe system crash may occur without refreshing whole VAD Map.\nRefresh?", "Error", MessageBoxButtons.YesNo, MessageBoxIcon.Error))
                            mainForm.refreshWholeVadMap = true;                        
                    }
                    else if(buffer.MessageType == 0xFF)
                    {
                        mainForm.isErrorInVadDetails = true;
                        if (DialogResult.OK == MessageBox.Show("This VAD is for Shared Memory, but the segment is not exist.\nThe system crash may occur without refreshing whole VAD Map.\nRefresh?", "Error", MessageBoxButtons.YesNo, MessageBoxIcon.Error))
                            mainForm.refreshWholeVadMap = true;
                    }
                }
                else
                {
                    mainForm.isErrorInVadDetails = true;
                    if(DialogResult.OK == MessageBox.Show("The VAD entry had freed.\nThe system crash may occur without refreshing whole VAD Map.\nRefresh?", "Error", MessageBoxButtons.YesNo, MessageBoxIcon.Error))
                        mainForm.refreshWholeVadMap = true;
                }

                // v == 0 이면, ManipulateMemory로 인한 Refresh
                if (v == 0)
                {
                    tVirtual.SelectedNode = tVirtual.Nodes.Find(selected, true)[0];
                }
                isProcessing = false;
            }

        }

        private void bAutoMoving_Click(object sender, EventArgs e)
        {
            if (autoMoving)
            {
                autoMoving = false;
                this.bAutoMoving.Image = global::MemoryExplorer.Properties.Resources.before;
            }
            else
            {
                autoMoving = true;
                this.bAutoMoving.Image = global::MemoryExplorer.Properties.Resources.after;
                MovingForm();
            }
        }

        private void toolStripButton1_Click(object sender, EventArgs e)
        {
            if(tVirtual.SelectedNode == null)
            {
      //          MessageBox.Show("Select a Node.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            else
            {
                byte dumpType = 0;
                byte secondType = 0;        // Subsection인 경우, 타겟 Number를 memoryDump[0] 에 넣자.
                                            // Flags인 경우, 플래그 넘버를 memoryDump[0]

                string name = tVirtual.SelectedNode.Name;
                switch (name)
                {
                    case "vad":
                        dumpType = IOCTL_MEMORY_DUMP_VAD;
                        break;
                    case "controlArea":
                        dumpType = IOCTL_MEMORY_DUMP_CA;
                        break;
                    case "segment":
                        dumpType = IOCTL_MEMORY_DUMP_SEGMENT;
                        break;
                    default:
                        if (name.Contains("Flags_"))
                        {
                            dumpType = IOCTL_MEMORY_DUMP_ULONG_FLAGS;
                            secondType = (byte)Convert.ToUInt32(name.Split(new char[] { '_' }, StringSplitOptions.RemoveEmptyEntries)[1]);
                        }
                        else if (name.Contains("subsection_"))
                        {
                            dumpType = IOCTL_MEMORY_DUMP_SUBSECTION;
                            secondType = (byte)Convert.ToUInt32(name.Split(new char[] { '_' }, StringSplitOptions.RemoveEmptyEntries)[1]);
                        }
                        else
                            return;
                        break;
                }
                mainForm.ShowMemoryDump(selectedVAD, dumpType, secondType);
            }
        }


        //internal void ChangeVad(uint v)
        //{
        //    /////////////////////////////////// 동기화 문제가 아닐수도!~!??       -> 이거 Private 영역인 경우, pSection에 있는 쓰레기 값 떄문에
        //    if ((v != 0) && (!isProcessing))
        //    {
        //        isProcessing = true;

        //        selectedVAD = v;
        //        this.Text = String.Format("VAD - 0x{0:X8}", selectedVAD);

        //        listView1.Items.Clear();
        //        VAD_DETAILS buffer = new VAD_DETAILS();
        //        buffer.VadAddress = selectedVAD;
        //        if (GetVadDetails(ref buffer) == 1)
        //        {
        //            uint tmp = 0;
        //            string[] entry = new string[2];
        //            entry[0] = "SubSection";
        //            entry[1] =  String.Format("0x{0:X8}", buffer.ControlArea);
        //            listView1.Items.Add(new ListViewItem(entry));

        //            //entry = new string[2];
        //            entry[0] = "Flags";
        //            //entry[1] = Convert.ToString(buffer.Flags, 2);
        //            /*
        //            ULONG CommitCharge : 19;
        //            ULONG NoChange : 1;
        //            ULONG VadType : 3;
        //            ULONG MemCommit : 1;
        //            ULONG Protection : 5;
        //            ULONG Spare0 : 2;
        //            ULONG PrivateMemory : 1;
        //            */
        //            entry[1] = "";
        //            for (int i = 0; i < 13; i++)
        //            {
        //                if ((i == 1) || (i == 3) || (i == 8) || (i == 9) || (i == 12))
        //                    entry[1] += " ";
        //                entry[1] += ((((buffer.VadFlags) & (0x80000000 >> i)) == 0)? "0":"1");
        //            }

        //            listView1.Items.Add(new ListViewItem(entry));

        //            tmp = ((buffer.VadFlags) & 0x07000000);   // Protection Bits

        //                //entry = new string[2];
        //                entry[0] = "";
        //            switch (tmp >> 24)
        //            {
        //                case 0:
        //                    entry[1] = "NO_ACCESS";
        //                    break;
        //                case 1:
        //                    entry[1] = "READONLY";
        //                    break;
        //                case 2:
        //                    entry[1] = "EXECUTE";       // Maybe...
        //                    break;
        //                case 3:
        //                    entry[1] = "EXECUTE_READ";
        //                    break;
        //                case 4:
        //                    entry[1] = "READWRITE";
        //                    break;
        //                case 5:
        //                    entry[1] = "WRITECOPY";
        //                    break;
        //                case 6:
        //                    entry[1] = "EXECUTE_READWRITE";
        //                    break;
        //                case 7:
        //                    entry[1] = "EXECUTE_WRITECOPY";
        //                    break;
        //                default:
        //                    entry[1] = "";
        //                    break;
        //            }
        //                if(entry[1].Length >= 1)
        //                    listView1.Items.Add(new ListViewItem(entry));

        //            //////////////////////////////////////////// 요거 드라이버에서 하는걸로 할까??? ////////////////////////////////////////////
        //            // Private
        //            if (((buffer.VadFlags) & 0x80) == 0x80)
        //            {
        //                entry[1] = "Private Memory";
        //            }
        //            else
        //            {
        //                entry[1] = "Mapped";
        //            }
        //            listView1.Items.Add(new ListViewItem(entry));

        //        }
        //        else
        //        {
        //            MessageBox.Show("Failed to Communication with Driver.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        //        }

        //        isProcessing = false;
        //    }

        //}
    }
}
