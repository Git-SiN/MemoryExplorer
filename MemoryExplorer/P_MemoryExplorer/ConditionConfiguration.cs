/*
    다이얼로그 박스 창이 닫기는 경우 :
        this.DialogReault 필드에 값을 넣을 경우.
        this.Dispose() this.Close() 하는 경우.
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
    public partial class ConditionConfiguration : Form
    {

        [DllImport(fMain.dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        static extern private byte SendControlMessageByPointer(byte control, ref FINDER_ENTRY pMessage, uint length);

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




        fMain mainForm = null;        
        byte mode = 0;

        FINDER_ENTRY pMessage = new FINDER_ENTRY();
        internal uint returnStart = 0;
        internal uint returnSize = 0;
        internal uint returnLevel = 0;
        internal byte returnRange = 0;

        public ConditionConfiguration()
        {
            InitializeComponent();
        }

        public ConditionConfiguration(fMain f, Byte m, string n)
        {
            InitializeComponent();
        
            mainForm = f;
            mode = m;
            this.Text = n;
            cRange.SelectedIndex = 0;

            switch (mode)
            {
                case 0:     // ADDRESS TRANSLATOR
                    tSize.Enabled = false;
                    this.Height = 180;
                    splitContainer1.Panel2Collapsed = true;
                    bStart.TabIndex = 1;
                    bCancel.TabIndex = 2;

                    groupBox1.Text = "Target Address";
                    lStart.Text = "Virtual Address :";
                    bStart.Text = "Translate";
                    cRange.Enabled = false;
                    break;
                case IOCTL_FIND_OBJECT_UNICODE:
                    lStart.Text = "Start Address :";
                    bStart.Text = "Search";
                    groupBox1.Text = "Target Range";

                    splitContainer1.Panel2Collapsed = false;
                    groupBox2.Height = 53;
                    this.Height = 266;
                    break;
                case IOCTL_FIND_PATTERN_UNICODE:
                case IOCTL_FIND_PATTERN_STRING:
                    lStart.Text = "Start Address :";
                    bStart.Text = "Search";
                    groupBox1.Text = "Target Range";

                    lOpt1.Visible = true;
                    tOpt1.Visible = true;
                    tOpt1.TabStop = true;
                    tOpt1.TabIndex = 2;
                    lOpt1.Text = "Minimum Length :";

                    splitContainer1.Panel2Collapsed = false;
                    groupBox2.Height = 53 + 26;
                    this.Height = 266 + 26;
                    break;
                case IOCTL_FIND_VALUE_UNICODE:
                case IOCTL_FIND_VALUE_STRING:
                    lStart.Text = "Start Address :";
                    bStart.Text = "Search";
                    groupBox1.Text = "Target Range";

                    lOpt1.Visible = true;
                    tOpt1.Visible = true;
                    tOpt1.TabStop = true;
                    tOpt1.TabIndex = 2;
                    lOpt1.Text = "Keywords :";

                    splitContainer1.Panel2Collapsed = false;
                    groupBox2.Height = 53 + 26;
                    this.Height = 266 + 26;
                    break;
                default:
                    this.DialogResult = DialogResult.Abort;
                    return;
            }

            pMessage.Contents = "";
        }


        private void bStart_Click(object sender, EventArgs e)
        {
            if(cRange.SelectedIndex == 0)
            {
                string start = this.tStart.Text.Trim();

                // Check the value of Start.
                if (start.Length <= 0)
                {
                    MessageBox.Show("Input the Start Address.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    tStart.Focus();
                    tStart.SelectAll();
                    return;
                }

                try
                {
                    returnStart = pMessage.Address = uint.Parse(start, System.Globalization.NumberStyles.HexNumber);
                }
                catch
                {
                    MessageBox.Show("Input in HEX.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    tStart.Focus();
                    tStart.SelectAll();
                    return;
                }

                if (mode > 0)
                {
                    string size = this.tSize.Text.Trim();

                    // Check the value of Size.
                    if (size.Length <= 0)
                    {
                        MessageBox.Show("Input the Size of retrieving.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        tSize.Focus();
                        tSize.SelectAll();
                        return;
                    }

                    try
                    {
                        pMessage.Length = uint.Parse(size, System.Globalization.NumberStyles.HexNumber);
                    }
                    catch
                    {
                        MessageBox.Show("Input in HEX.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        tSize.Focus();
                        tSize.SelectAll();
                        return;
                    }
                    if (pMessage.Length <= 0)
                    {
                        MessageBox.Show("The size must be above 0", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        tSize.Focus();
                        tSize.SelectAll();
                        return;
                    }
                    else if (pMessage.Length > 4096)
                    {
                        MessageBox.Show("The size is allowed up to 0x400.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        tSize.Focus();
                        tSize.SelectAll();
                        return;
                    }
                    returnSize = pMessage.Length;
                }
                pMessage.Address2 = (uint)(cRange.SelectedIndex);
                returnRange = (byte)(cRange.SelectedIndex);
                //////////////////////////////////////////////////////////       
                ////////////////////       Optional       ////////////////
                //////////////////////////////////////////////////////////
                switch (mode)
                {
                    case IOCTL_FIND_PATTERN_STRING:
                    case IOCTL_FIND_PATTERN_UNICODE:
                        try
                        {
                            returnLevel = Convert.ToUInt32(tOpt1.Text.Trim());
                        }
                        catch
                        {
                            MessageBox.Show("Input the \"Minimum Length\" in Decimal.\r\n[2 ~ 10]", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            tOpt1.Focus();
                            tOpt1.SelectAll();
                            return;
                        }
                        if ((returnLevel < 2) || (returnLevel > 10))
                        {
                            MessageBox.Show("Input the \"Minimum Length\" in Decimal.\r\n[2 ~ 10]", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            tOpt1.Focus();
                            tOpt1.SelectAll();
                            return;
                        }

                        // Most-significant 2 bytes of "Address2" field is for "Level".
                        pMessage.Address2 |= (returnLevel << 16);
                        break;
                    case IOCTL_FIND_VALUE_STRING:
                    case IOCTL_FIND_VALUE_UNICODE:
                        break;
                }
                //////////////////////////////////////////////////////////
                //////////////////////////////////////////////////////////
                //////////////////////////////////////////////////////////


                // Send Message 
                if (SendControlMessageByPointer(mode, ref pMessage, 520) == 1)
                {
                    this.DialogResult = DialogResult.OK;
                }
                else
                {
                    this.DialogResult = DialogResult.Abort;
                }

            }
            else    // Address Translator
            {
                this.DialogResult = DialogResult.OK;
            }
            
        }



        private void tSize_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)13)   // "Enter"
            {
                this.bStart_Click(this, null);
            }
        }

        private void bCancel_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.Cancel;
        }

        private void tStart_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)13)   // "Enter" 
            {
                this.bStart_Click(this, null);
            }
        }

        private void cRange_SelectedIndexChanged(object sender, EventArgs e)
        {
            if(cRange.SelectedIndex == 0)
            {
                tStart.Enabled = true;
                tSize.Enabled = true;
                tStart.Focus();
                tStart.SelectAll();
            }
            else
            {
                tStart.Enabled = false;
                tSize.Enabled = false;
            }
        }
    }

}
    