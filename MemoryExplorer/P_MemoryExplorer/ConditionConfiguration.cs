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
        static extern private byte SendControlMessageByPointer(byte control, uint[] pMessage, uint length);

        const byte IOCTL_FIND_OBJECT_UNICODE = 0x90;


        fMain mainForm = null;

        string start = null;
        string size = null;
        byte mode = 0;
        uint[] pMessage = new uint[2];


        public ConditionConfiguration()
        {
            InitializeComponent();
        }

        /// <summary>
        /// 1 : Hex Editor / 2 : Disassembler
        /// </summary>
        /// <param name="form"></param>
        /// <param name="mode"></param>
        public ConditionConfiguration(fMain f, Byte m, string n)
        {
            InitializeComponent();

            mainForm = f;
            mode = m;
            this.Text = n;

            switch (mode)
            {
                case 0:     // FINDER -> OBJECT -> UNICODE
                    lStart.Text = "Start Address :";
                    bStart.Text = "Search";
                    groupBox1.Text = "Target Range";

                    this.Height = 180;
                    splitContainer1.Panel2Collapsed = true;
                    break;
                case 1:     // ADDRESS TRANSLATOR
                    tSize.Enabled = false;
                    this.Height = 180;
                    splitContainer1.Panel2Collapsed = true;

                    groupBox1.Text = "Target Address";
                    lStart.Text = "Virtual Address :";
                    bStart.Text = "Translate";
                    break;
                case 2:     // FINDER -> PATTERN -> STRING
                    lStart.Text = "Start Address :";
                    bStart.Text = "Search";
                    groupBox1.Text = "Target Range";

                    lOpt1.Visible = true;
                    tOpt1.Visible = true;
                    lOpt1.Text = "Minimum Length :";

                    splitContainer1.Panel2Collapsed = false;
                    groupBox2.Height = 53;
                    this.Height = 266;
                    break;
                case 3:     // FINDER -> VALUE -> STRING
                    lStart.Text = "Start Address :";
                    bStart.Text = "Search";
                    groupBox1.Text = "Target Range";

                    lOpt1.Visible = true;
                    tOpt1.Visible = true;
                    lOpt1.Text = "Keywords :";

                    lOpt2.Visible = true;
                    tOpt2.Visible = true;
                    lOpt2.Text = "Keywords :";

                    splitContainer1.Panel2Collapsed = false;
                    groupBox2.Height = 53 + 26;
                    this.Height = 266 + 26;

                    break;
                default:
                    this.DialogResult = DialogResult.Abort;
                    return;
            }
            
        }


        private void bStart_Click(object sender, EventArgs e)
        {
            start = this.tStart.Text.Trim();

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
                pMessage[0] = uint.Parse(start, System.Globalization.NumberStyles.HexNumber);
            }
            catch
            {
                MessageBox.Show("Input in HEX.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                tStart.Focus();
                tStart.SelectAll();
                return;
            }

            if (mode == 0)
            {
                size = this.tSize.Text.Trim();

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
                    pMessage[1] = uint.Parse(size, System.Globalization.NumberStyles.HexNumber);
                }
                catch
                {
                    MessageBox.Show("Input in HEX.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    tSize.Focus();
                    tSize.SelectAll();
                    return;
                }
                if (pMessage[1] <= 0)
                {
                    MessageBox.Show("The size must be above 0", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    tSize.Focus();
                    tSize.SelectAll();
                    return;
                }
                else if (pMessage[1] > 4096)
                {
                    MessageBox.Show("The size is allowed up to 0x400.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    tSize.Focus();
                    tSize.SelectAll();
                    return;
                }

                if (SendControlMessageByPointer(IOCTL_FIND_OBJECT_UNICODE, pMessage, 8) == 1)
                {
                    mainForm.conditionStart = pMessage[0];
                    mainForm.conditionSize = pMessage[1];

                    this.DialogResult = DialogResult.OK;
                }
                else
                {
                    this.DialogResult = DialogResult.Abort;
                }

            }
            else if (mode == 1)
            {
                mainForm.conditionStart = pMessage[0];
                this.DialogResult = DialogResult.OK;
            }
            else
            {
                this.DialogResult = DialogResult.Cancel;
            }

            this.Dispose();
            this.Close();
            return;
        }



        private void tSize_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)13)   // "Enter"
            {
                this.bStart_Click(this, null);
                return;
            }
        }

        private void bCancel_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.Cancel;
            return;
        }

        private void tStart_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)13)   // "Enter" 
            {
                this.bStart_Click(this, null);
                return;
            }
        }

    }

}
