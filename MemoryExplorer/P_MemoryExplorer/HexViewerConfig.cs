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
    public partial class HexViewerConfig : Form
    {

        [DllImport(fMain.dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = true)]
        static extern private byte SendControlMessageByPointer(byte control, uint[] pMessage, uint length);

        const byte IOCTL_FIND_PATTERN_UNICODE = 0x80;


        fMain mainForm = null;

        string start = null;
        string size = null;
        byte mode = 0;
        uint[] pMessage = new uint[2];
        

        public HexViewerConfig()
        {
            InitializeComponent();
        }

        /// <summary>
        /// 1 : Hex Editor / 2 : Disassembler
        /// </summary>
        /// <param name="form"></param>
        /// <param name="mode"></param>
        public HexViewerConfig(fMain f, Byte m, string n)
        {
            InitializeComponent();
            mainForm = f;
            mode = m;

            if(mode == 0)
            {
                label1.Text = "Start : ";
                bStart.Text = "Search";
            }
            else if(mode == 1)
            {
                label2.Visible = false;
                tSize.Visible = false;

                label1.Text = "V.A : ";
                bStart.Text = "Translate";
            }
            else
            {
                this.DialogResult = DialogResult.Abort;
                return;
            }

            this.Text = n;
        }


        private void bStart_Click(object sender, EventArgs e)
        {
            start = this.tStart.Text.Trim();
      
            // Start 값 예외처리
            try
            {
                pMessage[0] = uint.Parse(start, System.Globalization.NumberStyles.HexNumber);
            }
            catch
            {
                MessageBox.Show("1Input in HEX above 0", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                tStart.Focus();
                tStart.SelectAll();
                return;
            }
            if (pMessage[0] <= 0)
            {
                MessageBox.Show("2Input in HEX above 0", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                tStart.Focus();
                tStart.SelectAll();
                return;
            }

            if (mode == 0)
            {
                size = this.tSize.Text.Trim();

                // Size 값 예외처리
                try
                {
                    pMessage[1] = uint.Parse(size, System.Globalization.NumberStyles.HexNumber);
                }
                catch
                {
                    MessageBox.Show("3Input in HEX above 0", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    tSize.Focus();
                    tSize.SelectAll();
                    return;
                }
                if (pMessage[1] <= 0)
                {
                    MessageBox.Show("Input in HEX above 0", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    tSize.Focus();
                    tSize.SelectAll();
                    return;
                }

                if (SendControlMessageByPointer(IOCTL_FIND_PATTERN_UNICODE, pMessage, 8) == 1)
                {
                    this.DialogResult = DialogResult.OK;
                }
                else
                {
                    this.DialogResult = DialogResult.Abort;
                }
                
            }
            else if(mode == 1)
            {
                mainForm.addressTranslator = pMessage[0];
                this.DialogResult = DialogResult.OK;
            }
            else
            {
                this.DialogResult = DialogResult.Cancel;
            }
            //this.Dispose();
            //this.Close();
            return;
        }


        //private void tStart_Leave(object sender, EventArgs e)
        //{
        //    if(tStart.Text.Length > 0)
        //    {
        //        start = this.tStart.Text;

        //        // Start 값 예외처리
        //        try
        //        {
        //            pMessage[0] = uint.Parse(start, System.Globalization.NumberStyles.HexNumber);
        //        }
        //        catch
        //        {
        //            MessageBox.Show("16진수 값으로 입력하세요.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        //            tStart.Focus();
        //            tStart.SelectAll();
        //            return;
        //        }
        //        if (pMessage[0] < 0)
        //        {
        //            MessageBox.Show("0보다 크고 파일 크기보다 작아야 합니다.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        //            tStart.Focus();
        //            tStart.SelectAll();
        //            return;
        //        }
        //    }
            

        //}

        private void tSize_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)13)   // Enter 의 키 코드
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
            if (e.KeyChar == (char)13)   // Enter 의 키 코드
            {
                this.bStart_Click(this, null);
                return;
            }
        }
    }
    
}
