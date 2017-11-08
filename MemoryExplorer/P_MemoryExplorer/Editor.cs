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
    public partial class Editor : Form
    {
        private fMain mainForm = null;

        [DllImport(fMain.dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.None, SetLastError = true)]
        private static extern byte ManipulateMemory(uint startAddress, uint length, byte[] buffer);


        private uint startAddress = 0;
        private uint count = 0;

        TextBox[] from_RawData = null;
        TextBox[] from_Ascii = null;
        TextBox[] to_RawData = null;
        TextBox[] to_Ascii = null;

        bool isError = false;

        public Editor()
        {
            InitializeComponent();
        }

        public Editor(fMain m, uint of, uint co)
        {
            InitializeComponent();

            this.StartPosition = FormStartPosition.CenterScreen;

            mainForm = m;
            startAddress = of;
            count = co;
        }

        
        private void Editor_Load(object sender, EventArgs e)
        {
            this.Text += string.Format("  [ 0x{0:X8} ]", startAddress);

            from_RawData = new TextBox[] { fr01, fr02, fr03, fr04, fr05, fr06, fr07, fr08, fr09, fr10, fr11, fr12, fr13, fr14, fr15, fr16 };
            from_Ascii = new TextBox[] { fa01, fa02, fa03, fa04, fa05, fa06, fa07, fa08, fa09, fa10, fa11, fa12, fa13, fa14, fa15, fa16 };
            to_RawData = new TextBox[] { tr01, tr02, tr03, tr04, tr05, tr06, tr07, tr08, tr09, tr10, tr11, tr12, tr13, tr14, tr15, tr16 };
            to_Ascii = new TextBox[] { ta01, ta02, ta03, ta04, ta05, ta06, ta07, ta08, ta09, ta10, ta11, ta12, ta13, ta14, ta15, ta16 };

            byte[] origin = new byte[count];

            for(int i = 0; i < count; i++)
            {
                origin[i] = mainForm.memoryDump[(startAddress - mainForm.dumpStartAddress) + 4 + i];

                from_RawData[i].Text = string.Format("{0:X2}", origin[i]);
                to_RawData[i].Text = string.Format("{0:X2}", origin[i]);

                from_Ascii[i].Text = ToAscii(origin[i]);
                to_Ascii[i].Text = ToAscii(origin[i]);

                // 입력 후 포커스를 벗어날 때의 이벤트 핸들러를 생성한다.
                this.to_RawData[i].Leave += new System.EventHandler(InputRawData);
                this.to_Ascii[i].Leave += new System.EventHandler(InputAscii);

                this.to_RawData[i].KeyPress += new System.Windows.Forms.KeyPressEventHandler(PressEnterKey);
                this.to_Ascii[i].KeyPress += new System.Windows.Forms.KeyPressEventHandler(PressEnterKey);

                this.to_RawData[i].Enabled = true;
                this.to_Ascii[i].Enabled = true;
            }
        }

        private void InputRawData(object sender, EventArgs e)
        {
            // Cancel 버튼 클릭 시, 연산하지 않는다.
            if (bCancel.Focused)
                return;

            byte input = 0;

            TextBox con = (TextBox)sender;
            // 공백 제거
            con.Text = con.Text.Trim();

            // 만약 아무값도 입력하지 않는다면, 원본값을 가져오자.
            if (con.Text == "")
            {
                for (int i = 0; i < count; i++)
                {
                    if (con.Name == to_RawData[i].Name)
                    {
                        con.Text = from_RawData[i].Text;
                        break;
                    }
                }
            }
            // 한 글자만 입력됬으면 0을 붙여주자.
            else if (con.Text.Length == 1)
                con.Text = "0" + con.Text;    
                        
            try
            {
                input = byte.Parse(con.Text, System.Globalization.NumberStyles.HexNumber);
                if(input < 0x00 || input > 0xFF)
                {
                    MessageBox.Show("0x00 부터 0xFF 사이의 값만 입력하세요.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    isError = true;
                    con.Focus();
                    con.SelectAll();
                    return;
                }
            }
            catch
            {                
                MessageBox.Show("16진수 값이 아닙니다.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                isError = true;
                con.Focus();
                con.SelectAll();
                return;
            }

            // 몇 번째 컨트롤인지 찾고, 대응하는 Ascii 텍스트 박스의 값을 바꾼다.
            for (int i = 0; i < count; i++)
            {
                if(con.Name == to_RawData[i].Name)
                {
                    to_Ascii[i].Text = ToAscii(input);
                    break;
                }
            }

            isError = false;   
        }

        private void InputAscii(object sender, EventArgs e)
        {
            // Cancel 버튼 클릭 시, 연산하지 않는다.
            if (bCancel.Focused)
                return;

            TextBox con = (TextBox)sender;
            byte input = 0;
            bool isAscii = false;

            // 공백 제거
            con.Text = con.Text.Trim();

            if(con.Text.Length != 1)
            {
                if(con.Text.ToUpper() == "SP")
                {
                    input = 0x20;
                    isAscii = true;
                }
                else if(con.Text == "\\0" || con.Text == "00")
                {
                    input = 0x00;
                    isAscii = true;
                }
                else
                {
                    isAscii = false;
                }               
            }
            else
            {
                try
                {
                    byte[] tmp = Encoding.ASCII.GetBytes(con.Text);
                    input = tmp[0];             
                    isAscii = true;
                }
                // 혹시 변환에 실패할 경우...
                catch
                {
                    isAscii = false;
                    //isError = true;
                    //return;
                }
            }

            if (isAscii)
            {
                // 몇 번째 컨트롤인지 찾고, 대응하는 RawData 텍스트 박스의 값을 바꾼다.
                for (int i = 0; i < count; i++)
                {
                    if (con.Name == to_Ascii[i].Name)
                    {
                        to_RawData[i].Text = string.Format("{0:X2}", input);
                        break;
                    }
                }
                isError = false;
            }
            else
            {
                if (con.Text == "")
                    return;
                MessageBox.Show("ASCII 값이 아닙니다.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                isError = true;
                con.Focus();
                con.SelectAll();
                return;
            }  
        }

        private string ToAscii(Byte data)
        {
            if (data >= 0x20 && data <= 0x7E)
            {
                if (data == 0x20)
                    return "SP";

                return string.Format("{0}", (char)data);
            }
            else if (data == 0x00)
                return "\\0";
            else
                return "";
        }

        private void bCancel_Click(object sender, EventArgs e)
        {
            this.Dispose();
            this.Close();
            return;
        }   

        private void bApply_Click(object sender, EventArgs e)
        {
            //bApply.Focus();
            if (isError)
                return;

            int i = 0;
            // 변경된 데이터가 없으면 그냥 패스.
            for(i = 0; i < count; i++)
            {
                if (from_RawData[i].Text != to_RawData[i].Text.ToUpper())
                    break;
            }
            if(i != count)
            {
                SaveData();
                if (isError)
                {
                    // 이중 검사라 에러 생길 리가 없지만, 일단 걸어둠.
                    return;
                }
            }
  
            this.Dispose();
            this.Close();
            return;     
        }

        private void SaveData()
        {
            byte[] replaced = new byte[8 + count];
            replaced.Initialize();

            for (int i = 0; i < count; i++)
            {
                // 에러 날 경우 없다. 아마도...
                try
                {
                    replaced[i + 8] = byte.Parse(to_RawData[i].Text, System.Globalization.NumberStyles.HexNumber);
                }
                catch
                {
                    MessageBox.Show("16진수 값이 아닙니다.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
           
                    // 여기서 Dispose해도 계속 진행된다. -> 일단, SaveData()까지 왔으면 isError쓸일 없으므로 사용하자.
                    isError = true;
                    return;
                }
            }

            // 드라이버로 수정 메시지 보내고, 성공 시 mainForm.memoryManipulated 셋.
            //      -> 실패 해도 그냥 돌아가자........
            if (1 == ManipulateMemory(startAddress, count, replaced))
            {
                this.DialogResult = DialogResult.OK;
              //  mainForm.memoryManipulated = true;
            }
            else
            {
                MessageBox.Show("Failed to manipulate memory.\n     [Error in driver]", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                this.DialogResult = DialogResult.Abort;
            }

            this.Dispose();
            this.Close();
            return;

        }

        private void PressEnterKey(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)13)
            {
                this.bApply_Click(this, null);
            }
            else if (e.KeyChar == (char)0x1B)
            {
                this.bCancel_Click(this, null);
            }
        }

        
    }
}
