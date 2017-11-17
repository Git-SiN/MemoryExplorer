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
    public partial class IndirectInput : Form
    {
        [DllImport(fMain.dllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.None, SetLastError = true)]
        private static extern byte ManipulateMemory(uint startAddress, uint length, byte[] buffer);
    
        fMain mainForm = null;
        uint maximumLength = 0;
        uint startAddress = 0;

        public IndirectInput()
        {
            InitializeComponent();
        }

        public IndirectInput(fMain m, uint address, uint length, string firstLine)
        {
            InitializeComponent();
           
            mainForm = m;
            maximumLength = length;
            startAddress = address;

            this.Width = 650;
            this.Height = 400;

            //tSize.Text = string.Format("Inputted :  0 bytes / {0} bytes", maximumLength);

            tMessage.Text = "";
            if (firstLine.Length > 0)
                tInput.Text = firstLine;

            this.Text += string.Format("Start Address : 0x{0:X8}", startAddress);
        }

        private void toolStripButton1_Click(object sender, EventArgs e)
        {
            tMessage.Text = "";
            string inputString = "";

            // Remove all blanks.
            string[] tmp = tInput.Text.Split(new char[] { ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries);    
            for (int i = 0; i < tmp.Length; i++)
                inputString += tmp[i];

            // The number of characters must be odd.
            if( inputString.Length % 2 != 0)
            {
                MessageBox.Show("\"A Byte\" must be represented by \"02X\"." , "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                tMessage.Text = "[Err] Incorrect Formatting";
                tInput.Focus();
                return;
            }

            // Bind two by two.
            string[] outputStrings = new string[inputString.Length / 2];
            for(int i = 0; i < inputString.Length / 2; i ++)
                outputStrings[i] = inputString.Substring(i * 2, 2);

            // Aligning
            tInput.Text = "";
            string output = "";
            for(int i  = 0; i < outputStrings.Length; i++)
            {          
                output += outputStrings[i] + " ";

                if ((i + 1) % 16 == 0)
                    output += "\r\n";
                else if ((i + 1) % 8 == 0)
                    output += "  ";
            }
            tInput.Text = output;

            // Length Check
            if (outputStrings.Length > maximumLength)
            {
                MessageBox.Show(string.Format("Exceed range of the current dump. [{0} bytes / {1} bytes]\r\n", outputStrings.Length, maximumLength), "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                tMessage.Text = "[Err] Exceed Limit";
                tInput.Focus();
                return;
            }
             
            // Hexadecimal Check
            string err = null;
            byte[] buffer = new byte[8 + outputStrings.Length];
            buffer.Initialize();

            for (int i = 0; i < outputStrings.Length; i++)
            {
                try
                {
                    buffer[i + 8] = byte.Parse(outputStrings[i], System.Globalization.NumberStyles.HexNumber);
                }
                catch
                {
                    err = outputStrings[i];
                    MessageBox.Show(String.Format("\"{0}\" is not the Hexadecimal.", err), "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    tInput.Focus();
                    tInput.Select(tInput.Text.IndexOf(err, 0), 2);
                    tMessage.Text = "[Err] Incorrect value";
                    return;
                }
            }

            // Pass the whole Check .
            if (DialogResult.Yes == MessageBox.Show("Pass the whole Check.\r\nApply this manipulation?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Information))
            {
                try
                {
                    // If Failed, just return to Main Form.
                    if (1 == ManipulateMemory(startAddress, (uint)(outputStrings.Length), buffer))
                    {
                        this.DialogResult = DialogResult.OK;
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
                catch
                {
                    tMessage.Text = string.Format("[Err] Manipulation Failed.");
                    tInput.Focus();
                }

            }
            else
                return;
        }

        private int GetSize()
        {
            string nonBlank = "";

            // Remove Blanks.
            string[] tmp = tInput.Text.Split(new char[] { ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < tmp.Length; i++)
                nonBlank += tmp[i];
            
            // Just Return for ".5".
            return nonBlank.Length;

        }

        // Calculate the Length Every Input.
        private void tInput_TextChanged(object sender, EventArgs e)
        {
            int currentSize = GetSize();

            // Express ".5"
            if(currentSize % 2 != 0)
                tSize.Text = string.Format("Size : {0}.5 bytes / {1} bytes", currentSize / 2, maximumLength);
            else
            {
                tSize.Text = string.Format("Size :   {0} bytes / {1} bytes", currentSize / 2, maximumLength);
                if (currentSize >= maximumLength)
                    tSize.ForeColor = Color.Red;
            }
        }
    }
}
