namespace MemoryExplorer
{
    partial class HexViewerConfig
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        { 
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(HexViewerConfig));
            this.tSize = new System.Windows.Forms.TextBox();
            this.tStart = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.bStart = new System.Windows.Forms.Button();
            this.bCancel = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // tSize
            // 
            this.tSize.BackColor = System.Drawing.Color.White;
            this.tSize.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tSize.Location = new System.Drawing.Point(110, 55);
            this.tSize.MaxLength = 8;
            this.tSize.Name = "tSize";
            this.tSize.Size = new System.Drawing.Size(270, 29);
            this.tSize.TabIndex = 11;
            this.tSize.WordWrap = false;
            this.tSize.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.tSize_KeyPress);
            // 
            // tStart
            // 
            this.tStart.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tStart.Location = new System.Drawing.Point(110, 15);
            this.tStart.MaxLength = 8;
            this.tStart.Name = "tStart";
            this.tStart.Size = new System.Drawing.Size(270, 29);
            this.tStart.TabIndex = 10;
            this.tStart.WordWrap = false;
            this.tStart.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.tStart_KeyPress);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(14, 16);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(80, 22);
            this.label1.TabIndex = 13;
            this.label1.Text = "Start :";
            // 
            // bStart
            // 
            this.bStart.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.bStart.Location = new System.Drawing.Point(122, 90);
            this.bStart.Name = "bStart";
            this.bStart.Size = new System.Drawing.Size(120, 34);
            this.bStart.TabIndex = 12;
            this.bStart.Text = "Search";
            this.bStart.UseVisualStyleBackColor = true;
            this.bStart.Click += new System.EventHandler(this.bStart_Click);
            // 
            // bCancel
            // 
            this.bCancel.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.bCancel.Location = new System.Drawing.Point(260, 90);
            this.bCancel.Name = "bCancel";
            this.bCancel.Size = new System.Drawing.Size(120, 34);
            this.bCancel.TabIndex = 15;
            this.bCancel.Text = "Cancel";
            this.bCancel.UseVisualStyleBackColor = true;
            this.bCancel.Click += new System.EventHandler(this.bCancel_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.Location = new System.Drawing.Point(25, 57);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(70, 22);
            this.label2.TabIndex = 14;
            this.label2.Text = "Size :";
            // 
            // HexViewerConfig
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(10F, 18F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(395, 135);
            this.Controls.Add(this.bCancel);
            this.Controls.Add(label2);
            this.Controls.Add(this.tSize);
            this.Controls.Add(this.tStart);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.bStart);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "HexViewerConfig";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox tSize;
        private System.Windows.Forms.TextBox tStart;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button bStart;
        private System.Windows.Forms.Button bCancel;
    }
}