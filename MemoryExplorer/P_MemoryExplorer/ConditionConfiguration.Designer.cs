﻿namespace MemoryExplorer
{
    partial class ConditionConfiguration
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
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.bCancel = new System.Windows.Forms.Button();
            this.bStart = new System.Windows.Forms.Button();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.tSize = new System.Windows.Forms.TextBox();
            this.tStart = new System.Windows.Forms.TextBox();
            this.lSize = new System.Windows.Forms.Label();
            this.lStart = new System.Windows.Forms.Label();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.cRange = new System.Windows.Forms.ComboBox();
            this.lRange = new System.Windows.Forms.Label();
            this.tOpt4 = new System.Windows.Forms.TextBox();
            this.lOpt4 = new System.Windows.Forms.Label();
            this.tOpt3 = new System.Windows.Forms.TextBox();
            this.lOpt3 = new System.Windows.Forms.Label();
            this.tOpt2 = new System.Windows.Forms.TextBox();
            this.lOpt2 = new System.Windows.Forms.Label();
            this.tOpt1 = new System.Windows.Forms.TextBox();
            this.lOpt1 = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.SuspendLayout();
            // 
            // splitContainer1
            // 
            this.splitContainer1.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
            this.splitContainer1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer1.FixedPanel = System.Windows.Forms.FixedPanel.Panel1;
            this.splitContainer1.Location = new System.Drawing.Point(0, 0);
            this.splitContainer1.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.splitContainer1.Name = "splitContainer1";
            this.splitContainer1.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // splitContainer1.Panel1
            // 
            this.splitContainer1.Panel1.Controls.Add(this.bCancel);
            this.splitContainer1.Panel1.Controls.Add(this.bStart);
            this.splitContainer1.Panel1.Controls.Add(this.groupBox1);
            this.splitContainer1.Panel1MinSize = 150;
            // 
            // splitContainer1.Panel2
            // 
            this.splitContainer1.Panel2.Controls.Add(this.groupBox2);
            this.splitContainer1.Panel2MinSize = 0;
            this.splitContainer1.Size = new System.Drawing.Size(478, 538);
            this.splitContainer1.SplitterDistance = 150;
            this.splitContainer1.SplitterWidth = 2;
            this.splitContainer1.TabIndex = 0;
            this.splitContainer1.TabStop = false;
            // 
            // bCancel
            // 
            this.bCancel.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.bCancel.Location = new System.Drawing.Point(316, 157);
            this.bCancel.Name = "bCancel";
            this.bCancel.Size = new System.Drawing.Size(150, 35);
            this.bCancel.TabIndex = 22;
            this.bCancel.Text = "Cancel";
            this.bCancel.UseVisualStyleBackColor = true;
            this.bCancel.Click += new System.EventHandler(this.bCancel_Click);
            // 
            // bStart
            // 
            this.bStart.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.bStart.Location = new System.Drawing.Point(147, 157);
            this.bStart.Name = "bStart";
            this.bStart.Size = new System.Drawing.Size(150, 35);
            this.bStart.TabIndex = 21;
            this.bStart.Text = "Start";
            this.bStart.UseVisualStyleBackColor = true;
            this.bStart.Click += new System.EventHandler(this.bStart_Click);
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.tSize);
            this.groupBox1.Controls.Add(this.tStart);
            this.groupBox1.Controls.Add(this.lSize);
            this.groupBox1.Controls.Add(this.lStart);
            this.groupBox1.Font = new System.Drawing.Font("Consolas", 11F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox1.ForeColor = System.Drawing.SystemColors.ControlDarkDark;
            this.groupBox1.Location = new System.Drawing.Point(16, 12);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(450, 130);
            this.groupBox1.TabIndex = 0;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Target Range";
            // 
            // tSize
            // 
            this.tSize.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tSize.Location = new System.Drawing.Point(208, 77);
            this.tSize.MaxLength = 8;
            this.tSize.Name = "tSize";
            this.tSize.Size = new System.Drawing.Size(233, 29);
            this.tSize.TabIndex = 1;
            this.tSize.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.t_KeyPress);
            // 
            // tStart
            // 
            this.tStart.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tStart.Location = new System.Drawing.Point(208, 38);
            this.tStart.MaxLength = 8;
            this.tStart.Name = "tStart";
            this.tStart.Size = new System.Drawing.Size(233, 29);
            this.tStart.TabIndex = 0;
            this.tStart.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.t_KeyPress);
            // 
            // lSize
            // 
            this.lSize.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lSize.ForeColor = System.Drawing.SystemColors.ControlText;
            this.lSize.Location = new System.Drawing.Point(13, 79);
            this.lSize.Name = "lSize";
            this.lSize.Size = new System.Drawing.Size(190, 25);
            this.lSize.TabIndex = 1;
            this.lSize.Text = "Size :";
            this.lSize.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // lStart
            // 
            this.lStart.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lStart.ForeColor = System.Drawing.SystemColors.ControlText;
            this.lStart.Location = new System.Drawing.Point(13, 41);
            this.lStart.Name = "lStart";
            this.lStart.Size = new System.Drawing.Size(190, 25);
            this.lStart.TabIndex = 0;
            this.lStart.Text = "Start Address :";
            this.lStart.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.cRange);
            this.groupBox2.Controls.Add(this.lRange);
            this.groupBox2.Controls.Add(this.tOpt4);
            this.groupBox2.Controls.Add(this.lOpt4);
            this.groupBox2.Controls.Add(this.tOpt3);
            this.groupBox2.Controls.Add(this.lOpt3);
            this.groupBox2.Controls.Add(this.tOpt2);
            this.groupBox2.Controls.Add(this.lOpt2);
            this.groupBox2.Controls.Add(this.tOpt1);
            this.groupBox2.Controls.Add(this.lOpt1);
            this.groupBox2.Font = new System.Drawing.Font("Consolas", 11F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox2.ForeColor = System.Drawing.SystemColors.ControlDarkDark;
            this.groupBox2.Location = new System.Drawing.Point(16, 12);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(449, 242);
            this.groupBox2.TabIndex = 0;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Optional";
            // 
            // cRange
            // 
            this.cRange.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cRange.FormattingEnabled = true;
            this.cRange.Items.AddRange(new object[] {
            "Specified",
            "WorkingSet - Whole",
            "WorkingSet - UserMode",
            "WorkingSet - KernelMode"});
            this.cRange.Location = new System.Drawing.Point(208, 32);
            this.cRange.Name = "cRange";
            this.cRange.Size = new System.Drawing.Size(233, 30);
            this.cRange.TabIndex = 10;
            this.cRange.SelectedIndexChanged += new System.EventHandler(this.cRange_SelectedIndexChanged);
            // 
            // lRange
            // 
            this.lRange.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lRange.ForeColor = System.Drawing.SystemColors.ControlText;
            this.lRange.Location = new System.Drawing.Point(13, 34);
            this.lRange.Name = "lRange";
            this.lRange.Size = new System.Drawing.Size(190, 25);
            this.lRange.TabIndex = 12;
            this.lRange.Text = "Range :";
            this.lRange.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // tOpt4
            // 
            this.tOpt4.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tOpt4.Location = new System.Drawing.Point(208, 197);
            this.tOpt4.MaxLength = 256;
            this.tOpt4.Name = "tOpt4";
            this.tOpt4.Size = new System.Drawing.Size(233, 29);
            this.tOpt4.TabIndex = 2;
            this.tOpt4.TabStop = false;
            this.tOpt4.Visible = false;
            this.tOpt4.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.t_KeyPress);
            // 
            // lOpt4
            // 
            this.lOpt4.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lOpt4.ForeColor = System.Drawing.SystemColors.ControlText;
            this.lOpt4.Location = new System.Drawing.Point(13, 199);
            this.lOpt4.Name = "lOpt4";
            this.lOpt4.Size = new System.Drawing.Size(190, 25);
            this.lOpt4.TabIndex = 11;
            this.lOpt4.Text = "Optional :";
            this.lOpt4.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.lOpt4.Visible = false;
            // 
            // tOpt3
            // 
            this.tOpt3.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tOpt3.Location = new System.Drawing.Point(208, 156);
            this.tOpt3.MaxLength = 256;
            this.tOpt3.Name = "tOpt3";
            this.tOpt3.Size = new System.Drawing.Size(233, 29);
            this.tOpt3.TabIndex = 2;
            this.tOpt3.TabStop = false;
            this.tOpt3.Visible = false;
            this.tOpt3.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.t_KeyPress);
            // 
            // lOpt3
            // 
            this.lOpt3.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lOpt3.ForeColor = System.Drawing.SystemColors.ControlText;
            this.lOpt3.Location = new System.Drawing.Point(13, 158);
            this.lOpt3.Name = "lOpt3";
            this.lOpt3.Size = new System.Drawing.Size(190, 25);
            this.lOpt3.TabIndex = 9;
            this.lOpt3.Text = "Optional :";
            this.lOpt3.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.lOpt3.Visible = false;
            // 
            // tOpt2
            // 
            this.tOpt2.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tOpt2.Location = new System.Drawing.Point(208, 115);
            this.tOpt2.MaxLength = 256;
            this.tOpt2.Name = "tOpt2";
            this.tOpt2.Size = new System.Drawing.Size(233, 29);
            this.tOpt2.TabIndex = 2;
            this.tOpt2.TabStop = false;
            this.tOpt2.Visible = false;
            this.tOpt2.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.t_KeyPress);
            // 
            // lOpt2
            // 
            this.lOpt2.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lOpt2.ForeColor = System.Drawing.SystemColors.ControlText;
            this.lOpt2.Location = new System.Drawing.Point(13, 117);
            this.lOpt2.Name = "lOpt2";
            this.lOpt2.Size = new System.Drawing.Size(190, 25);
            this.lOpt2.TabIndex = 7;
            this.lOpt2.Text = "Optional :";
            this.lOpt2.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.lOpt2.Visible = false;
            // 
            // tOpt1
            // 
            this.tOpt1.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tOpt1.Location = new System.Drawing.Point(208, 74);
            this.tOpt1.MaxLength = 256;
            this.tOpt1.Name = "tOpt1";
            this.tOpt1.Size = new System.Drawing.Size(233, 29);
            this.tOpt1.TabIndex = 2;
            this.tOpt1.TabStop = false;
            this.tOpt1.Visible = false;
            this.tOpt1.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.t_KeyPress);
            // 
            // lOpt1
            // 
            this.lOpt1.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lOpt1.ForeColor = System.Drawing.SystemColors.ControlText;
            this.lOpt1.Location = new System.Drawing.Point(13, 76);
            this.lOpt1.Name = "lOpt1";
            this.lOpt1.Size = new System.Drawing.Size(190, 25);
            this.lOpt1.TabIndex = 5;
            this.lOpt1.Text = "Optional :";
            this.lOpt1.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.lOpt1.Visible = false;
            // 
            // ConditionConfiguration
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(144F, 144F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            this.ClientSize = new System.Drawing.Size(478, 538);
            this.Controls.Add(this.splitContainer1);
            this.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.Name = "ConditionConfiguration";
            this.Text = "Condition Configuration";
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.Button bStart;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.Label lStart;
        private System.Windows.Forms.TextBox tSize;
        private System.Windows.Forms.TextBox tStart;
        private System.Windows.Forms.Label lSize;
        private System.Windows.Forms.Button bCancel;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.TextBox tOpt4;
        private System.Windows.Forms.Label lOpt4;
        private System.Windows.Forms.TextBox tOpt3;
        private System.Windows.Forms.Label lOpt3;
        private System.Windows.Forms.TextBox tOpt2;
        private System.Windows.Forms.Label lOpt2;
        private System.Windows.Forms.TextBox tOpt1;
        private System.Windows.Forms.Label lOpt1;
        private System.Windows.Forms.ComboBox cRange;
        private System.Windows.Forms.Label lRange;
    }
}