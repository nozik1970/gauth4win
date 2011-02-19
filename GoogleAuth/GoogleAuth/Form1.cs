using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace GoogleAuth
{
    public partial class KeyInput : Form
    {
        int exiting = 0;
        public KeyInput()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            textBox1.Text=Application.UserAppDataRegistry.GetValue("key").ToString();
            notifyIcon1.Text = "Current key is " + textBox1.Text;
        }

        private void KeyInput_SizeChanged(object sender, EventArgs e)
        {
            if (WindowState == FormWindowState.Minimized)
            {
                Hide();
            }

        }

        private void notifyIcon1_DoubleClick(object sender, EventArgs e)
        {
            Clipboard.SetText(lastcode.ToString());
//            modifyKeyToolStripMenuItem_Click(sender, e);
        }

        private void KeyInput_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (exiting == 0)
            {
                e.Cancel = true;
                WindowState = FormWindowState.Minimized;
            }
        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            exiting = 1;
            Application.Exit();
        }

        private void modifyKeyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Show();
            WindowState = FormWindowState.Normal;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Application.UserAppDataRegistry.SetValue("key", textBox1.Text);
//            notifyIcon1.Text = "Current key is " + textBox1.Text;
            WindowState = FormWindowState.Minimized;
        }

        private string calckey(String baseKey, long ts)
        {
            ts /= 30;
            int base32len = baseKey.Length;
            int secretlen = (base32len * 5 + 7) / 8;
            byte[] deckey = MhanoHarkness.Base32Url.FromBase32String(textBox1.Text);
            for (int i = secretlen; i < deckey.Length; i++)
            {
                deckey[i] = 0;
            }

            long chlg=ts;
            byte[] challenge;
            challenge = new byte[8];

            for (int j=7;j>=0;j--) {
                challenge[j]=(byte)((int)chlg&0xff);
                chlg >>= 8;
            }

            //    hmac_sha1(secret, secretLen, challenge, 8, hash, SHA1_DIGEST_LENGTH);

            //Compute sha1 here
            /*
            byte[] tmpkey;
            tmpkey = new byte[64];
            //Create a 64 byte key, by xoring 0x36 with the actual key...
            for (int i = 0; i < secretlen; i++)
            {
                tmpkey[i] = (byte)((int)deckey[i] ^ 0x36);
            }
            //...and initializing the rest to 0^0x36 which is actually 0x36.
            for (int i = secretlen; i < tmpkey.Length; i++)
            {
                tmpkey[i] = 0x36;
            }

            System.Security.Cryptography.HMAC sha1provider = System.Security.Cryptography.HMACSHA1.Create();
            sha1provider.Key = tmpkey;
            byte[] shainner = sha1provider.ComputeHash(challenge);

            //Compute outer digest by padding the key with 0x5c
            for (int i = 0; i < secretlen; i++)
            {
                tmpkey[i] = (byte)((int)deckey[i] ^ 0x5c);
            }
            for (int i = secretlen; i < tmpkey.Length; i++)
            {
                tmpkey[i] = 0x5c;
            }

            sha1provider.Key = tmpkey;
            byte[] result = sha1provider.ComputeHash(shainner);
            */

            System.Security.Cryptography.HMAC sha1prov = System.Security.Cryptography.HMACSHA1.Create();

            sha1prov.Key = deckey;
            byte[] result = sha1prov.ComputeHash(challenge);

            int offset = result[result.Length - 1] & 0xf;

            int truncatedHash = 0;
            for (int j = 0; j < 4; j++)
            {
                truncatedHash <<= 8;
                truncatedHash |= result[offset + j];
            }

            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= 1000000;
            //System.Security.Cryptography.SHA1
            string ret = truncatedHash.ToString();
            if (ret.Length < 6)
            {
                ret.PadLeft(6, '0');
            }
            return ret;
        }

        long lasttime;
        string lastcode;

        private void timer1_Tick(object sender, EventArgs e)
        {
            //here is the papa
            long ticks = DateTime.UtcNow.Ticks - DateTime.Parse("01/01/1970 00:00:00").Ticks;
            ticks /= 10000000; //Convert windows ticks to seconds
            long remainder = ticks % 30;
            System.Resources.ResourceManager rm=Properties.Resources.ResourceManager;
            notifyIcon1.Icon = (Icon)rm.GetObject("ga"+(remainder+1));
            remainder = 30 - remainder;
            if (lasttime != ticks)
            {
                //int key = calckey(textBox1.Text, ticks);
                lastcode = calckey(textBox1.Text, ticks);
                lasttime = ticks;
            }
            notifyIcon1.Text=lastcode.ToString()+" ("+remainder.ToString()+")";
        }

        private void copyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(lastcode.ToString());
        }
    }
}