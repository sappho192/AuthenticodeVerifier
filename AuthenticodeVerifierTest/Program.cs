using System;

namespace AuthenticodeVerifierTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[[디지털 서명 검사 테스트]]");
            var verifier = new AuthenticodeVerifier.AuthenticodeVerifier();
            verifier.LoadTarget(@"C:\temp\dbk32.sys");
            Console.WriteLine(verifier.Verify());
            verifier.CertificateInfo.PrintInfo();

            verifier.LoadTarget(@"C:\temp\msvcr110.dll");
            Console.WriteLine(verifier.Verify());
            verifier.CertificateInfo.PrintInfo();

            verifier.LoadTarget(@"C:\temp\siegfried.exe");
            Console.WriteLine(verifier.Verify());
            verifier.CertificateInfo.PrintInfo();

            verifier.LoadTarget(@"C:\temp\COMDLG32.OCX");
            Console.WriteLine(verifier.Verify());
            verifier.CertificateInfo.PrintInfo();
        }
    }
}
