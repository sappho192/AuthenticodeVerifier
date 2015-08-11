using System;

namespace AuthenticodeVerifierTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[[디지털 서명 검사 테스트]]");
            var verifier = new AuthenticodeVerifier.AuthenticodeVerifier();
        }
    }
}
