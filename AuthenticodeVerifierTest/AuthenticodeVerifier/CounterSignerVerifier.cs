/*
 * TaeIn Kim <sappho192@gmail.com>
 * 2015-08-11
 * 
 * CounterSignerVerifier 클래스
 */

using System;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using AuthenticodeVerifierTest.Certificates;

namespace AuthenticodeVerifierTest.AuthenticodeVerifier
{
    /// <summary>
    /// 연대 디지털 서명의 유효성을 검사할 수 있는 클래스입니다.
    /// </summary>
    public class CounterSignerVerifier : Verifier
    {
        /// <summary>
        /// 기본 생성자입니다. LoadTarget()으로 파일을 부르고 Verify()를 호출해 검사를 진행하세요.
        /// </summary>
        public CounterSignerVerifier()
        {
        }

        public override bool Verify()
        {
            // 마지막으로 한 번 더 하는 경로 검증
            if (_targetPath == null || !LoadTarget(_targetPath))
            {
                return false;
            }

            Initialize();
            // 연대 서명으로부터 인증서, 타임스탬프 등의 정보를 가져옴
            if (!WinCrypt32.GetCounterSignerInfo(_targetPath, ref _counterCertificate, ref SigningTime))
            {
                return false;
            }

            // 연대 서명의 인증서를 가져와서 CertificateVerifier로 검사해야함
            _counterCertificateVerifier.LoadTargetDirect(_counterCertificate);
            if (_counterCertificateVerifier.VerifyDirect())
            {
                return true;
            }

            return false;
        }

        public override string GetResult()
        {
            throw new System.NotImplementedException();
        }

        public override void PrintResult()
        {
            Console.Write(GetResult());
        }

        /// <summary>
        /// 검사할 대상을 지정합니다. true가 반환되면 Verify()를 호출해 검사를 진행합니다.
        /// </summary>
        /// <param name="filePath">대상의 경로(절대, 상대 모두 가능)</param>
        public override bool LoadTarget(string filePath)
        {
            if (!File.Exists(filePath)) return false;
            _targetPath = filePath;
            return true;
        }

        private void Initialize()
        {
            _counterCertificateVerifier = new CertificateVerifier();
            _counterCertificate = null;
            SigningTime = null;
        }

        public bool ResultCertificate { get; set; }

        public CertificateInfo CertificateInfo
        {
            get { return _counterCertificateVerifier.CertificateInfo; }
        }
        public Pkcs9SigningTime SigningTime;

        private string _targetPath;
        private CertificateVerifier _counterCertificateVerifier;
        private X509Certificate2 _counterCertificate;
    }
}