using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using AuthenticodeVerifierTest.Certificates;

namespace AuthenticodeVerifierTest.AuthenticodeVerifier
{
    /// <summary>
    /// x509 인증서의 정보를 얻고 검증할 수 있는 클래스입니다.
    /// </summary>
    public class CertificateVerifier : Verifier
    {
        public CertificateVerifier()
        {
            _certificateStore = new CertificateStore();
        }
        public override bool Verify()
        {
            Initialize();
            if (!ExtractCert()) return false;

            ResultPrimary = _mainCert.Verify();
            if (!ResultPrimary) ResultAdvanced = VerifyAdvanced();   // 기본 검증에 실패했을 때만 수행

            return ResultPrimary || ResultAdvanced;
        }

        public override string GetResult()
        {
            var stringBuilder = new StringBuilder();
            stringBuilder.AppendLine("[디지털 서명]");
            stringBuilder.AppendLine("유효 여부: " + (ResultPrimary || ResultAdvanced ? "유효" : "무효"));

            return stringBuilder.ToString();
        }

        public override void PrintResult()
        {
            Console.Write(GetResult());
        }

        public override bool LoadTarget(string filePath)
        {
            if (!File.Exists(filePath)) return false;
            _targetPath = filePath;
            return true;
        }

        private void Initialize()
        {
            _basicCert = null;  // 할당은 ExtractCert()에서...
            _mainCert = null;   // 할당은 ExtractCert()에서...
            _keyChain = new X509Chain();
        }

        private bool ExtractCert()
        {
            try
            {
                _basicCert = X509Certificate.CreateFromSignedFile(_targetPath);
            }
            catch (CryptographicException)
            {
                //PrintLineConsole("해당 파일에는 인증서가 없는 것 같습니다.");
                return false;
            }
            _mainCert = new X509Certificate2(_basicCert);
            return true;
        }

        private bool VerifyAdvanced()
        {
            _keyChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            _keyChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            _keyChain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(1000);
            _keyChain.ChainPolicy.VerificationTime = DateTime.Now;
            try
            {
                var elementValid = _keyChain.Build(_mainCert);
                //PrintLineConsole(string.Format("keyChain building status: {0}", elementValid));
                if (elementValid == false)
                {
                    foreach (X509ChainStatus chainStatus in _keyChain.ChainStatus)
                    {
                        //PrintLineConsole(string.Format("keyChain error: {0} {1}", chainStatus.Status, chainStatus.StatusInformation));
                        if (chainStatus.Status != X509ChainStatusFlags.NotTimeValid) continue;
                        //PrintLineConsole("현재 인증서는 만료되었습니다.");
                        //AddCertNote("현재 인증서는 만료되었습니다.");
                        // 인증서 기한은 만료되었는데 부모 인증서들은 유효한 경우
                        if (VerifyParentCert())
                        {
                            //PrintLineConsole("부모 인증서는 유효합니다.");
                            //AddCertNote("부모 인증서는 유효합니다.");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine(ex.ToString());
            }
            return false;
        }

        /// <summary>
        /// 부모 인증서를 획득한 후 검증합니다.
        /// </summary>
        /// <returns>검증 결과</returns>
        private bool VerifyParentCert()
        {
            //foreach (var chain in _keyChain.ChainElements)
            //{
            //    Console.WriteLine("체인 유효성: " + chain.Certificate.Verify());
            //}
            if (VerifyParentCertURL())
            {
                return true;
            }
            if (VerifyParentCertWithStore())
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// 부모 인증서를 다운로드 받아 검사할 수 있는 경우의 검증방법입니다.
        /// </summary>
        /// <returns>검증 결과</returns>
        private bool VerifyParentCertURL()
        {
            string url = GetParentCertURL();
            if (url.Equals(""))
            {
                return false;
            }
            Match match = Regex.Match(url, @".{0,}\/(.{0,}.crt)");
            string fileName = match.Groups[1].Value;

            using (var client = new WebClient())
            {
                try
                {
                    client.DownloadFile(url, fileName);
                }
                catch (WebException ex)
                {
                    //PrintLineConsole("파일 다운로드에 실패했습니다.");
                    //PrintLineConsole("사유: " + ex.Message);
                    //AddCertNote("부모 인증서를 다운로드하지 못했습니다.");
                    return false;
                }
            }

            CertificateVerifier parentVerifier = new CertificateVerifier();
            if (!parentVerifier.LoadTarget(fileName)) return false;
            if (!parentVerifier.Verify()) return false;

            // 검증을 위해 임시로 받았던 부모 인증서를 제거
            if (!File.Exists(fileName)) return true;
            try
            {
                File.Delete(fileName);
            }
            catch (IOException ex)
            {
                Console.WriteLine(ex.Message);
            }
            return true;
        }

        /// <summary>
        /// 사용자 컴퓨터에 저장된 인증서들 중 부모 인증서와 같은 것이 있는지 찾습니다.
        /// 같은 것이 있으면 로컬 저장소에 있는 인증서가 유효한지 검사합니다.
        /// </summary>
        /// <returns>검사 결과</returns>
        private bool VerifyParentCertWithStore()
        {
            string storeCert;
            string mainCert;
            int index;
            foreach (var cert in _certificateStore.IntermediateCertList)
            {
                storeCert = cert.SubjectName.Name;
                if (storeCert != null)
                {
                    index = storeCert.IndexOf(",", StringComparison.Ordinal);
                    storeCert = storeCert.Substring(3, index - 3);

                    mainCert = _mainCert.IssuerName.Name;
                    if (mainCert != null)
                    {
                        index = mainCert.IndexOf(",", StringComparison.Ordinal);
                        mainCert = mainCert.Substring(3, index - 3);

                        if (!storeCert.Equals(mainCert)) continue;
                    }
                }
                //PrintLineConsole("부모 인증서가 로컬 저장소에 존재합니다.");
                //AddCertNote("부모 인증서가 로컬 저장소에 존재합니다.");

                if (cert.Verify()) return true;
            }
            foreach (var cert in _certificateStore.AuthRootCertList)
            {
                storeCert = cert.SubjectName.Name;
                if (storeCert != null)
                {
                    index = storeCert.IndexOf(",", StringComparison.Ordinal);
                    storeCert = storeCert.Substring(3, index - 3);

                    mainCert = _mainCert.IssuerName.Name;
                    if (mainCert != null)
                    {
                        index = mainCert.IndexOf(",", StringComparison.Ordinal);
                        mainCert = mainCert.Substring(3, index - 3);

                        if (!storeCert.Equals(mainCert)) continue;
                    }
                }
                //PrintLineConsole("부모 인증서가 로컬 저장소에 존재합니다.");
                //AddCertNote("부모 인증서가 로컬 저장소에 존재합니다.");

                if (cert.Verify()) return true;
            }
            foreach (var cert in _certificateStore.RootCertList)
            {
                storeCert = cert.SubjectName.Name;
                if (storeCert != null)
                {
                    index = storeCert.IndexOf(",", StringComparison.Ordinal);
                    storeCert = storeCert.Substring(3, index - 3);

                    mainCert = _mainCert.IssuerName.Name;
                    if (mainCert != null)
                    {
                        index = mainCert.IndexOf(",", StringComparison.Ordinal);
                        mainCert = mainCert.Substring(3, index - 3);

                        if (!storeCert.Equals(mainCert)) continue;
                    }
                }
                //PrintLineConsole("부모 인증서가 로컬 저장소에 존재합니다.");
                //AddCertNote("부모 인증서가 로컬 저장소에 존재합니다.");

                if (cert.Verify()) return true;
            }
            return false;
        }
        /// <summary>
        /// 부모 인증서를 받을 수 있는 주소를 반환합니다.
        /// </summary>
        /// <returns>부모 인증서의 URL</returns>
        public string GetParentCertURL(bool silently = false)
        {
            string result;
            string rawData = _mainCert.ToString(true);

            int start = rawData.IndexOf("Authority Info Access", StringComparison.Ordinal);
            if (start < 0)
            {
                if (silently)
                {
                    return "";
                }

                //PrintLineConsole("부모 인증서의 URL이 존재하지 않습니다.");
                //AddCertNote("부모 인증서의 URL이 존재하지 않습니다.");
                return "";
            }
            rawData = rawData.Substring(start, rawData.Length - start);

            Match match = Regex.Match(rawData, @"URL=(.{0,}crt)");
            result = match.Groups[1].Value;

            return result;
        }

        private string _targetPath;
        private X509Certificate _basicCert;
        private X509Certificate2 _mainCert;
        private X509Chain _keyChain;
        private readonly CertificateStore _certificateStore;

        public bool ResultPrimary { get; set; }
        public bool ResultAdvanced { get; set; }
    }
}