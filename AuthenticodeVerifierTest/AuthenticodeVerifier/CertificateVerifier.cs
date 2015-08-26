using System;
using System.Diagnostics;
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
            CertificateInfo = new CertificateInfo();
            // 나머지 멤버 변수들은 Initalize()를 통해 늦은 초기화를 겪습니다.
        }
        public override bool Verify()
        {
            // 마지막으로 한 번 더 하는 경로 검증
            if (_targetPath == null || !LoadTarget(_targetPath))
            {
                return false;
            }


            Initialize();
            if (!ExtractCert()) return false;

            ResultPrimary = _mainCert.Verify();
            if (!ResultPrimary) ResultAdvanced = VerifyAdvanced();   // 기본 검증에 실패했을 때만 수행

            GetCertInfo();
            return ResultPrimary || ResultAdvanced;
        }

        /// <summary>
        /// 검사 결과를 문자열로 반환합니다. Verify() 혹은 VerifyDirect()가 선행되어야 합니다.
        /// </summary>
        /// <returns></returns>
        public override string GetResult()
        {
            var stringBuilder = new StringBuilder();
            stringBuilder.AppendLine("[디지털 인증서]");
            stringBuilder.AppendLine("유효 여부: " + (ResultPrimary || ResultAdvanced ? "유효" : "무효"));

            return stringBuilder.ToString();
        }

        /// <summary>
        /// 검사 결과를 콘솔 창에 출력합니다. Verify() 혹은 VerifyDirect()가 선행되어야 합니다.
        /// </summary>
        public override void PrintResult()
        {
            Console.Write(GetResult());
        }

        /// <summary>
        /// 검사할 대상을 지정합니다. true가 반환되면 Verify()를 호출해 검사를 진행하세요.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public override bool LoadTarget(string filePath)
        {
            if (!File.Exists(filePath)) return false;
            _targetPath = filePath;
            return true;
        }

        /// <summary>
        /// X509Certificate2 객체를 가지고 있을 때 호출할 수 있습니다.
        /// VerifyDirect()를 호출하면 검사를 수행합니다.
        /// </summary>
        /// <param name="target"></param>
        public void LoadTargetDirect(X509Certificate2 target)
        {
            _mainCert = target;
            _parentCertURL = GetParentCertURL();
        }

        /// <summary>
        /// 인증서가 유효한지 검사합니다. LoadTargetDirect가 반드시 선행되어야 합니다.
        /// </summary>
        /// <returns></returns>
        public bool VerifyDirect()
        {
            InitializeDirect();

            ResultPrimary = _mainCert.Verify();
            if (!ResultPrimary) ResultAdvanced = VerifyAdvanced();   // 기본 검증에 실패했을 때만 수행

            GetCertInfo();
            return ResultPrimary || ResultAdvanced;
        }

        /// <summary>
        /// 하나의 인스턴스에 여러 개의 파일을 넣어 검사할 경우에 대비해 초기화 구문을 분리했습니다.
        /// </summary>
        private void Initialize()
        {
            _mainCert = null;   // 할당은 ExtractCert()에서...
            _parentCertURL = "null";
            _keyChain = new X509Chain();
            CertificateInfo = new CertificateInfo();
        }

        /// <summary>
        /// _mainCert가 이미 초기화된 상태이므로 다른 멤버 변수들만 초기화합니다.
        /// </summary>
        private void InitializeDirect()
        {
            _keyChain = new X509Chain();
            CertificateInfo = new CertificateInfo();
        }

        /// <summary>
        /// 지정한 파일에서 디지털 서명의 객체를 추출합니다.
        /// </summary>
        /// <returns></returns>
        private bool ExtractCert()
        {
            try
            {
                _mainCert = new X509Certificate2(X509Certificate.CreateFromSignedFile(_targetPath));
                _parentCertURL = GetParentCertURL(); // 부모 인증서의 주소를 얻음

                return true;
            }
            catch (CryptographicException)
            {
                //("해당 파일에는 인증서가 없는 것 같습니다.");
                return false;
            }
        }

        /// <summary>
        /// 시스템의 기본 검증 정책을 통과하지 못했을 경우 세부적으로 다시 검증합니다.
        /// </summary>
        /// <returns></returns>
        private bool VerifyAdvanced()
        {
            _keyChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            _keyChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            _keyChain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(1000);
            _keyChain.ChainPolicy.VerificationTime = DateTime.Now;
            try
            {
                var elementValid = _keyChain.Build(_mainCert);
                //(string.Format("keyChain building status: {0}", elementValid));
                if (elementValid == false)
                {
                    foreach (X509ChainStatus chainStatus in _keyChain.ChainStatus)
                    {
                        //(string.Format("keyChain error: {0} {1}", chainStatus.Status, chainStatus.StatusInformation));
                        if (chainStatus.Status != X509ChainStatusFlags.NotTimeValid) continue;
                        AddCertNote("현재 인증서는 만료되었습니다.");

                        // 인증서 기한은 만료되었으므로 부모 인증서는 만료되었는지 체크함
                        if (VerifyParentCert())
                        {
                            AddCertNote("부모 인증서는 유효합니다.");
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AddCertNote("CertificateVerifier::VerifyAdvanced(): " + ex);
            }
            return false;
        }

        /// <summary>
        /// 부모 인증서를 획득한 후 검증합니다.
        /// </summary>
        /// <returns>검증 결과</returns>
        private bool VerifyParentCert()
        {
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
            string url = _parentCertURL;
            if (url.Equals("null"))
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
                    AddCertNote("부모 인증서를 다운로드하지 못했습니다. 사유: " + ex.Message);
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
            // 현재는 같은 것이 있는지를 CN값만 가지고 찾지만 추가적인 방법도 만들어서 정확성을 높여야 함.

            string storeCert;
            string mainCert = _mainCert.IssuerName.Name;

            Debug.Assert(mainCert != null, "mainCert != null");
            var index = mainCert.IndexOf(",", StringComparison.Ordinal);
            // 인증서의 CN 값만 추출함
            mainCert = index > -1 ? mainCert.Substring(3, index - 3) : mainCert.Substring(3, mainCert.Length - 3);

            foreach (var cert in _certificateStore.IntermediateCertList)
            {
                storeCert = cert.SubjectName.Name;
                if (storeCert != null)
                {
                    index = storeCert.IndexOf(",", StringComparison.Ordinal);
                    storeCert = index > -1 ? storeCert.Substring(3, index - 3) : storeCert.Substring(3, storeCert.Length - 3);
                    if (!storeCert.Equals(mainCert)) continue;
                }
                AddCertNote("부모 인증서가 로컬 저장소에 존재합니다.");

                if (cert.Verify()) return true;
            }
            foreach (var cert in _certificateStore.AuthRootCertList)
            {
                storeCert = cert.SubjectName.Name;
                if (storeCert != null)
                {
                    index = storeCert.IndexOf(",", StringComparison.Ordinal);
                    storeCert = index > -1 ? storeCert.Substring(3, index - 3) : storeCert.Substring(3, storeCert.Length - 3);

                    if (!storeCert.Equals(mainCert)) continue;
                }
                AddCertNote("부모 인증서가 로컬 저장소에 존재합니다.");

                if (cert.Verify()) return true;
            }
            foreach (var cert in _certificateStore.RootCertList)
            {
                storeCert = cert.SubjectName.Name;
                if (storeCert != null)
                {
                    index = storeCert.IndexOf(",", StringComparison.Ordinal);
                    storeCert = index > -1 ? storeCert.Substring(3, index - 3) : storeCert.Substring(3, storeCert.Length - 3);

                    if (!storeCert.Equals(mainCert)) continue;
                }
                AddCertNote("부모 인증서가 로컬 저장소에 존재합니다.");

                if (cert.Verify()) return true;
            }
            AddCertNote("부모 인증서가 로컬 저장소에 없습니다.");
            return false;
        }
        /// <summary>
        /// 부모 인증서를 받을 수 있는 주소를 반환합니다. 없으면 "null"을 반환합니다.
        /// </summary>
        /// <returns>부모 인증서의 URL</returns>
        public string GetParentCertURL()
        {
            string rawData = _mainCert.ToString(true);

            int start = rawData.IndexOf("Authority Info Access", StringComparison.Ordinal);
            if (start < 0)
            {
                /* 부모 인증서 주소를 얻는 곳이 VerifyAdvanced()와 GetCertInfo() 두 곳이라서
                 * 함수는 ExtractCert()에서 한 번만 호출시키고 대신 그 때 멤버변수
                 * _parentCertURL에 주소를 저장해둔다.
                 */
                AddCertNote("부모 인증서의 URL이 존재하지 않습니다.");
                return "null";
            }
            rawData = rawData.Substring(start, rawData.Length - start);

            Match match = Regex.Match(rawData, @"URL=(.{0,}crt)");
            if (match.Groups.Count > 1) return match.Groups[1].Value;

            AddCertNote("부모 인증서의 URL이 CRT파일을 가리키고 있지 않습니다. 추가 구현이 필요합니다.");
            return "null";
        }

        /// <summary>
        /// 인증서를 검증하는 중에 발생한 특이사항을 보존합니다.
        /// </summary>
        /// <param name="reason"></param>
        private void AddCertNote(string reason)
        {
            CertificateInfo.Notes.Add(reason);
        }

        /// <summary>
        /// 인증서의 정보 및 검증 결과를 CertificateInfo에 저장합니다.
        /// </summary>
        private void GetCertInfo()
        {
            CertificateInfo.VerifiedResultPrimary = ResultPrimary;
            CertificateInfo.VerifiedResultAdvanced = ResultAdvanced;
            CertificateInfo.ThumbPrint = _mainCert.Thumbprint;
            CertificateInfo.SerialNumber = _mainCert.SerialNumber;
            CertificateInfo.Algorithm = _mainCert.SignatureAlgorithm.FriendlyName;
            CertificateInfo.DateEffective = _mainCert.GetEffectiveDateString();
            CertificateInfo.DateExpiry = _mainCert.GetExpirationDateString();
            CertificateInfo.Subject = _mainCert.SubjectName.Name;
            CertificateInfo.Issuer = _mainCert.IssuerName.Name;
            CertificateInfo.IssuerCertificateURL = _parentCertURL;
        }

        private string _targetPath;
        private X509Certificate2 _mainCert;
        private X509Chain _keyChain;
        private readonly CertificateStore _certificateStore;
        private string _parentCertURL = "null";

        public bool ResultPrimary { get; set; }
        public bool ResultAdvanced { get; set; }
        public CertificateInfo CertificateInfo { get; set; }
    }
}