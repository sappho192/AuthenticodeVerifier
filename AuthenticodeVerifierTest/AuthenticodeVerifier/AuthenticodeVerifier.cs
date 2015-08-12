/*
 * TaeIn Kim <sappho192@gmail.com>
 * 2015-08-11
 * 
 * AuthenticodeVerifier 클래스
 */

using System.IO;

namespace AuthenticodeVerifierTest.AuthenticodeVerifier
{
    /// <summary>
    /// MS Authenticode로 서명된 파일의 유효성을 검사하는 클래스입니다.
    /// 디지털 서명을 검사하는 SignerVerifier와 연대 디지털 서명을 검사하는 CounterSignerVerifier를 포함합니다.
    /// </summary>
    public class AuthenticodeVerifier : Verifier
    {
        public AuthenticodeVerifier()
        {
        }

        /// <summary>
        /// 디지털 서명과 연대 디지털 서명 모두를 검사합니다.
        /// </summary>
        /// <returns>검사 결과</returns>
        public override bool Verify()
        {
            Initialize();
            // 파일이 중간에 사라졌다면 false를 반환해 줄거에요.
            if (!_signerVerifier.LoadTarget(_targetPath))
            {
                return false;
            }
            if (!_counterSignerVerifier.LoadTarget(_targetPath))
            {
                return false;
            }

            return _signerVerifier.Verify() && _counterSignerVerifier.Verify();
        }

        /// <summary>
        /// 디지털 서명과 연대 디지털 서명의 세부 정보를 반환합니다.
        /// </summary>
        /// <returns></returns>
        public override string GetResult()
        {
            throw new System.NotImplementedException();
        }

        /// <summary>
        /// 디지털 서명과 연대 디지털 서명의 세부 정보를 콘솔에 출력합니다.
        /// </summary>
        public override void PrintResult()
        {
            throw new System.NotImplementedException();
        }

        public override bool LoadTarget(string filePath)
        {
            if (!File.Exists(filePath)) return false;
            _targetPath = filePath;
            return true;
        }

        public void Initialize()
        {
            _signerVerifier = new SignerVerifier();
            _counterSignerVerifier = new CounterSignerVerifier();
        }

        private SignerVerifier _signerVerifier;
        private CounterSignerVerifier _counterSignerVerifier;

        private string _targetPath;
    }
}
