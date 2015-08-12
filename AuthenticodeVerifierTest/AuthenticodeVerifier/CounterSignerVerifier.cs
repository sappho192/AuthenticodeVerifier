/*
 * TaeIn Kim <sappho192@gmail.com>
 * 2015-08-11
 * 
 * CounterSignerVerifier 클래스
 */

using System.IO;

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
            throw new System.NotImplementedException();
        }

        public override string GetResult()
        {
            throw new System.NotImplementedException();
        }

        public override void PrintResult()
        {
            throw new System.NotImplementedException();
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

        private string _targetPath;
    }
}