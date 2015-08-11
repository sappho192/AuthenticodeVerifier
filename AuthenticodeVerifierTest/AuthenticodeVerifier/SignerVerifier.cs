using System.IO;

namespace AuthenticodeVerifierTest.AuthenticodeVerifier
{
    /// <summary>
    /// 디지털 서명의 유효성을 검사할 수 있는 클래스입니다.
    /// </summary>
    public class SignerVerifier : Verifier
    {
        public SignerVerifier()
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

        public override bool LoadTarget(string filePath)
        {
            if (!File.Exists(filePath)) return false;
            _targetPath = filePath;
            return true;
        }

        private string _targetPath;
    }
}