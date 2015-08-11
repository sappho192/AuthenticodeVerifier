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
            _signerVerifier = new SignerVerifier();
            _counterSignerVerifier = new CounterSignerVerifier();
        }

        /// <summary>
        /// 디지털 서명과 연대 디지털 서명 모두를 검사합니다.
        /// </summary>
        /// <returns>검사 결과</returns>
        public override bool Verify()
        {
            throw new System.NotImplementedException();
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

        private SignerVerifier _signerVerifier;
        private CounterSignerVerifier _counterSignerVerifier;
    }
}
