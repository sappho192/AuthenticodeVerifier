/*
 * TaeIn Kim <sappho192@gmail.com>
 * 2015-08-11
 * 
 * Verifier 추상 클래스
 */

namespace AuthenticodeVerifierTest.AuthenticodeVerifier
{
    /// <summary>
    /// 대상이 유효한지 검사할 수 있는 추상 클래스입니다.
    /// LoadTarget()으로 파일을 부르고 Verify()를 호출해 검사를 진행합니다.
    /// </summary>
    public abstract class Verifier
    {
        protected Verifier()
        {
        }

        public abstract bool Verify();
        /// <summary>
        /// 검사한 대상의 세부 정보를 문자열로 반환합니다.
        /// </summary>
        /// <returns></returns>
        public abstract string GetResult();
        /// <summary>
        /// 검사한 대상의 세부 정보를 콘솔에 출력합니다.
        /// </summary>
        public abstract void PrintResult();

        /// <summary>
        /// 검사할 대상을 지정합니다. true가 반환되면 Verify()를 호출해 검사를 진행하세요.
        /// </summary>
        /// <param name="filePath">대상의 경로(절대, 상대 모두 가능)</param>
        public abstract bool LoadTarget(string filePath);
    }
}