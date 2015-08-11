﻿/*
 * TaeIn Kim <sappho192@gmail.com>
 * 2015-08-11
 * 
 * Verifier 추상 클래스
 */

namespace AuthenticodeVerifierTest.AuthenticodeVerifier
{
    /// <summary>
    /// 대상이 유효한지 검사할 수 있는 추상 클래스입니다.
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
    }
}