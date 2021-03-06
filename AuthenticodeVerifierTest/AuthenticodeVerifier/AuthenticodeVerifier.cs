﻿/*
 * TaeIn Kim <sappho192@gmail.com>
 * 2015-08-11
 * 
 * AuthenticodeVerifier 클래스
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using AuthenticodeVerifierTest.Certificates;

namespace AuthenticodeVerifierTest.AuthenticodeVerifier
{
    /// <summary>
    /// MS Authenticode로 서명된 파일의 유효성을 검사하는 클래스입니다.
    /// 디지털 서명을 검사하는 SignerVerifier와 연대 디지털 서명을 검사하는 CounterSignerVerifier를 포함합니다.
    /// </summary>
    public class AuthenticodeVerifier : Verifier
    {
        /// <summary>
        /// 기본 생성자입니다. LoadTarget()으로 파일을 부르고 Verify()를 호출해 검사를 진행하세요.
        /// </summary>
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
            if (!LoadTarget(_targetPath))
            {
                return false;
            }

            // 파일이 중간에 사라졌다면 false를 반환해 줄거에요.
            if (!_signerVerifier.LoadTarget(_targetPath))
            {
                return false;
            }
            if (!_counterSignerVerifier.LoadTarget(_targetPath))
            {
                return false;
            }

            GatherFileVersionInfo();

            var signerResult = _signerVerifier.Verify();
            var counterSignerResult = _counterSignerVerifier.Verify();

            return signerResult || counterSignerResult;
        }

        /// <summary>
        /// 디지털 서명과 연대 디지털 서명의 세부 정보를 반환합니다.
        /// </summary>
        /// <returns></returns>
        public override string GetResult()
        {
            string result;
            result = GetFileVersionInfo();
            result += _signerVerifier.GetResult();
            result += _counterSignerVerifier.GetResult();

            return result;
        }

        /// <summary>
        /// 디지털 서명과 연대 디지털 서명의 세부 정보를 콘솔에 출력합니다.
        /// </summary>
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

        /// <summary>
        /// 초기화 작업을 진행합니다.
        /// </summary>
        public void Initialize()
        {
            _signerVerifier = new SignerVerifier();
            _counterSignerVerifier = new CounterSignerVerifier();
        }

        /// <summary>
        /// 해당 파일의 정보를 FileVersionInfo 클래스를 이용해 가져옵니다.
        /// </summary>
        private void GatherFileVersionInfo()
        {
            FileVersionInfo = FileVersionInfo.GetVersionInfo(_targetPath);
        }

        public string GetFileVersionInfo()
        {
            var stringBuilder = new StringBuilder();
            stringBuilder.AppendLine("Copyright: " + FileVersionInfo.LegalCopyright);
            stringBuilder.AppendLine("Publisher: " + FileVersionInfo.CompanyName);
            stringBuilder.AppendLine("Product: " + FileVersionInfo.ProductName);
            stringBuilder.AppendLine("Original name: " + FileVersionInfo.OriginalFilename);
            stringBuilder.AppendLine("Internal name: " + FileVersionInfo.InternalName);
            stringBuilder.AppendLine("File Version: " + FileVersionInfo.FileMajorPart
                + "-" + FileVersionInfo.FileMinorPart
                + "(" + FileVersionInfo.FilePrivatePart + ")");
            stringBuilder.AppendLine("Description: " + FileVersionInfo.FileDescription);

            return stringBuilder.ToString();
        }

        public void PrintFileVersionInfo()
        {
            Console.WriteLine(GetFileVersionInfo());
        }

        public CertificateInfo CertificateInfo
        {
            get { return _signerVerifier.CertificateInfo; }
        }

        public CertificateInfo CounterCertificateInfo
        {
            get { return _counterSignerVerifier.CertificateInfo; }
        }

        public FileVersionInfo FileVersionInfo { get; set; }

        private SignerVerifier _signerVerifier;
        private CounterSignerVerifier _counterSignerVerifier;

        private string _targetPath;
    }
}
