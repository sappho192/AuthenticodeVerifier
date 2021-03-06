﻿/*
 * TaeIn Kim <sappho192@gmail.com>
 * 2015-08-11
 * 
 * Certificate 클래스
 */

using System;
using System.Collections.Generic;

namespace AuthenticodeVerifierTest.Certificates
{
    /// <summary>
    /// 인증서의 정보를 담을 수 있습니다.
    /// </summary>
    public class CertificateInfo
    {
        public CertificateInfo()
        {
            Notes = new List<string>();
        }

        public void PrintInfo()
        {
            if (ThumbPrint == null) { Console.WriteLine("인증서 정보가 없습니다."); }
            else
            {
                Console.WriteLine("[[인증서 정보]]");
                Console.WriteLine("기본 검증결과: " + VerifiedResultPrimary);
                Console.WriteLine("세부 검증결과: " + VerifiedResultAdvanced);
                Console.WriteLine("[비고]");
                if (Notes.Count > 0)
                {
                    foreach (var note in Notes)
                    {
                        Console.WriteLine(note);
                    }
                }
                else
                {
                    Console.WriteLine("특이 사항이 없었습니다.");
                }
                Console.WriteLine("지문: " + ThumbPrint);
                Console.WriteLine("일련번호: " + SerialNumber);
                Console.WriteLine("알고리즘: " + Algorithm);
                Console.WriteLine("발효시기: " + DateEffective);
                Console.WriteLine("만료시기: " + DateExpiry);
                Console.WriteLine("서명자: " + Subject);
                Console.WriteLine("발급자: " + Issuer);
                Console.WriteLine("발급자 인증서: " + IssuerCertificateURL);
            }
        }

        public bool VerifiedResultPrimary { get; set; }
        public bool VerifiedResultAdvanced { get; set; }
        public List<string> Notes { get; set; }
        public string ThumbPrint { get; set; }
        public string SerialNumber { get; set; }
        public string Algorithm { get; set; }
        public string DateEffective { get; set; }
        public string DateExpiry { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public string IssuerCertificateURL { get; set; }
    }
}
