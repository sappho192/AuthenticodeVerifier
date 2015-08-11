/*
 * TaeIn Kim <sappho192@gmail.com>
 * 2015-08-11
 * 
 * CertificateStore 클래스
 */

using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeVerifierTest.Certificates
{
    /// <summary>
    /// 실행 컴퓨터에 저장되어 있는 인증서들을 보여줍니다.
    /// </summary>
    public class CertificateStore
    {
        public CertificateStore()
        {
            IntermediateCertList = new X509Certificate2Collection();
            RootCertList = new X509Certificate2Collection();
            AuthRootCertList = new X509Certificate2Collection();
            LoadStore();
        }
        private void LoadStore()
        {
            var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            IntermediateCertList = store.Certificates;

            store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            RootCertList = store.Certificates;

            store = new X509Store(StoreName.AuthRoot, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            AuthRootCertList = store.Certificates;
        }

        public X509Certificate2Collection IntermediateCertList;
        public X509Certificate2Collection RootCertList;
        public X509Certificate2Collection AuthRootCertList;
    }
}