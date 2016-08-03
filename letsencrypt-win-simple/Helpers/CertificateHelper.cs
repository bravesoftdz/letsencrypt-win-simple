using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LetsEncrypt.ACME.Simple {
    class CertificateHelper {
        public static void InstallCertificate(Binding binding, string pfxFilename, out X509Store store, out X509Certificate2 certificate) {
            // See http://paulstovell.com/blog/x509certificate2
            certificate = new X509Certificate2(pfxFilename, "", X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            certificate.FriendlyName = $"{binding.IPAddress} {certificate.NotBefore.ToString(Properties.Settings.Default.FileDateFormat)}";
            store = null;

            if (Globals.ShouldInstallCertificate()) {
                try {
                    store = new X509Store("WebHosting", StoreLocation.LocalMachine);
                    store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
                } catch (CryptographicException) {
                    store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
                }
                Globals.Log($"Opened certificate store: {store.Name}");

                Globals.Log($" - Cert friendly name: {certificate.FriendlyName}");

                Globals.Log($" - Adding certificate to store");
                store.Add(certificate);
                store.Close();
            } else {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Globals.Log($"* If I wasn't running in {Config.Options.RunMode} mode, I'd be installing {pfxFilename} right now");
                Console.ResetColor();
            }
        }

    }
}
