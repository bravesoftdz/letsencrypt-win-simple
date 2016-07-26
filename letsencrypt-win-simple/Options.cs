using CommandLine;
using System;
using System.Diagnostics;

namespace LetsEncrypt.ACME.Simple {
    enum RunMode {
        CreateCert,
        InstallCert,
        Production,
        Staging,
    }

    class Options {
        [Option(Required = true, HelpText = "Sets the mode, which determines the behaviour of the application")]
        public RunMode RunMode { get; set; }

        public bool ShouldGenerateCertificate() {
            switch (RunMode) {
                case RunMode.CreateCert: return true; // CreateCert should generate a certificate
                case RunMode.InstallCert: return false; // InstallCert should note generate a certificate
                case RunMode.Production: return true; // Production should generate a certificate
                case RunMode.Staging: return true; // Staging should generate a certificate
                default: throw new ArgumentOutOfRangeException("Unexpected RunMode: " + RunMode);
            }
        }

        public bool ShouldInstallCertificate() {
            switch (RunMode) {
                case RunMode.CreateCert: return false; // CreateCert should not install a certificate
                case RunMode.InstallCert: return true; // InstallCert should install a certificate
                case RunMode.Production: return true; // Production should install a certificate
                case RunMode.Staging: return Debugger.IsAttached; // Staging should install a certificate in debugger
                default: throw new ArgumentOutOfRangeException("Unexpected RunMode: " + RunMode);
            }
        }

        public bool ShouldUpdateBindings() {
            switch (RunMode) {
                case RunMode.CreateCert: return false; // CreateCert should not update bindings
                case RunMode.InstallCert: return true; // InstallCert should update bindings
                case RunMode.Production: return true; // Production should update bindings
                case RunMode.Staging: return Debugger.IsAttached; // Staging should update bindings in debugger
                default: throw new ArgumentOutOfRangeException("Unexpected RunMode: " + RunMode);
            }
        }
    }
}