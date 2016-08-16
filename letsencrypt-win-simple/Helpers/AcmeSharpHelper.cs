using ACMESharp;
using ACMESharp.HTTP;
using ACMESharp.JOSE;
using ACMESharp.PKI;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace LetsEncrypt.ACME.Simple {
    class AcmeSharpHelper : IDisposable {
        private Dictionary<string, DateTime> _AuthorizedIdentifiers;
        private string _AuthorizedIdentifiersJsonPath;
        private AcmeClient _Client;
        private string _RegistrationJsonPath;
        private RS256Signer _Signer;
        private string _SignerXmlPath;
        private readonly string _Web_ConfigXmlPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "web_config.xml");

        private bool AuthorizeBinding(Binding binding) {
            RetryAfterInvalidAuthorization: // If LetsEncrypt says a challenge is invalid, and the user hits Y to retry, it'll jump back up here

            if (_AuthorizedIdentifiers.ContainsKey(binding.Hostname)) {
                return true;
            } else {
                Globals.Log();
                Globals.Log($"Authorizing hostname {binding.Hostname} via {AcmeProtocol.CHALLENGE_TYPE_HTTP}");
                Globals.Log(" - Decoding challenge");
                var AuthState = _Client.AuthorizeIdentifier(binding.Hostname);
                var Challenge = _Client.DecodeChallenge(AuthState, AcmeProtocol.CHALLENGE_TYPE_HTTP);
                var HttpChallenge = Challenge.Challenge as ACMESharp.ACME.HttpChallenge;

                // Create the challenge file
                var AnswerPath = Environment.ExpandEnvironmentVariables(Path.Combine(binding.WebRootPath, HttpChallenge.FilePath.TrimStart('/')));
                Globals.Log($" - Writing challenge answer to {AnswerPath}");
                Directory.CreateDirectory(Path.GetDirectoryName(AnswerPath));
                File.WriteAllText(AnswerPath, HttpChallenge.FileContent);

                // Create the web.config to allow extensionless file loading
                string WebConfigPath = Path.Combine(Path.GetDirectoryName(AnswerPath), "web.config");
                Globals.Log($" - Copying extensionless-enabling web.config to {WebConfigPath}");
                File.Copy(_Web_ConfigXmlPath, WebConfigPath, true);

                // Warmup the answer url
                Globals.WarmUpUrl(HttpChallenge.FileUrl, HttpChallenge.FileContent);

                try {
                    int x = Console.CursorLeft;
                    int y = Console.CursorTop;

                    Globals.Log(" - Submitting challenge answer");
                    AuthState.Challenges = new AuthorizeChallenge[] { Challenge };
                    _Client.SubmitChallengeAnswer(AuthState, AcmeProtocol.CHALLENGE_TYPE_HTTP, true);

                    // Give a quick 1 second delay before refreshing -- then we'll loop with a "nicer" 5 second delay if we're still pending
                    if (AuthState.Status == "pending") {
                        Thread.Sleep(1000);
                        Globals.Log($" - Checking authorization status");
                        AuthState = _Client.RefreshIdentifierAuthorization(AuthState);
                    }

                    // Loop while in pending state
                    int TryNumber = 2; // 2 because we submitted above, which counts as try #1
                    while (AuthState.Status == "pending") {
                        Globals.Log("   - Authorization pending, waiting 5 seconds before trying again...");
                        Thread.Sleep(5000);

                        // This prevents scrolling while retrying
                        Console.CursorTop -= 1;
                        Console.Write(new string(' ', Console.WindowWidth - 1));
                        Console.SetCursorPosition(x, y);

                        Globals.Log($" - Refreshing authorization status (Try #{TryNumber++})");
                        AuthState = _Client.RefreshIdentifierAuthorization(AuthState);
                    }

                    Globals.Log($" - Authorization status: {AuthState.Status}");
                    if (AuthState.Status == "valid") {
                        // Record the expiry date for the valid result, so we can skip authorization in the future
                        _AuthorizedIdentifiers.Add(binding.Hostname, (DateTime)AuthState.Expires);
                    } else if (AuthState.Status == "invalid") {
                        // Prompt to see if we're going to fix and retry
                        Console.WriteLine("   - LetsEncrypt Uri:");
                        Console.WriteLine($"     {AuthState.Uri}");
                        Console.WriteLine("   - Check the URL above to see if it loads correctly");
                        Console.WriteLine("     If the site does a redirect, it may need to be disabled");
                        Console.WriteLine("     (The LetsEncrypt script contains 'letsencrypt.org' in the user-agent,");
                        Console.WriteLine("      so you could disable rewrite rules for that user-agent fragment)");
                        Console.WriteLine($"     Hit Y to try again or N to skip creating a cert for {binding.IPAddress}");
                        if (Globals.PromptYesNo()) goto RetryAfterInvalidAuthorization; // Suck it goto haters
                        // TODOX Add options for (1) to load challenge url and (2) for LetEncrypt info url
                    }

                    return (AuthState.Status == "valid");
                } finally {
                    // TODOX DeleteAuthorization?
                }
            }
        }

        public bool AuthorizeBindings(List<Binding> bindings) {
            bool Result = true;

            if (Globals.ShouldAuthorizeHostnames()) {
                LoadAuthorizedIdentifiers();
                foreach (var Binding in bindings) {
                    if (AuthorizeBinding(Binding)) {
                        SaveAuthorizedIdentifiers(); // todox likely saves too often, ie even when cached auth exists
                    } else {
                        Result = false;
                    }
                }
            }

            return Result;
        }

        private string GetIssuerCertificate(CertificateRequest certificate, CertificateProvider cp) {
            var linksEnum = certificate.Links;
            if (linksEnum != null) {
                var links = new LinkCollection(linksEnum);
                var upLink = links.GetFirstOrDefault("up");
                if (upLink != null) {
                    var temporaryFileName = Path.GetTempFileName();
                    try {
                        using (var web = new WebClient()) {
                            var uri = new Uri(new Uri(Config.BaseUri), upLink.Uri);
                            web.DownloadFile(uri, temporaryFileName);
                        }

                        var cacert = new X509Certificate2(temporaryFileName);
                        var sernum = cacert.GetSerialNumberString();

                        var cacertDerFile = Path.Combine(Config.Path, $"ca-{sernum}-crt.der");
                        var cacertPemFile = Path.Combine(Config.Path, $"ca-{sernum}-crt.pem");

                        if (!File.Exists(cacertDerFile))
                            File.Copy(temporaryFileName, cacertDerFile, true);

                        Globals.Log($"Saving Issuer Certificate to {cacertPemFile}");
                        if (!File.Exists(cacertPemFile))
                            using (FileStream source = new FileStream(cacertDerFile, FileMode.Open),
                                target = new FileStream(cacertPemFile, FileMode.Create)) {
                                var caCrt = cp.ImportCertificate(EncodingFormat.DER, source);
                                cp.ExportCertificate(caCrt, EncodingFormat.PEM, target);
                            }

                        return cacertPemFile;
                    } finally {
                        if (File.Exists(temporaryFileName))
                            File.Delete(temporaryFileName);
                    }
                }
            }

            return null;
        }

        public void Init() {
            _RegistrationJsonPath = Path.Combine(Config.Path, "Registration.json");
            _SignerXmlPath = Path.Combine(Config.Path, "Signer.xml");

            _Signer = new RS256Signer();
            _Signer.Init();

            // Load signer from file if it exists
            if (File.Exists(_SignerXmlPath)) {
                Globals.Log($"Loading {_SignerXmlPath}");
                using (var FS = File.OpenRead(_SignerXmlPath)) _Signer.Load(FS);
            }

            // Init client
            _Client = new AcmeClient(new Uri(Config.BaseUri), new AcmeServerDirectory(), _Signer);
            _Client.Init();
            _Client.GetDirectory(true);

            // Load registration from file, or prompt for email and create registration
            LoadOrCreateRegistration();
        }

        private void LoadAuthorizedIdentifiers() {
            _AuthorizedIdentifiersJsonPath = Path.Combine(Config.Path, "AuthorizedIdentifiers.json");

            if (File.Exists(_AuthorizedIdentifiersJsonPath)) {
                // Load previously authorized identifiers
                _AuthorizedIdentifiers = JsonConvert.DeserializeObject<Dictionary<string, DateTime>>(File.ReadAllText(_AuthorizedIdentifiersJsonPath));

                // Remove expired entries (subtract 1 day just to ensure that we don't try to use an expired authorization)
                var Yesterday = DateTime.UtcNow.AddDays(-1);
                var ExpiredEntries = _AuthorizedIdentifiers.Where(x => x.Value < Yesterday).ToList();
                foreach (var ExpiredEntry in ExpiredEntries) {
                    _AuthorizedIdentifiers.Remove(ExpiredEntry.Key);
                }
            } else {
                _AuthorizedIdentifiers = new Dictionary<string, DateTime>();
            }

        }

        private void LoadOrCreateRegistration() {
            if (File.Exists(_RegistrationJsonPath)) {
                Globals.Log($"Loading {_RegistrationJsonPath}");
                using (var FS = File.OpenRead(_RegistrationJsonPath)) _Client.Registration = AcmeRegistration.Load(FS);
            } else {
                Console.WriteLine("Enter an email address (not public, used for renewal fail notices):");
                var Email = Console.ReadLine().Trim();

                string[] Contacts = { };
                if (!string.IsNullOrWhiteSpace(Email)) {
                    Contacts = new string[] { $"mailto:{Email}" };
                }

                Globals.Log($"Registering with email: {Email}");
                _Client.Register(Contacts);

                Globals.Log("Updating registration");
                _Client.UpdateRegistration(true, true);

                Globals.Log($"Saving {_RegistrationJsonPath}");
                using (var FS = File.OpenWrite(_RegistrationJsonPath)) _Client.Registration.Save(FS);

                Globals.Log($"Saving {_SignerXmlPath}");
                using (var FS = File.OpenWrite(_SignerXmlPath)) _Signer.Save(FS);
            }
        }

        public string RequestCertificateAndConvertToPfx(List<Binding> bindings) {
            var keyGenFile = Path.Combine(Config.Path, $"{bindings[0].IPAddress}-gen-key.json");
            var keyPemFile = Path.Combine(Config.Path, $"{bindings[0].IPAddress}-key.pem");
            var csrGenFile = Path.Combine(Config.Path, $"{bindings[0].IPAddress}-gen-csr.json");
            var csrPemFile = Path.Combine(Config.Path, $"{bindings[0].IPAddress}-csr.pem");
            var crtDerFile = Path.Combine(Config.Path, $"{bindings[0].IPAddress}-crt.der");
            var crtPemFile = Path.Combine(Config.Path, $"{bindings[0].IPAddress}-crt.pem");
            var chainPemFile = Path.Combine(Config.Path, $"{bindings[0].IPAddress}-chain.pem");
            var crtPfxFile = Path.Combine(Config.Path, $"{bindings[0].IPAddress}-all.pfx");

            if (Globals.ShouldCreateCertificate()) {
                // TODOX Should check if the requested certificate (lowercase and sort hostnames) was issued in previous 10 days

                var cp = CertificateProvider.GetProvider();
                var rsaPkp = new RsaPrivateKeyParams();
                try {
                    if (Properties.Settings.Default.RSAKeyBits >= 2048) {
                        rsaPkp.NumBits = Properties.Settings.Default.RSAKeyBits;
                    } else {
                        Globals.Log($"Requested key size of {Properties.Settings.Default.RSAKeyBits} is not secure.  Using 2048.");
                        rsaPkp.NumBits = 2048;
                    }
                } catch (Exception ex) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Globals.Log($"Unable to set RSA key size, letting ACMESharp select default. Error: {ex}");
                    Console.ResetColor();
                }

                var rsaKeys = cp.GeneratePrivateKey(rsaPkp);
                var csrDetails = new CsrDetails {
                    CommonName = bindings[0].Hostname,
                    AlternativeNames = bindings.Select(x => x.Hostname).ToList(),
                };
                var csrParams = new CsrParams {
                    Details = csrDetails,
                };
                var csr = cp.GenerateCsr(csrParams, rsaKeys, Crt.MessageDigest.SHA256);

                byte[] derRaw;
                using (var bs = new MemoryStream()) {
                    cp.ExportCsr(csr, EncodingFormat.DER, bs);
                    derRaw = bs.ToArray();
                }
                var derB64U = JwsHelper.Base64UrlEncode(derRaw);

                Globals.Log();
                Globals.Log("Requesting Certificate");
                var certRequ = _Client.RequestCertificate(derB64U);

                Globals.Log($" - Request Status: {certRequ.StatusCode}");

                if (certRequ.StatusCode == System.Net.HttpStatusCode.Created) {
                    using (var fs = new FileStream(keyGenFile, FileMode.Create))
                        cp.SavePrivateKey(rsaKeys, fs);
                    using (var fs = new FileStream(keyPemFile, FileMode.Create))
                        cp.ExportPrivateKey(rsaKeys, EncodingFormat.PEM, fs);
                    using (var fs = new FileStream(csrGenFile, FileMode.Create))
                        cp.SaveCsr(csr, fs);
                    using (var fs = new FileStream(csrPemFile, FileMode.Create))
                        cp.ExportCsr(csr, EncodingFormat.PEM, fs);

                    Globals.Log($" - Saving DER certificate to {crtDerFile}");
                    using (var file = File.Create(crtDerFile))
                        certRequ.SaveCertificate(file);

                    Crt crt;
                    using (FileStream source = new FileStream(crtDerFile, FileMode.Open),
                        target = new FileStream(crtPemFile, FileMode.Create)) {
                        crt = cp.ImportCertificate(EncodingFormat.DER, source);
                        cp.ExportCertificate(crt, EncodingFormat.PEM, target);
                    }

                    // To generate a PKCS#12 (.PFX) file, we need the issuer's public certificate
                    var isuPemFile = GetIssuerCertificate(certRequ, cp);

                    using (FileStream intermediate = new FileStream(isuPemFile, FileMode.Open),
                        certificate = new FileStream(crtPemFile, FileMode.Open),
                        chain = new FileStream(chainPemFile, FileMode.Create)) {
                        certificate.CopyTo(chain);
                        intermediate.CopyTo(chain);
                    }

                    Globals.Log($" - Saving PFX certificate to {crtPfxFile}");
                    using (FileStream source = new FileStream(isuPemFile, FileMode.Open),
                        target = new FileStream(crtPfxFile, FileMode.Create)) {
                        var isuCrt = cp.ImportCertificate(EncodingFormat.PEM, source);
                        cp.ExportArchive(rsaKeys, new[] { crt, isuCrt }, ArchiveFormat.PKCS12, target, "");
                    }

                    cp.Dispose();

                    // TODOX Should store that the requested certificate (lowercase and sort hostnames) was issued

                    return crtPfxFile;
                } else {
                    throw new Exception($"Certificate request status = {certRequ.StatusCode}, uri = {certRequ.Uri}");
                }
            } else {
                // Don't want to request a new cert, so return the filename to the last requested cert
                return crtPfxFile;
            }
        }

        private void SaveAuthorizedIdentifiers() {
            File.WriteAllText(_AuthorizedIdentifiersJsonPath, JsonConvert.SerializeObject(_AuthorizedIdentifiers, Formatting.Indented));
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing) {
            if (!disposedValue) {
                if (disposing) {
                    // dispose managed state (managed objects).
                    if (_Client != null) {
                        _Client.Dispose();
                        _Client = null;
                    }
                    if (_Signer != null) {
                        _Signer.Dispose();
                        _Signer = null;
                    }
                }

                // free unmanaged resources (unmanaged objects) and override a finalizer below.
                // set large fields to null.

                disposedValue = true;
            }
        }

        // override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~AcmeSharpHelper() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose() {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
    }
}