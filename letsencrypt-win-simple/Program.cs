using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Security.Principal;
using CommandLine;
using Microsoft.Win32.TaskScheduler;
using System.Reflection;
using ACMESharp;
using ACMESharp.HTTP;
using ACMESharp.JOSE;
using ACMESharp.PKI;
using System.Security.Cryptography;
using ACMESharp.ACME;
//using Serilog;
using System.Text;
using Microsoft.Win32;
using Microsoft.Web.Administration;
using System.Text.RegularExpressions;
using System.Diagnostics;
using Newtonsoft.Json;

namespace LetsEncrypt.ACME.Simple {
    class Program {
        private static Dictionary<string, DateTime> _AuthorizedIdentifiers;
        private static string _BaseUri = "https://acme-v01.api.letsencrypt.org/";
        private static string _CertificateStore = "WebHosting";
        private static AcmeClient _Client;
        private static string _ConfigPath;
        private static Version _IISVersion;
        private static List<string> _Log = new List<string>();
        private static Options _Options;
        private static readonly string _Web_ConfigXmlPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "web_config.xml");

        private static void Main(string[] args) {
            try {
                if (!IsElevated()) {
                    Log("You must run this program as an administrator.  Aborting.");
                    return;
                }

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;

                // Output header information
                Log("Let's Encrypt (Simple Windows ACME Client -- SAN per IP mod)");
                Log();

                // Parse and validate the command line arguments
                if (!TryParseOptions(args)) return;
                if (_Options.RunMode == RunMode.Staging) _BaseUri = "https://acme-staging.api.letsencrypt.org/";

                // Create config directory
                _ConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, CleanFilename(_BaseUri));
                Log($"Config path: {_ConfigPath}");
                Log();
                Directory.CreateDirectory(_ConfigPath);

                // Confirm options before continuing
                Log(_Options.RunMode.ToString().ToUpper() + " MODE");
                Log($"  - ACME Server: {_BaseUri}");
                Log("  - A certificate " + (_Options.ShouldGenerateCertificate() ? "WILL" : "WON'T") + " be generated for each unique IP address");
                Log("  - The certificates " + (_Options.ShouldInstallCertificate() ? "WILL" : "WON'T") + " be installed to the cerificate store" + (_Options.RunMode == RunMode.InstallCert ? "*" : ""));
                Log("  - The server's IIS bindings " + (_Options.ShouldUpdateBindings() ? "WILL" : "WON'T") + " be updated to use the certificates" + (_Options.RunMode == RunMode.InstallCert ? "*" : ""));
                if (_Options.RunMode == RunMode.InstallCert) {
                    Log();
                    Log("* Since certificate generation is being skipped, the newest certificate on disk will be used instead");
                }
                Log();
                Console.Write("Do you wish to continue in this mode? [Y/N] ");
                if (!PromptYesNo()) return;

                try {
                    _IISVersion = GetIISVersion();
                    if (_IISVersion.Major == 0) {
                        Log("You must run this on a server with IIS installed.  Aborting.");
                        return;
                    }

                    using (var Signer = new RS256Signer()) {
                        Signer.Init();

                        var SignerXmlPath = Path.Combine(_ConfigPath, "Signer.xml");
                        if (File.Exists(SignerXmlPath)) {
                            using (var FS = File.OpenRead(SignerXmlPath)) Signer.Load(FS);

                        }

                        using (_Client = new AcmeClient(new Uri(_BaseUri), new AcmeServerDirectory(), Signer)) {
                            _Client.Init();

                            Log("Getting ACME Server Directory");
                            _Client.GetDirectory(true);

                            // Load registration from file, or prompt for email and create registration
                            LoadOrCreateRegistration(Signer, SignerXmlPath);

                            // Now the certificate generating can begin!
                            GenerateAndInstallCertificatesForEachIP();
                        }
                    }
                } catch (AcmeClient.AcmeWebException awex) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Log();
                    Log("ACME WEB EXCEPTION: " + awex.Message);
                    Log("  - Response: " + awex.Response.ContentAsString);
                    Log("  - Stacktrace: " + awex.StackTrace.ToString());
                    Console.ResetColor();
                } catch (Exception ex) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Log();
                    Log("EXCEPTION: " + ex.ToString());
                    Console.ResetColor();
                }
            } finally {
                File.AppendAllLines(Path.Combine(_ConfigPath, "letsencrypt.log"), _Log);
                Console.WriteLine();
                Console.WriteLine("Press enter to continue.");
                Console.ReadLine();
            }
        }

        public static bool Authorize(Binding binding) {
            RetryAfterInvalidAuthorization: // If LetsEncrypt says a challenge is invalid, and the user hits Y to retry, it'll jump back up here

            Log();
            Log($"Authorizing Identifier {binding.Hostname} via {AcmeProtocol.CHALLENGE_TYPE_HTTP}");
            if (_AuthorizedIdentifiers.ContainsKey(binding.Hostname)) {
                Log(" - Skipping, existing auth doesn't expire until " + _AuthorizedIdentifiers[binding.Hostname].ToLocalTime());
                return true;
            } else {
                Log(" - Decoding challenge");
                var AuthState = _Client.AuthorizeIdentifier(binding.Hostname);
                var Challenge = _Client.DecodeChallenge(AuthState, AcmeProtocol.CHALLENGE_TYPE_HTTP);
                var HttpChallenge = Challenge.Challenge as HttpChallenge;

                // Create the challenge file
                var AnswerPath = Environment.ExpandEnvironmentVariables(Path.Combine(binding.WebRootPath, HttpChallenge.FilePath.TrimStart('/')));
                Log($" - Writing challenge answer to {AnswerPath}");
                Directory.CreateDirectory(Path.GetDirectoryName(AnswerPath));
                File.WriteAllText(AnswerPath, HttpChallenge.FileContent);

                // Create the web.config to allow extensionless file loading
                string WebConfigPath = Path.Combine(Path.GetDirectoryName(AnswerPath), "web.config");
                Log($" - Copying extensionless-enabling web.config to {WebConfigPath}");
                File.Copy(_Web_ConfigXmlPath, WebConfigPath, true);

                // Warmup the answer url
                var AnswerUrl = new Uri(HttpChallenge.FileUrl);
                int TryNumber = 1;
                while (true) {
                    int x = Console.CursorLeft;
                    int y = Console.CursorTop;

                    Log($" - Warming up {AnswerUrl} (Try #{TryNumber++})");
                    try {
                        using (var WC = new WebClient()) {
                            WC.Headers.Add("user-agent", "Mozilla/5.0 (compatible; Let's Encrypt validation server;  https://www.letsencrypt.org)");
                            string Response = WC.DownloadString(AnswerUrl);
                            if (Response == HttpChallenge.FileContent) {
                                break; // Got the response we want, so exit the loop and let LetsEncrypt retrieve the answer
                            }
                        }
                    } catch (WebException wex) {
                        Log($"   - WEB EXCEPTION ({wex.Status}): {wex.Message}");
                    } catch (Exception ex) {
                        Log($"   - EXCEPTION: {ex.Message}");
                    }

                    // If we get here we didn't get the response we want -- for sites like Sitefinity that are slow to warmup we should delay and try again
                    Log($"   - Invalid response, waiting 5 seconds before trying again...");
                    Thread.Sleep(5000);

                    // This prevents scrolling while retrying
                    Console.CursorTop -= 1;
                    Console.Write(new string(' ', Console.WindowWidth - 1));
                    Console.SetCursorPosition(x, y);
                }

                try {
                    int x = Console.CursorLeft;
                    int y = Console.CursorTop;

                    Log(" - Submitting challenge answer");
                    AuthState.Challenges = new AuthorizeChallenge[] { Challenge };
                    _Client.SubmitChallengeAnswer(AuthState, AcmeProtocol.CHALLENGE_TYPE_HTTP, true);
                    
                    // Loop while in pending state
                    TryNumber = 2; // 2 because we submitted above, which counts as try #1
                    while (AuthState.Status == "pending") {
                        Log("   - Authorization pending, waiting 5 seconds before trying again...");
                        Thread.Sleep(5000);

                        // This prevents scrolling while retrying
                        Console.CursorTop -= 1;
                        Console.Write(new string(' ', Console.WindowWidth - 1));
                        Console.SetCursorPosition(x, y);

                        Log($" - Refreshing authorization status (Try #{TryNumber++})");
                        AuthState = _Client.RefreshIdentifierAuthorization(AuthState);
                    }

                    Log($" - Authorization status: {AuthState.Status}");
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
                        if (PromptYesNo()) goto RetryAfterInvalidAuthorization; // Suck it goto haters
                    }

                    return (AuthState.Status == "valid");
                } finally {
                    // TODOX DeleteAuthorization?
                }
            }
        }

        private static bool AuthorizeAll(List<Binding> bindings) {
            bool Result = true;

            if (_Options.ShouldGenerateCertificate()) {
                foreach (var Binding in bindings) {
                    Result &= Authorize(Binding);
                }
            }

            return Result;
        }

        private static string CleanFilename(string filename) {
            return Path.GetInvalidFileNameChars().Aggregate(filename, (current, c) => current.Replace(c.ToString(), string.Empty));
        }

        public static void GenerateAndInstallCertificatesForEachIP() {
            string AuthorizedIdentifiersJsonPath = Path.Combine(_ConfigPath, "AuthorizedIdentifiers.json");

            try {
                LoadAuthorizedIdentifiersFromFile(AuthorizedIdentifiersJsonPath);

                // Get a listing of all the HTTP bindings
                List<Binding> Bindings = GetHTTPBindings();

                if (Bindings.Count > 0) {
                    // Get a listing of the unique IP addresses used by the various bindings
                    var UniqueIPAddresses = Bindings.Select(x => x.IPAddress).Distinct();

                    // Loop through the list of unique IP addresses
                    foreach (var UniqueIPAddress in UniqueIPAddresses) {
                        Log();
                        Log($"Handling {UniqueIPAddress}");

                        try {
                            // Get a listing of the bindings that use this IP address
                            var ThisIPsBindings = Bindings.Where(x => x.IPAddress == UniqueIPAddress).ToList();
                            if (ThisIPsBindings.Count > 100) {
                                // Let's Encrypt doesn't support this many hosts in a single cert
                                Log($"IP {UniqueIPAddress} has too many hosts for a SAN certificate.  Let's Encrypt currently has a maximum of 100 alternative names per certificate.");
                            } else {
                                // Try to authorize all the hosts
                                if (AuthorizeAll(ThisIPsBindings)) {
                                    // Generate the certificate
                                    string pfxFilename = GetCertificate(ThisIPsBindings);
                                    if (!string.IsNullOrWhiteSpace(pfxFilename)) {
                                        // Install the certificate into the WebHost store
                                        X509Store store;
                                        X509Certificate2 certificate;
                                        InstallCertificate(ThisIPsBindings[0], pfxFilename, out store, out certificate);

                                        // TODOX Uninstall the old certificate from the WebHost store

                                        // Add/update the HTTPS bindings in IIS to use the new certificate (don't update in test mode, unless we're debugging locally)
                                        UpdateBindings(ThisIPsBindings, pfxFilename, store, certificate);
                                    }
                                } else {
                                    // One or more hosts failed to authorize, so this cert cannot be generated
                                    Log("One or more hosts failed to pass authorization, so the certifcate will not be created/installed");
                                }
                            }
                        } catch (Exception ex) {
                            Log($"EXCEPTION: {ex}");
                            Log("Continuing with next IP address...");
                            // TODOX Maybe record the failed IPs and then output a command at the end that will re-process just that one IP
                            // TODOX Take the existing options into account (ie include --test if it was used for the current process)
                            // TODOX Then add --ips 10.20.30.100,127.0.0.1 etc to target just the given IP(s)
                        }
                    }
                }
            } finally {
                Log();
                Log($"Saving {AuthorizedIdentifiersJsonPath}");
                File.WriteAllText(AuthorizedIdentifiersJsonPath, JsonConvert.SerializeObject(_AuthorizedIdentifiers));
            }
        }

        public static string GetCertificate(List<Binding> bindings) {
            if (_Options.ShouldGenerateCertificate()) {
                var cp = CertificateProvider.GetProvider();
                var rsaPkp = new RsaPrivateKeyParams();
                try {
                    if (Properties.Settings.Default.RSAKeyBits >= 2048) {
                        rsaPkp.NumBits = Properties.Settings.Default.RSAKeyBits;
                    } else {
                        Log($"Requested key size of {Properties.Settings.Default.RSAKeyBits} is not secure.  Using 2048.");
                        rsaPkp.NumBits = 2048;
                    }
                } catch (Exception ex) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Log($"Unable to set RSA key size, letting ACMESharp select default. Error: {ex}");
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

                Log();
                Log("Requesting Certificate");
                var certRequ = _Client.RequestCertificate(derB64U);

                Log($" - Request Status: {certRequ.StatusCode}");

                if (certRequ.StatusCode == System.Net.HttpStatusCode.Created) {
                    var keyGenFile = Path.Combine(_ConfigPath, $"{bindings[0].IPAddress}-gen-key.json");
                    var keyPemFile = Path.Combine(_ConfigPath, $"{bindings[0].IPAddress}-key.pem");
                    var csrGenFile = Path.Combine(_ConfigPath, $"{bindings[0].IPAddress}-gen-csr.json");
                    var csrPemFile = Path.Combine(_ConfigPath, $"{bindings[0].IPAddress}-csr.pem");
                    var crtDerFile = Path.Combine(_ConfigPath, $"{bindings[0].IPAddress}-crt.der");
                    var crtPemFile = Path.Combine(_ConfigPath, $"{bindings[0].IPAddress}-crt.pem");
                    var chainPemFile = Path.Combine(_ConfigPath, $"{bindings[0].IPAddress}-chain.pem");
                    var crtPfxFile = Path.Combine(_ConfigPath, $"{bindings[0].IPAddress}-all.pfx");

                    using (var fs = new FileStream(keyGenFile, FileMode.Create))
                        cp.SavePrivateKey(rsaKeys, fs);
                    using (var fs = new FileStream(keyPemFile, FileMode.Create))
                        cp.ExportPrivateKey(rsaKeys, EncodingFormat.PEM, fs);
                    using (var fs = new FileStream(csrGenFile, FileMode.Create))
                        cp.SaveCsr(csr, fs);
                    using (var fs = new FileStream(csrPemFile, FileMode.Create))
                        cp.ExportCsr(csr, EncodingFormat.PEM, fs);

                    Log($" - Saving DER certificate to {crtDerFile}");
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

                    Log($" - Saving PFX certificate to {crtPfxFile}");
                    using (FileStream source = new FileStream(isuPemFile, FileMode.Open),
                        target = new FileStream(crtPfxFile, FileMode.Create)) {
                        var isuCrt = cp.ImportCertificate(EncodingFormat.PEM, source);
                        cp.ExportArchive(rsaKeys, new[] { crt, isuCrt }, ArchiveFormat.PKCS12, target, "");
                    }

                    cp.Dispose();

                    return crtPfxFile;
                } else {
                    throw new Exception($"Certificate request status = {certRequ.StatusCode}, uri = {certRequ.Uri}");
                }
            } else {
                // TODOX Find the newest certificate for this IP on disk
                //       Handle the case where there is no certificate on disk for this IP
                throw new NotImplementedException();
            }
        }

        public static List<Binding> GetHTTPBindings() {
            var Result = new List<Binding>();

            Log("Retrieving HTTP bindings from IIS");
            using (var IISManager = new ServerManager()) {
                foreach (var Site in IISManager.Sites) {
                    foreach (var Binding in Site.Bindings) {
                        // Get HTTP sites that aren't IDN and aren't internal (ie no-period hosts)
                        if (!string.IsNullOrWhiteSpace(Binding.Host) && Binding.Host.Contains(".") &&
                            Binding.Protocol == "http" && !Regex.IsMatch(Binding.Host, @"[^\u0000-\u007F]")) {
                            if (!Result.Any(x => x.Hostname == Binding.Host && x.IPAddress == Binding.EndPoint.Address.ToString())) {
                                Result.Add(new Binding() {
                                    Hostname = Binding.Host,
                                    IPAddress = Binding.EndPoint.Address.ToString(),
                                    WebRootPath = Site.Applications["/"].VirtualDirectories["/"].PhysicalPath,
                                });
                            }
                        }
                    }
                }
            }

            if (!Result.Any()) Log(" - No HTTP bindings with hostnames found -- please add some and try again");

            return Result;
        }

        private static Version GetIISVersion() {
            using (RegistryKey Key = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\InetStp", false)) {
                if (Key != null) {
                    int majorVersion = (int)Key.GetValue("MajorVersion", -1);
                    int minorVersion = (int)Key.GetValue("MinorVersion", -1);

                    if (majorVersion != -1 && minorVersion != -1) {
                        return new Version(majorVersion, minorVersion);
                    }
                }

                return new Version(0, 0);
            }
        }

        public static string GetIssuerCertificate(CertificateRequest certificate, CertificateProvider cp) {
            var linksEnum = certificate.Links;
            if (linksEnum != null) {
                var links = new LinkCollection(linksEnum);
                var upLink = links.GetFirstOrDefault("up");
                if (upLink != null) {
                    var temporaryFileName = Path.GetTempFileName();
                    try {
                        using (var web = new WebClient()) {
                            var uri = new Uri(new Uri(_BaseUri), upLink.Uri);
                            web.DownloadFile(uri, temporaryFileName);
                        }

                        var cacert = new X509Certificate2(temporaryFileName);
                        var sernum = cacert.GetSerialNumberString();

                        var cacertDerFile = Path.Combine(_ConfigPath, $"ca-{sernum}-crt.der");
                        var cacertPemFile = Path.Combine(_ConfigPath, $"ca-{sernum}-crt.pem");

                        if (!File.Exists(cacertDerFile))
                            File.Copy(temporaryFileName, cacertDerFile, true);

                        Log($"Saving Issuer Certificate to {cacertPemFile}");
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

        public static void InstallCertificate(Binding binding, string pfxFilename, out X509Store store, out X509Certificate2 certificate) {
            // See http://paulstovell.com/blog/x509certificate2
            certificate = new X509Certificate2(pfxFilename, "", X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            certificate.FriendlyName = $"{binding.IPAddress} {DateTime.Now.ToString(Properties.Settings.Default.FileDateFormat)}";
            store = null;

            if (_Options.ShouldInstallCertificate()) {
                try {
                    store = new X509Store(_CertificateStore, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
                } catch (CryptographicException) {
                    store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
                }
                Log($"Opened certificate store: {store.Name}");

                Log($" - Cert friendly name: {certificate.FriendlyName}");

                Log($" - Adding certificate to store");
                store.Add(certificate);
                store.Close();
            } else {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Log($"* If I wasn't running in {_Options.RunMode} mode, I'd be installing {pfxFilename} to cert store {_CertificateStore} right now");
                Console.ResetColor();
            }
        }

        private static bool IsElevated() {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static void LoadAuthorizedIdentifiersFromFile(string filename) {
            if (File.Exists(filename)) {
                // Load previously authorized identifiers
                _AuthorizedIdentifiers = JsonConvert.DeserializeObject<Dictionary<string, DateTime>>(File.ReadAllText(filename));

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

        private static void LoadOrCreateRegistration(RS256Signer signer, string signerXmlPath) {
            var RegistrationJsonPath = Path.Combine(_ConfigPath, "Registration.json");
            if (File.Exists(RegistrationJsonPath)) {
                Log($"Loading {RegistrationJsonPath}");
                using (var FS = File.OpenRead(RegistrationJsonPath)) _Client.Registration = AcmeRegistration.Load(FS);
            } else {
                Console.WriteLine("Enter an email address (not public, used for renewal fail notices):");
                var Email = Console.ReadLine().Trim();

                string[] Contacts = { };
                if (!string.IsNullOrWhiteSpace(Email)) {
                    Contacts = new string[] { $"mailto:{Email}" };
                }

                Log($"Registering with email: {Email}");
                _Client.Register(Contacts);

                Log("Updating registration");
                _Client.UpdateRegistration(true, true);

                Log($"Saving {RegistrationJsonPath}");
                using (var FS = File.OpenWrite(RegistrationJsonPath)) _Client.Registration.Save(FS);

                Log($"Saving {signerXmlPath}");
                using (var FS = File.OpenWrite(signerXmlPath)) signer.Save(FS);
            }
        }

        private static void Log(string message = "") {
            Console.WriteLine(message.Replace(AppDomain.CurrentDomain.BaseDirectory, "")); // Convert absolute filenames to relative filenames when outputting to screen
            _Log.Add(message.Trim()); // message may lead with carriage return, so trim it
        }

        public static bool PromptYesNo() {
            try {
                while (true) {
                    var CKI = Console.ReadKey(true);
                    if (CKI.Key == ConsoleKey.Y) return true;
                    if (CKI.Key == ConsoleKey.N) return false;
                    Console.Write("\nPlease press Y or N: ");
                }
            } finally {
                Console.WriteLine();
                Console.WriteLine();
            }
        }

        private static bool TryParseOptions(string[] args) {
            try {
                var Result = Parser.Default.ParseArguments<Options>(args);
                var Parsed = Result as Parsed<Options>;
                if (Parsed == null) {
                    Console.WriteLine("RunMode Options (case sensitive!):");
                    Console.WriteLine();
                    Console.WriteLine(" --runmode CreateCert");
                    Console.WriteLine("   Creates a production cert, doesn't install it, doesn't update bindings");
                    Console.WriteLine();
                    Console.WriteLine(" --runmode InstallCert");
                    Console.WriteLine("   Doesn't create a cert, installs the most recent, updates bindings");
                    Console.WriteLine();
                    Console.WriteLine(" --runmode Production");
                    Console.WriteLine("   Creates a productions cert, installs it, updates bindings");
                    Console.WriteLine();
                    Console.WriteLine(" --runmode Staging");
                    Console.WriteLine("   Creates a staging cert, doesn't install it, doesn't update bindings");
                    Console.WriteLine();
                    return false; // not parsed
                }

                _Options = Parsed.Value;

                return true;
            } catch {
                Log("Failed to parse command-line options");
                throw;
            }
        }

        private static void UpdateBindings(List<Binding> bindings, string pfxFilename, X509Store store, X509Certificate2 certificate) {
            Log();
            Log("Adding/updating HTTPS bindings");

            using (var IISManager = new ServerManager()) {
                foreach (var Site in IISManager.Sites) {
                    foreach (var Binding in bindings) {
                        string BindingIPAddress = Binding.IPAddress.Replace("0.0.0.0", "*");

                        // Check if this site has the HTTP binding in question
                        var HasHTTPBinding = Site.Bindings.Any(x => x.Host == Binding.Hostname && x.EndPoint.Address.ToString() == Binding.IPAddress && x.Protocol == "http");
                        if (HasHTTPBinding) {
                            // It does, so check if it has an HTTPS binding (may have multiple, for example if a hostname is running HTTPS on two different ports)
                            var ExistingHTTPSBindings = Site.Bindings.Where(x => x.Host == Binding.Hostname && x.EndPoint.Address.ToString() == Binding.IPAddress && x.Protocol == "https").ToList();
                            if (ExistingHTTPSBindings.Any()) {
                                foreach (var ExistingHTTPSBinding in ExistingHTTPSBindings) {
                                    string NewBinding = $"{BindingIPAddress}:{ExistingHTTPSBinding.EndPoint.Port}:{Binding.Hostname}";

                                    if (_Options.ShouldUpdateBindings()) {
                                        Log($" - Replacing binding for {NewBinding}");
                                        Site.Bindings.Remove(ExistingHTTPSBinding);
                                        var iisBinding = Site.Bindings.Add(NewBinding, certificate.GetCertHash(), store.Name);
                                        iisBinding.Protocol = "https";
                                        if (_IISVersion.Major >= 8) iisBinding.SetAttributeValue("sslFlags", 0); // Disable SNI support

                                        // This fails sometimes when there's two HTTPS bindings for the same hostname with different ports
                                        //Console.WriteLine($" Updating Existing https Binding");
                                        //Log.Information("Updating Existing https Binding");
                                        //Console.ForegroundColor = ConsoleColor.Yellow;
                                        //Console.WriteLine($" IIS will serve the new certificate after the Application Pool Idle Timeout time has been reached.");
                                        //Log.Information("IIS will serve the new certificate after the Application Pool Idle Timeout time has been reached.");
                                        //Console.ResetColor();

                                        //existingHTTPSBinding.CertificateStoreName = store.Name;
                                        //existingHTTPSBinding.CertificateHash = certificate.GetCertHash();
                                        //if (_IISVersion.Major >= 8)
                                        //    existingHTTPSBinding.SetAttributeValue("sslFlags", 0); // Disable SNI support
                                    } else {
                                        Console.ForegroundColor = ConsoleColor.Yellow;
                                        Log($" * If I wasn't running in {_Options.RunMode} mode, I'd be replacing the binding for {NewBinding} right now");
                                        Console.ResetColor();
                                    }
                                }
                            } else {
                                string NewBinding = $"{BindingIPAddress}:443:{Binding.Hostname}";

                                if (_Options.ShouldUpdateBindings()) {
                                    Log($" - Adding binding for {NewBinding}");
                                    var iisBinding = Site.Bindings.Add(NewBinding, certificate.GetCertHash(), store.Name);
                                    iisBinding.Protocol = "https";
                                    if (_IISVersion.Major >= 8) iisBinding.SetAttributeValue("sslFlags", 0); // Disable SNI support
                                } else {
                                    Console.ForegroundColor = ConsoleColor.Yellow;
                                    Log($" * If I wasn't running in {_Options.RunMode} mode, I'd be adding a binding for {NewBinding} right now");
                                    Console.ResetColor();
                                }
                            }
                        }
                    }
                }

                if (_Options.ShouldUpdateBindings()) {
                    Log($" - Committing binding changes to IIS");
                    IISManager.CommitChanges();
                }
            }
        }
    }
}
