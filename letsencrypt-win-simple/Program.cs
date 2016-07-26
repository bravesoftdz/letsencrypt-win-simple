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
using Serilog;
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
        private static Options _Options;
        private static readonly string _Web_ConfigXmlPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "web_config.xml");

        static bool IsElevated
            => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        private static void Main(string[] args) {
            CreateLogger();

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;

            // Parse and validate the command line arguments
            if (!TryParseOptions(args)) return;
            if (_Options.RunMode == RunMode.Staging) SetStagingParameters();

            // Output header information
            Console.WriteLine("Let's Encrypt (Simple Windows ACME Client)");
            Console.WriteLine($"\nACME Server: {_BaseUri}");
            Console.WriteLine();
            Log.Information("ACME Server: {BaseUri}", _BaseUri);

            // Confirm options before continuing
            Console.WriteLine(_Options.RunMode.ToString().ToUpper() + " MODE");
            Console.WriteLine("  - A certificate " + (_Options.ShouldGenerateCertificate() ? "WILL" : "WON'T") + " be generated for each unique IP address");
            Console.WriteLine("  - The certificates " + (_Options.ShouldInstallCertificate() ? "WILL" : "WON'T") + " be installed to the cerificate store" + (_Options.RunMode == RunMode.InstallCert ? "*" : ""));
            Console.WriteLine("  - The server's IIS bindings " + (_Options.ShouldUpdateBindings() ? "WILL" : "WON'T") + " be updated to use the certificates" + (_Options.RunMode == RunMode.InstallCert ? "*" : ""));
            if (_Options.RunMode == RunMode.InstallCert) {
                Console.WriteLine();
                Console.WriteLine("* Since certificate generation is being skipped, the newest certificate on disk will be used instead");
            }
            Console.WriteLine();
            Console.Write("Do you wish to continue in this mode? [Y/N] ");
            if (!PromptYesNo()) return;

            CreateConfigPath();

            try {
                LoadAuthorizedIdentifiers();

                using (var signer = new RS256Signer()) {
                    signer.Init();

                    var signerPath = Path.Combine(_ConfigPath, "Signer");
                    if (File.Exists(signerPath))
                        LoadSignerFromFile(signer, signerPath);

                    using (_Client = new AcmeClient(new Uri(_BaseUri), new AcmeServerDirectory(), signer)) {
                        _Client.Init();
                        Console.WriteLine("\nGetting AcmeServerDirectory");
                        Log.Information("Getting AcmeServerDirectory");
                        _Client.GetDirectory(true);

                        var registrationPath = Path.Combine(_ConfigPath, "Registration");
                        if (File.Exists(registrationPath))
                            LoadRegistrationFromFile(registrationPath);
                        else {
                            Console.Write("Enter an email address (not public, used for renewal fail notices): ");
                            var email = Console.ReadLine().Trim();

                            string[] contacts = GetContacts(email);

                            AcmeRegistration registration = CreateRegistration(contacts);

                            UpdateRegistration();
                            SaveRegistrationToFile(registrationPath);
                            SaveSignerToFile(signer, signerPath);
                        }

                        // This is where the magic happens!
                        GenerateAndInstallCertificatesForEachIP();
                    }
                }
            } catch (Exception e) {
                Log.Error("Error {@e}", e);
                Console.ForegroundColor = ConsoleColor.Red;
                var acmeWebException = e as AcmeClient.AcmeWebException;
                if (acmeWebException != null) {
                    Console.WriteLine(acmeWebException.Message);
                    Console.WriteLine("ACME Server Returned:");
                    Console.WriteLine(acmeWebException.Response.ContentAsString);
                } else {
                    Console.WriteLine(e);
                }
                Console.ResetColor();
            } finally {
                SaveAuthorizedIdentifiers();
            }

            Console.WriteLine("Press enter to continue.");
            Console.ReadLine();
        }

        private static bool TryParseOptions(string[] args) {
            try {
                var commandLineParseResult = Parser.Default.ParseArguments<Options>(args);
                var parsed = commandLineParseResult as Parsed<Options>;
                if (parsed == null) {
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
                    LogParsingErrorAndWaitForEnter();
                    return false; // not parsed
                }

                _Options = parsed.Value;
                Log.Debug("{@Options}", _Options);

                return true;
            } catch {
                Console.WriteLine("Failed while parsing options.");
                throw;
            }
        }

        private static AcmeRegistration CreateRegistration(string[] contacts) {
            Console.WriteLine("Calling Register");
            Log.Information("Calling Register");
            var registration = _Client.Register(contacts);
            return registration;
        }

        private static void SetStagingParameters() {
            _BaseUri = "https://acme-staging.api.letsencrypt.org/";
            Log.Debug("Staging paramater set: {BaseUri}", _BaseUri);
        }

        private static void LoadRegistrationFromFile(string registrationPath) {
            Console.WriteLine($"Loading Registration from {registrationPath}");
            Log.Information("Loading Registration from {registrationPath}", registrationPath);
            using (var registrationStream = File.OpenRead(registrationPath))
                _Client.Registration = AcmeRegistration.Load(registrationStream);
        }

        private static string[] GetContacts(string email) {
            var contacts = new string[] { };
            if (!String.IsNullOrEmpty(email)) {
                Log.Debug("Registration email: {email}", email);
                email = "mailto:" + email;
                contacts = new string[] { email };
            }

            return contacts;
        }

        private static void SaveSignerToFile(RS256Signer signer, string signerPath) {
            Console.WriteLine("Saving Signer");
            Log.Information("Saving Signer");
            using (var signerStream = File.OpenWrite(signerPath))
                signer.Save(signerStream);
        }

        private static void SaveRegistrationToFile(string registrationPath) {
            Console.WriteLine("Saving Registration");
            Log.Information("Saving Registration");
            using (var registrationStream = File.OpenWrite(registrationPath))
                _Client.Registration.Save(registrationStream);
        }

        private static void UpdateRegistration() {
            Console.WriteLine("Updating Registration");
            Log.Information("Updating Registration");
            _Client.UpdateRegistration(true, true);
        }

        private static void LoadSignerFromFile(RS256Signer signer, string signerPath) {
            Console.WriteLine($"Loading Signer from {signerPath}");
            Log.Information("Loading Signer from {signerPath}", signerPath);
            using (var signerStream = File.OpenRead(signerPath))
                signer.Load(signerStream);
        }

        private static void CreateConfigPath() {
            //_ConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ClientName,
            //    CleanFileName(_BaseUri));
            _ConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, CleanFileName(_BaseUri));
            Console.WriteLine("Config Folder: " + _ConfigPath);
            Log.Information("Config Folder: {_configPath}", _ConfigPath);
            Directory.CreateDirectory(_ConfigPath);
        }

        private static void LogParsingErrorAndWaitForEnter() {
            Log.Debug("Program Debug Enabled");
            Console.WriteLine("Press enter to continue.");
            Console.ReadLine();
        }

        private static void CreateLogger() {
            try {
                Log.Logger = new LoggerConfiguration()
                    .ReadFrom.AppSettings()
                    .CreateLogger();
                Log.Information("The global logger has been configured");
            } catch {
                Console.WriteLine("Error while creating logger.");
                throw;
            }
        }

        private static string CleanFileName(string fileName)
            =>
                Path.GetInvalidFileNameChars()
                    .Aggregate(fileName, (current, c) => current.Replace(c.ToString(), string.Empty));

        public static bool PromptYesNo() {
            try {
                while (true) {
                    var response = Console.ReadKey(true);
                    if (response.Key == ConsoleKey.Y)
                        return true;
                    if (response.Key == ConsoleKey.N)
                        return false;
                    Console.Write("\nPlease press Y or N: ");
                }
            } finally {
                Console.WriteLine();
                Console.WriteLine();
            }
        }

        public static void InstallCertificate(Binding binding, string pfxFilename, out X509Store store,
            out X509Certificate2 certificate) {

            if (_Options.ShouldInstallCertificate()) {
                try {
                    store = new X509Store(_CertificateStore, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
                } catch (CryptographicException) {
                    store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
                } catch (Exception ex) {
                    Log.Error("Error encountered while opening certificate store. Error: {@ex}", ex);
                    throw new Exception(ex.Message);
                }

                Console.WriteLine($" Opened Certificate Store \"{store.Name}\"");
                Log.Information("Opened Certificate Store {Name}", store.Name);
                certificate = null;
                try {
                    // See http://paulstovell.com/blog/x509certificate2
                    certificate = new X509Certificate2(pfxFilename, "",
                        X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet |
                        X509KeyStorageFlags.Exportable);

                    certificate.FriendlyName =
                        $"{binding.IPAddress} {DateTime.Now.ToString(Properties.Settings.Default.FileDateFormat)}";
                    Log.Debug("{FriendlyName}", certificate.FriendlyName);

                    Console.WriteLine($" Adding Certificate to Store");
                    Log.Information("Adding Certificate to Store");
                    store.Add(certificate);

                    Console.WriteLine($" Closing Certificate Store");
                    Log.Information("Closing Certificate Store");
                } catch (Exception ex) {
                    Log.Error("Error saving certificate {@ex}", ex);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error saving certificate: {ex.Message.ToString()}");
                    Console.ResetColor();
                }
                store.Close();
            } else {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"DEBUG: InstallCertificate({binding}, {pfxFilename}, {_CertificateStore});");
                Console.ResetColor();
                Log.Debug($"DEBUG: InstallCertificate({binding}, {pfxFilename}, {_CertificateStore});");

                certificate = new X509Certificate2(pfxFilename, "",
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet |
                    X509KeyStorageFlags.Exportable);
                certificate.FriendlyName = $"{binding.IPAddress} {DateTime.Now.ToString(Properties.Settings.Default.FileDateFormat)}";
                store = null;
            }
        }

        //public static void UninstallCertificate(string host, out X509Store store, X509Certificate2 certificate) {
        //    try {
        //        store = new X509Store(_CertificateStore, StoreLocation.LocalMachine);
        //        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
        //    } catch (CryptographicException) {
        //        store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        //        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
        //    } catch (Exception ex) {
        //        Log.Error("Error encountered while opening certificate store. Error: {@ex}", ex);
        //        throw new Exception(ex.Message);
        //    }

        //    Console.WriteLine($" Opened Certificate Store \"{store.Name}\"");
        //    Log.Information("Opened Certificate Store {Name}", store.Name);
        //    try {
        //        X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindBySubjectName, host, false);

        //        foreach (var cert in col) {
        //            var subjectName = cert.Subject.Split(',');

        //            if (cert.FriendlyName != certificate.FriendlyName && subjectName[0] == "CN=" + host) {
        //                Console.WriteLine($" Removing Certificate from Store {cert.FriendlyName}");
        //                Log.Information("Removing Certificate from Store {@cert}", cert);
        //                store.Remove(cert);
        //            }
        //        }

        //        Console.WriteLine($" Closing Certificate Store");
        //        Log.Information("Closing Certificate Store");
        //    } catch (Exception ex) {
        //        Log.Error("Error removing certificate {@ex}", ex);
        //        Console.ForegroundColor = ConsoleColor.Red;
        //        Console.WriteLine($"Error removing certificate: {ex.Message.ToString()}");
        //        Console.ResetColor();
        //    }
        //    store.Close();
        //}

        public static string GetCertificate(List<Binding> bindings) {
            if (_Options.ShouldGenerateCertificate()) {
                var cp = CertificateProvider.GetProvider();
                var rsaPkp = new RsaPrivateKeyParams();
                try {
                    if (Properties.Settings.Default.RSAKeyBits >= 1024) {
                        rsaPkp.NumBits = Properties.Settings.Default.RSAKeyBits;
                        Log.Debug("RSAKeyBits: {RSAKeyBits}", Properties.Settings.Default.RSAKeyBits);
                    } else {
                        Log.Warning(
                            "RSA Key Bits less than 1024 is not secure. Letting ACMESharp default key bits. http://openssl.org/docs/manmaster/crypto/RSA_generate_key_ex.html");
                    }
                } catch (Exception ex) {
                    Log.Warning("Unable to set RSA Key Bits, Letting ACMESharp default key bits, Error: {@ex}", ex);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(
                        $"Unable to set RSA Key Bits, Letting ACMESharp default key bits, Error: {ex.Message.ToString()}");
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

                Console.WriteLine($"\nRequesting Certificate");
                Log.Information("Requesting Certificate");
                var certRequ = _Client.RequestCertificate(derB64U);

                Log.Debug("certRequ {@certRequ}", certRequ);

                Console.WriteLine($" Request Status: {certRequ.StatusCode}");
                Log.Information("Request Status: {StatusCode}", certRequ.StatusCode);

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

                    Console.WriteLine($" Saving Certificate to {crtDerFile}");
                    Log.Information("Saving Certificate to {crtDerFile}", crtDerFile);
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


                    Console.WriteLine($" Saving Certificate to {crtPfxFile}");
                    Log.Information("Saving Certificate to {crtPfxFile}", crtPfxFile);
                    using (FileStream source = new FileStream(isuPemFile, FileMode.Open),
                        target = new FileStream(crtPfxFile, FileMode.Create)) {
                        try {
                            var isuCrt = cp.ImportCertificate(EncodingFormat.PEM, source);
                            cp.ExportArchive(rsaKeys, new[] { crt, isuCrt }, ArchiveFormat.PKCS12, target, "");
                        } catch (Exception ex) {
                            Log.Error("Error exporting archive {@ex}", ex);
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"Error exporting archive: {ex.Message.ToString()}");
                            Console.ResetColor();
                        }

                    }

                    cp.Dispose();

                    return crtPfxFile;
                }
                Log.Error("Request status = {StatusCode}", certRequ.StatusCode);
                throw new Exception($"Request status = {certRequ.StatusCode}");
            } else {
                // TODOX Find the newest certificate for this IP on disk
                //       Handle the case where there is no certificate on disk for this IP
                throw new NotImplementedException();
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

                        Console.WriteLine($" Saving Issuer Certificate to {cacertPemFile}");
                        Log.Information("Saving Issuer Certificate to {cacertPemFile}", cacertPemFile);
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

        public static bool Authorize(Binding binding) {
            Console.WriteLine(
                $"\nAuthorizing Identifier {binding.Hostname} Using Challenge Type {AcmeProtocol.CHALLENGE_TYPE_HTTP}");
            Log.Information("Authorizing Identifier {dnsIdentifier} Using Challenge Type {CHALLENGE_TYPE_HTTP}",
                binding.Hostname, AcmeProtocol.CHALLENGE_TYPE_HTTP);

            if (_AuthorizedIdentifiers.ContainsKey(binding.Hostname)) {
                Console.WriteLine("We already have authorization until " + _AuthorizedIdentifiers[binding.Hostname].ToLocalTime());
                Log.Information("We already have authorization until " + _AuthorizedIdentifiers[binding.Hostname].ToLocalTime());
                return true;
            } else {
                var authzState = _Client.AuthorizeIdentifier(binding.Hostname);
                var challenge = _Client.DecodeChallenge(authzState, AcmeProtocol.CHALLENGE_TYPE_HTTP);
                var httpChallenge = challenge.Challenge as HttpChallenge;

                // We need to strip off any leading '/' in the path
                var filePath = httpChallenge.FilePath;
                if (filePath.StartsWith("/", StringComparison.OrdinalIgnoreCase))
                    filePath = filePath.Substring(1);
                var answerPath = Environment.ExpandEnvironmentVariables(Path.Combine(binding.WebRootPath, filePath));

                CreateAuthorizationFile(answerPath, httpChallenge.FileContent);

                BeforeAuthorize(binding, answerPath, httpChallenge.Token);

                var answerUri = new Uri(httpChallenge.FileUrl);

                Console.WriteLine($"Waiting for site to warmup...");
                WarmupSite(answerUri);

                Console.WriteLine($" Answer should now be browsable at {answerUri}");
                Log.Information("Answer should now be browsable at {answerUri}", answerUri);

                try {
                    Console.WriteLine(" Submitting answer");
                    Log.Information("Submitting answer");
                    authzState.Challenges = new AuthorizeChallenge[] { challenge };
                    _Client.SubmitChallengeAnswer(authzState, AcmeProtocol.CHALLENGE_TYPE_HTTP, true);

                    // have to loop to wait for server to stop being pending.
                    // TODO: put timeout/retry limit in this loop
                    while (authzState.Status == "pending") {
                        Console.WriteLine(" Refreshing authorization");
                        Log.Information("Refreshing authorization");
                        Thread.Sleep(4000); // this has to be here to give ACME server a chance to think
                        var newAuthzState = _Client.RefreshIdentifierAuthorization(authzState);
                        if (newAuthzState.Status != "pending")
                            authzState = newAuthzState;
                    }

                    Console.WriteLine($" Authorization Result: {authzState.Status}");
                    Log.Information("Auth Result {Status}", authzState.Status);
                    if (authzState.Status == "invalid") {
                        Log.Error("Authorization Failed {Status}", authzState.Status);
                        Log.Debug("Full Error Details {@authzState}", authzState);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(
                            "\n******************************************************************************");
                        Console.WriteLine($"The ACME server was probably unable to reach {answerUri}");
                        Log.Error("Unable to reach {answerUri}", answerUri);

                        Console.WriteLine("\nCheck in a browser to see if the answer file is being served correctly.");

                        OnAuthorizeFail(binding);

                        Console.WriteLine(
                            "\n******************************************************************************");
                        Console.ResetColor();
                    } else if (authzState.Status == "valid") {
                        _AuthorizedIdentifiers.Add(binding.Hostname, (DateTime)authzState.Expires);
                    }

                    return (authzState.Status == "valid");
                } finally {
                    if (authzState.Status == "valid") {
                        DeleteAuthorization(answerPath, httpChallenge.Token, binding.WebRootPath, filePath);
                    }
                }
            }
        }

        private static void WarmupSite(Uri uri) {
            var request = WebRequest.Create(uri);

            try {
                using (var response = request.GetResponse()) { }
            } catch (Exception ex) {
                Console.WriteLine($"Error warming up site: {ex.Message}");
                Log.Error("Error warming up site: {@ex}", ex);
            }
        }





        private static bool AuthorizeAll(List<Binding> bindings) {
            bool Result = true;

            if (_Options.ShouldGenerateCertificate()) {
                foreach (var Binding in bindings) {
                    if (!Authorize(Binding)) {
                        Console.WriteLine($"Hostname {Binding.Hostname} on IP {Binding.IPAddress} failed to authorize");
                        Log.Error($"Hostname {Binding.Hostname} on IP {Binding.IPAddress} failed to authorize");
                        Result = false;
                    }
                }
            }

            return Result;
        }

        public static void BeforeAuthorize(Binding binding, string answerPath, string token) {
            var directory = Path.GetDirectoryName(answerPath);
            var webConfigPath = Path.Combine(directory, "web.config");

            Console.WriteLine($" Writing web.config to add extensionless mime type to {webConfigPath}");
            Log.Information("Writing web.config to add extensionless mime type to {webConfigPath}", webConfigPath);
            File.Copy(_Web_ConfigXmlPath, webConfigPath, true);
        }

        public static void CreateAuthorizationFile(string answerPath, string fileContents) {
            Console.WriteLine($" Writing challenge answer to {answerPath}");
            Log.Information("Writing challenge answer to {answerPath}", answerPath);
            var directory = Path.GetDirectoryName(answerPath);
            Directory.CreateDirectory(directory);
            File.WriteAllText(answerPath, fileContents);
        }

        public static void DeleteAuthorization(string answerPath, string token, string webRootPath, string filePath) {
            Console.WriteLine(" Deleting answer");
            Log.Information("Deleting answer");
            File.Delete(answerPath);

            try {
                var folderPath = answerPath.Remove((answerPath.Length - token.Length), token.Length);
                var files = Directory.GetFiles(folderPath);

                if (files.Length == 1) {
                    if (files[0] == (folderPath + "web.config")) {
                        Log.Information("Deleting web.config");
                        File.Delete(files[0]);
                        Log.Information("Deleting {folderPath}", folderPath);
                        Directory.Delete(folderPath);

                        var filePathFirstDirectory =
                            Environment.ExpandEnvironmentVariables(Path.Combine(webRootPath,
                                filePath.Remove(filePath.IndexOf("/"), (filePath.Length - filePath.IndexOf("/")))));
                        Log.Information("Deleting {filePathFirstDirectory}", filePathFirstDirectory);
                        Directory.Delete(filePathFirstDirectory);
                    } else {
                        Log.Warning("Additional files exist in {folderPath} not deleting.", folderPath);
                    }
                } else {
                    Log.Warning("Additional files exist in {folderPath} not deleting.", folderPath);
                }
            } catch (Exception ex) {
                Log.Warning("Error occured while deleting folder structure. Error: {@ex}", ex);
            }
        }

        public static void GenerateAndInstallCertificatesForEachIP() {
            // Get a listing of all the HTTP bindings
            List<Binding> Bindings = GetHTTPBindings();

            if (Bindings.Count == 0) {
                Console.WriteLine("No bindings found.");
                Log.Error("No bindings found.");
            } else {
                // Get a listing of the unique IP addresses used by the various bindings
                var UniqueIPAddresses = Bindings.Select(x => x.IPAddress).Distinct();

                // Loop through the list of unique IP addresses
                foreach (var UniqueIPAddress in UniqueIPAddresses) {
                    try {
                        // Get a listing of the bindings that use this IP address
                        var ThisIPsBindings = Bindings.Where(x => x.IPAddress == UniqueIPAddress).ToList();
                        if (ThisIPsBindings.Count > 100) {
                            // Let's Encrypt doesn't support this many hosts in a single cert
                            Console.WriteLine($"IP {UniqueIPAddress} has too many hosts for a SAN certificate.  Let's Encrypt currently has a maximum of 100 alternative names per certificate.");
                            Log.Error($"IP {UniqueIPAddress} has too many hosts for a SAN certificate.  Let's Encrypt currently has a maximum of 100 alternative names per certificate.");
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
                                Console.WriteLine("All hosts under all sites need to pass authorization before you can continue");
                                Log.Error("All hosts under all sites need to pass authorization before you can continue.");
                            }
                        }
                    } catch (Exception ex) {
                        Console.WriteLine("Exception: " + ex.Message + " while processing " + UniqueIPAddress);
                        // TODOX Don't let one bad IP screw it up for the rest
                        // TODOX Maybe record the failed IPs and then output a command at the end that will re-process just that one IP
                        // TODOX Take the existing options into account (ie include --test if it was used for the current process)
                        // TODOX Then add --ips 10.20.30.100,127.0.0.1 etc to target just the given IP(s)
                    }
                }
            }
        }

        public static List<Binding> GetHTTPBindings() {
            var Result = new List<Binding>();

            Console.WriteLine("\nScanning IIS Site Bindings");
            Log.Information("Scanning IIS Site Bindings");

            _IISVersion = GetIISVersion();
            if (_IISVersion.Major == 0) {
                Console.WriteLine("IIS Version not found in windows registry. Skipping scan.");
                Log.Information("IIS Version not found in windows registry. Skipping scan.");
            } else {
                using (var iisManager = new ServerManager()) {
                    foreach (var site in iisManager.Sites) {
                        foreach (var binding in site.Bindings) {
                            //Get HTTP sites that aren't IDN and aren't internal (ie no-period hosts)
                            if (!String.IsNullOrEmpty(binding.Host) && binding.Host.Contains(".") &&
                                binding.Protocol == "http" && !Regex.IsMatch(binding.Host, @"[^\u0000-\u007F]")) {
                                if (Result.Where(h => h.Hostname == binding.Host && h.IPAddress == binding.EndPoint.Address.ToString()).Count() == 0) {
                                    Result.Add(new Binding() {
                                        Hostname = binding.Host,
                                        IPAddress = binding.EndPoint.Address.ToString(),
                                        WebRootPath = site.Applications["/"].VirtualDirectories["/"].PhysicalPath,
                                    });
                                }
                            }
                        }
                    }
                }

                if (Result.Count == 0) {
                    Console.WriteLine("No IIS bindings with host names were found. Please add one using IIS Manager. A host name and site path are required to verify domain ownership.");
                    Log.Information("No IIS bindings with host names were found. Please add one using IIS Manager. A host name and site path are required to verify domain ownership.");
                }
            }

            return Result;
        }

        private static Version GetIISVersion() {
            using (RegistryKey componentsKey = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\InetStp", false)) {
                if (componentsKey != null) {
                    int majorVersion = (int)componentsKey.GetValue("MajorVersion", -1);
                    int minorVersion = (int)componentsKey.GetValue("MinorVersion", -1);

                    if (majorVersion != -1 && minorVersion != -1) {
                        return new Version(majorVersion, minorVersion);
                    }
                }

                return new Version(0, 0);
            }
        }

        private static void LoadAuthorizedIdentifiers() {
            string Filename = Path.Combine(_ConfigPath, "AuthorizedIdentifiers.json");
            if (File.Exists(Filename)) {
                // Load previously authorized identifiers
                _AuthorizedIdentifiers = JsonConvert.DeserializeObject<Dictionary<string, DateTime>>(File.ReadAllText(Filename));

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

        public static void OnAuthorizeFail(Binding binding) {
            Console.WriteLine(@"

This could be caused by IIS not being setup to handle extensionless static
files. Here's how to fix that:
1. In IIS manager goto Site/Server->Handler Mappings->View Ordered List
2. Move the StaticFile mapping above the ExtensionlessUrlHandler mappings.
(like this http://i.stack.imgur.com/nkvrL.png)
3. If you need to make changes to your web.config file, update the one
at " + _Web_ConfigXmlPath);
            Log.Error(
                "Authorize failed: This could be caused by IIS not being setup to handle extensionless static files.Here's how to fix that: 1.In IIS manager goto Site/ Server->Handler Mappings->View Ordered List 2.Move the StaticFile mapping above the ExtensionlessUrlHandler mappings. (like this http://i.stack.imgur.com/nkvrL.png) 3.If you need to make changes to your web.config file, update the one at {_sourceFilePath}",
                _Web_ConfigXmlPath);
        }

        private static void SaveAuthorizedIdentifiers() {
            string Filename = Path.Combine(_ConfigPath, "AuthorizedIdentifiers.json");
            File.WriteAllText(Filename, JsonConvert.SerializeObject(_AuthorizedIdentifiers));
        }

        private static void UpdateBindings(List<Binding> bindings, string pfxFilename, X509Store store, X509Certificate2 certificate) {
            using (var iisManager = new ServerManager()) {
                foreach (var Site in iisManager.Sites) {
                    foreach (var Binding in bindings) {
                        string BindingIPAddress = Binding.IPAddress.Replace("0.0.0.0", "*");

                        // Check if this site has the HTTP binding in question
                        var HasHTTPBinding = Site.Bindings.Any(x => x.Host == Binding.Hostname && x.EndPoint.Address.ToString() == Binding.IPAddress && x.Protocol == "http");
                        if (HasHTTPBinding) {
                            // It does, so check if it has an HTTPS binding
                            var existingHTTPSBindings = Site.Bindings.Where(x => x.Host == Binding.Hostname && x.EndPoint.Address.ToString() == Binding.IPAddress && x.Protocol == "https").ToList();
                            if (existingHTTPSBindings.Any()) {
                                foreach (var existingHTTPSBinding in existingHTTPSBindings) {
                                    if (_Options.ShouldUpdateBindings()) {
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

                                        Console.WriteLine($" Replacing https Binding");
                                        Log.Information("Replacing https Binding");
                                        Site.Bindings.Remove(existingHTTPSBinding);
                                        var iisBinding = Site.Bindings.Add(BindingIPAddress + ":" + existingHTTPSBinding.EndPoint.Port.ToString() + ":" + Binding.Hostname, certificate.GetCertHash(),
                                            store.Name);
                                        iisBinding.Protocol = "https";
                                        if (_IISVersion.Major >= 8)
                                            iisBinding.SetAttributeValue("sslFlags", 0); // Disable SNI support
                                    } else {
                                        Console.ForegroundColor = ConsoleColor.White;
                                        Console.WriteLine($"DEBUG: Updating HTTPS binding {existingHTTPSBinding.EndPoint.Address}:{existingHTTPSBinding.EndPoint.Port}:{existingHTTPSBinding.Host} to use cert {certificate.FriendlyName}");
                                        Console.ResetColor();
                                        Log.Debug($"DEBUG: Updating HTTPS binding {existingHTTPSBinding.EndPoint.Address}:{existingHTTPSBinding.EndPoint.Port}:{existingHTTPSBinding.Host} to use cert {certificate.FriendlyName}");
                                    }
                                }
                            } else {
                                if (_Options.ShouldUpdateBindings()) {
                                    Console.WriteLine($" Adding https Binding");
                                    Log.Information("Adding https Binding");
                                    var iisBinding = Site.Bindings.Add(BindingIPAddress + ":443:" + Binding.Hostname, certificate.GetCertHash(),
                                        store.Name);
                                    iisBinding.Protocol = "https";
                                    if (_IISVersion.Major >= 8)
                                        iisBinding.SetAttributeValue("sslFlags", 0); // Disable SNI support
                                } else {
                                    Console.ForegroundColor = ConsoleColor.White;
                                    Console.WriteLine($"\nDEBUG: Adding HTTPS binding {BindingIPAddress}:443:{Binding.Hostname} with cert {certificate.FriendlyName}");
                                    Console.ResetColor();
                                    Log.Debug($"DEBUG: Adding HTTPS binding {BindingIPAddress}:443:{Binding.Hostname} with cert {certificate.FriendlyName}");
                                }
                            }
                        }
                    }
                }

                if (_Options.ShouldUpdateBindings()) {
                    Console.WriteLine($" Committing binding changes to IIS");
                    Log.Information("Committing binding changes to IIS");
                    iisManager.CommitChanges();
                }
            }
        }
    }
}
