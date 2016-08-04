using CommandLine;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Threading;

namespace LetsEncrypt.ACME.Simple {
    enum RunMode {
        CreateCert,
        InstallCert,
        Production,
        Staging,
    }

    class Globals {
        public static string CleanFilename(string filename) {
            return Path.GetInvalidFileNameChars().Aggregate(filename, (current, c) => current.Replace(c.ToString(), string.Empty));
        }

        public static bool IsElevated() {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static void Log(string message = "") {
            Console.WriteLine(message.Replace(AppDomain.CurrentDomain.BaseDirectory, "")); // Convert absolute filenames to relative filenames when outputting to screen
            if (!string.IsNullOrWhiteSpace(Config.Path)) {
                File.AppendAllText(Path.Combine(Config.Path, "letsencrypt.log"), message.Trim() + Environment.NewLine);
            }
        }

        public static void LogOpen() {
            Process.Start(Path.Combine(Config.Path, "letsencrypt.log"));
        }

        public static void LogReset() {
            File.Delete(Path.Combine(Config.Path, "letsencrypt.log"));
        }

        public static bool ParseOptions(string[] args) {
            // Parse and validate the command line arguments
            var Result = Parser.Default.ParseArguments<Options>(args);
            var Parsed = Result as Parsed<Options>;
            if (Parsed == null) {
                // Output extra information about how the runmode option works
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
                return false;
            }

            Config.Options = Parsed.Value;
            if (Config.Options.RunMode == RunMode.Staging) Config.BaseUri = "https://acme-staging.api.letsencrypt.org/";

            // Create config directory
            Config.Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, Globals.CleanFilename(Config.BaseUri));
            Directory.CreateDirectory(Config.Path);
            Globals.LogReset();
            Globals.Log($"Config path: {Config.Path}");
            Globals.Log();

            // Confirm options before continuing
            Globals.Log(Config.Options.RunMode.ToString().ToUpper() + " MODE");
            Globals.Log($"  - ACME Server: {Config.BaseUri}");
            Globals.Log("  - A certificate " + (Globals.ShouldCreateCertificate() ? "WILL" : "WON'T") + " be generated for each unique IP address");
            Globals.Log("  - The certificates " + (Globals.ShouldInstallCertificate() ? "WILL" : "WON'T") + " be installed to the cerificate store" + (Config.Options.RunMode == RunMode.InstallCert ? "*" : ""));
            Globals.Log("  - The server's IIS bindings " + (Globals.ShouldUpdateBindings() ? "WILL" : "WON'T") + " be updated to use the certificates" + (Config.Options.RunMode == RunMode.InstallCert ? "*" : ""));
            if (Config.Options.RunMode == RunMode.InstallCert) {
                Globals.Log();
                Globals.Log("* Since certificate generation is being skipped, the newest certificate on disk will be used instead");
            }
            Globals.Log();
            Console.Write("Do you wish to continue in this mode? [Y/N] ");
            return Globals.PromptYesNo();
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

        public static bool ShouldCreateCertificate() {
            switch (Config.Options.RunMode) {
                case RunMode.CreateCert: return true; // CreateCert should generate a certificate
                case RunMode.InstallCert: return false; // InstallCert should note generate a certificate
                case RunMode.Production: return true; // Production should generate a certificate
                case RunMode.Staging: return true; // Staging should generate a certificate
                default: throw new ArgumentOutOfRangeException("Unexpected RunMode: " + Config.Options.RunMode);
            }
        }

        public static bool ShouldInstallCertificate() {
            switch (Config.Options.RunMode) {
                case RunMode.CreateCert: return false; // CreateCert should not install a certificate
                case RunMode.InstallCert: return true; // InstallCert should install a certificate
                case RunMode.Production: return true; // Production should install a certificate
                case RunMode.Staging: return Debugger.IsAttached; // Staging should install a certificate in debugger
                default: throw new ArgumentOutOfRangeException("Unexpected RunMode: " + Config.Options.RunMode);
            }
        }

        public static bool ShouldUpdateBindings() {
            switch (Config.Options.RunMode) {
                case RunMode.CreateCert: return false; // CreateCert should not update bindings
                case RunMode.InstallCert: return true; // InstallCert should update bindings
                case RunMode.Production: return true; // Production should update bindings
                case RunMode.Staging: return Debugger.IsAttached; // Staging should update bindings in debugger
                default: throw new ArgumentOutOfRangeException("Unexpected RunMode: " + Config.Options.RunMode);
            }
        }

        public static void WarmUpUrl(string url, string expectedResponse) {
            int TryNumber = 1;
            while (true) {
                int x = Console.CursorLeft;
                int y = Console.CursorTop;

                Globals.Log($" - Warming up {url} (Try #{TryNumber++})");
                try {
                    using (var WC = new WebClient()) {
                        WC.Headers.Add("user-agent", "Mozilla/5.0 (compatible; Let's Encrypt validation server;  https://www.letsencrypt.org)");
                        string Response = WC.DownloadString(url);
                        if (Response == expectedResponse) {
                            break; // Got the response we want, so exit the loop and let LetsEncrypt retrieve the answer
                        }
                    }
                } catch (WebException wex) {
                    if (wex.Response is HttpWebResponse) {
                        var Response = (HttpWebResponse)wex.Response;
                        if (Response.StatusCode == HttpStatusCode.NotFound) {
                            Globals.Log($"   - HTTP EXCEPTION ({Response.StatusCode}): {wex.Message} -- Fix the problem and hit a key to try again");
                            Console.ReadKey();
                            Console.CursorTop -= 1;
                            Console.Write(new string(' ', Console.WindowWidth));
                            Console.CursorTop -= 2;
                            Console.Write(new string(' ', Console.WindowWidth));
                        } else {
                            Globals.Log($"   - HTTP EXCEPTION ({Response.StatusCode}): {wex.Message}");
                        }
                    } else {
                        Globals.Log($"   - WEB EXCEPTION ({wex.Status}): {wex.Message}");
                    }
                } catch (Exception ex) {
                    Globals.Log($"   - EXCEPTION: {ex.Message}");
                }

                // If we get here we didn't get the response we want -- for sites like Sitefinity that are slow to warmup we should delay and try again
                Globals.Log($"   - Invalid response, waiting 5 seconds before trying again...");
                Thread.Sleep(5000);

                // This prevents scrolling while retrying
                Console.CursorTop -= 1;
                Console.Write(new string(' ', Console.WindowWidth - 1));
                Console.SetCursorPosition(x, y);
            }
        }
    }
}
