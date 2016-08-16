// TODOX First domain is 429'ing, and then subsequent are 400'ing.  Maybe loop and create a unique client for each IP address?
// TODOX Store the lowercase alpha-sorted hostnames used when creating a given certificate, so if the list hasn't changed a new cert isn't requested again within an X day period
//       (avoids their "5 duplicate certs per week" rate limit)
using ACMESharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LetsEncrypt.ACME.Simple {
    class Program {
        private static void Main(string[] args) {
            try {
                // Force TLS 1.1 or 1.2
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;

                // Output banner
                Console.Clear();
                Globals.Log("Let's Encrypt (Simple Windows ACME Client -- SAN per IP mod)");
                Globals.Log();

                // Confirm running as admin
                if (!Globals.IsElevated()) {
                    Globals.Log("You must run this program as an administrator.  Aborting.");
                    return;
                }

                // Confirm IIS is installed
                if (!IIS.IsInstalled()) {
                    Globals.Log("You must run this program on a computer with IIS installed.  Aborting.");
                    return;
                }

                // Parse command-line options and confirm user wants to continue with the selected options
                if (!Globals.ParseOptions(args)) return;

                // Get a listing of all the IIS bindings
                List<Binding> Bindings = IIS.GetBindings();
                if (Bindings.Count > 0) {
                    // Get a listing of the unique IP addresses used by the various bindings
                    var UniqueIPAddresses = Bindings.Select(x => x.IPAddress).Distinct();
                    foreach (var UniqueIPAddress in UniqueIPAddresses) {
                        // Initialize the AcmeSharp library
                        var ASH = new AcmeSharpHelper();
                        ASH.Init();

                        Globals.Log();
                        Globals.Log($"Handling {UniqueIPAddress}");

                        try {
                            // Get a listing of the bindings that use this IP address
                            var ThisIPsBindings = Bindings.Where(x => x.IPAddress == UniqueIPAddress).ToList();
                            if (ThisIPsBindings.Count > 100) {
                                // Let's Encrypt doesn't support this many hosts in a single cert
                                Globals.Log($" - IP {UniqueIPAddress} has too many hosts for a SAN certificate.  Let's Encrypt currently has a maximum of 100 alternative names per certificate.");
                            } else {
                                // Try to authorize all the hosts
                                if (ASH.AuthorizeBindings(ThisIPsBindings)) {
                                    // Generate the certificate
                                    string PfxFilename = ASH.RequestCertificateAndConvertToPfx(ThisIPsBindings);
                                    if (File.Exists(PfxFilename)) {
                                        // Install the certificate into the WebHost store
                                        X509Store Store;
                                        X509Certificate2 Certificate;
                                        CertificateHelper.InstallCertificate(ThisIPsBindings[0], PfxFilename, out Store, out Certificate);

                                        // TODOX Uninstall the old certificate from the WebHost store

                                        // Add/update the HTTPS bindings in IIS to use the new certificate (don't update in test mode, unless we're debugging locally)
                                        IIS.UpdateBindings(ThisIPsBindings, PfxFilename, Store, Certificate);
                                    } else {
                                        // If we were wanting to install this certificate, throw an exception to say it couldn't be found
                                        if (Globals.ShouldInstallCertificate()) {
                                            throw new Exception($" - Certificate file {PfxFilename} does not exist");
                                        }
                                    }
                                } else {
                                    // One or more hosts failed to authorize, so this cert cannot be generated
                                    throw new Exception(" - One or more hosts failed to pass authorization, so the certifcate will not be created/installed");
                                }
                            }
                        } catch (Exception ex) {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Globals.Log();
                            Globals.Log("EXCEPTION: " + ex.ToString());
                            Console.ResetColor();
                            Globals.Log("Continuing with next IP address...");
                            // TODOX Maybe record the failed IPs and then output a command at the end that will re-process just that one IP
                            //       Take the existing options into account (ie include --runmode Staging if it was used for the current process)
                            //       Then add --ips 10.20.30.100,127.0.0.1 etc to target just the given IP(s)
                        }
                    }
                }
            } catch (AcmeClient.AcmeWebException awex) {
                Console.ForegroundColor = ConsoleColor.Red;
                Globals.Log();
                Globals.Log("ACME WEB EXCEPTION: " + awex.Message);
                Globals.Log("  - Response: " + awex.Response.ContentAsString);
                Globals.Log("  - Stacktrace: " + awex.StackTrace.ToString());
                Console.ResetColor();
            } catch (Exception ex) {
                Console.ForegroundColor = ConsoleColor.Red;
                Globals.Log();
                Globals.Log("EXCEPTION: " + ex.ToString());
                Console.ResetColor();
            }

            Console.WriteLine();
            Console.WriteLine("Press enter to continue.");
            Console.ReadLine();
            Globals.LogOpen();
        }
    }
}
