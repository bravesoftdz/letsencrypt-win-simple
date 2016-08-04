using Microsoft.Web.Administration;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace LetsEncrypt.ACME.Simple {
    class IIS {
        public static Version Version { get; set; }

        public static List<Binding> GetBindings() {
            var Result = new List<Binding>();

            Globals.Log("Retrieving HTTP(S) bindings from IIS");
            using (var IISManager = new ServerManager()) {
                foreach (var Site in IISManager.Sites) {
                    foreach (var Binding in Site.Bindings) {
                        // Get HTTP(S) sites that aren't IDN and aren't internal (ie no-period hosts)
                        if (!string.IsNullOrWhiteSpace(Binding.Host) && Binding.Host.Contains(".") &&
                            (Binding.Protocol == "http" || Binding.Protocol == "https") && !Regex.IsMatch(Binding.Host, @"[^\u0000-\u007F]")) {
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

            if (!Result.Any()) Globals.Log(" - No HTTP(S) bindings with hostnames found -- please add some and try again");

            return Result;
        }

        private static Version GetVersion() {
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

        public static bool IsInstalled() {
            Version = GetVersion();
            return (Version.Major > 0);
        }

        public static void UpdateBindings(List<Binding> bindings, string pfxFilename, X509Store store, X509Certificate2 certificate) {
            Globals.Log();
            Globals.Log("Adding/updating HTTPS bindings");

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
                                    //string NewBinding = $"{BindingIPAddress}:{ExistingHTTPSBinding.EndPoint.Port}:{Binding.Hostname}";

                                    if (Globals.ShouldUpdateBindings()) {
                                        //Globals.Log($" - Replacing binding for {NewBinding}");
                                        //Site.Bindings.Remove(ExistingHTTPSBinding);
                                        //var iisBinding = Site.Bindings.Add(NewBinding, certificate.GetCertHash(), store.Name);
                                        //iisBinding.Protocol = "https";
                                        //if (IIS.Version.Major >= 8) iisBinding.SetAttributeValue("sslFlags", 0); // Disable SNI support

                                        // TODO This fails sometimes when there's two HTTPS bindings for the same hostname with different ports
                                        //      Worked around it by a port redirect on the firewall, so now everything is on 443
                                        Globals.Log($" - Updating binding for {ExistingHTTPSBinding}");
                                        ExistingHTTPSBinding.CertificateStoreName = store.Name;
                                        ExistingHTTPSBinding.CertificateHash = certificate.GetCertHash();
                                        if (Version.Major >= 8) ExistingHTTPSBinding.SetAttributeValue("sslFlags", 0); // Disable SNI support
                                    } else {
                                        Console.ForegroundColor = ConsoleColor.Yellow;
                                        Globals.Log($" * If I wasn't running in {Config.Options.RunMode} mode, I'd be updating the binding for {ExistingHTTPSBinding} right now");
                                        Console.ResetColor();
                                    }
                                }
                            } else {
                                string NewBinding = $"{BindingIPAddress}:443:{Binding.Hostname}";

                                if (Globals.ShouldUpdateBindings()) {
                                    Globals.Log($" - Adding binding for {NewBinding}");
                                    var iisBinding = Site.Bindings.Add(NewBinding, certificate.GetCertHash(), store.Name);
                                    iisBinding.Protocol = "https";
                                    if (Version.Major >= 8) iisBinding.SetAttributeValue("sslFlags", 0); // Disable SNI support
                                } else {
                                    Console.ForegroundColor = ConsoleColor.Yellow;
                                    Globals.Log($" * If I wasn't running in {Config.Options.RunMode} mode, I'd be adding a binding for {NewBinding} right now");
                                    Console.ResetColor();
                                }
                            }
                        }
                    }
                }

                if (Globals.ShouldUpdateBindings()) {
                    Globals.Log($" - Committing binding changes to IIS");
                    IISManager.CommitChanges();
                }
            }
        }
    }
}
