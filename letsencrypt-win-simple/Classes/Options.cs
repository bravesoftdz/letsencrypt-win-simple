using CommandLine;

namespace LetsEncrypt.ACME.Simple {
    class Options {
        [Option(Required = true, HelpText = "Sets the mode, which determines the behaviour of the application")]
        public RunMode RunMode { get; set; }        
    }
}