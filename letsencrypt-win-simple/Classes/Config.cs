namespace LetsEncrypt.ACME.Simple {
    class Config {
        public static string BaseUri { get; set; } = "https://acme-v01.api.letsencrypt.org/";
        public static Options Options { get; set; }
        public static string Path { get; set; }
    }
}
