namespace LetsEncrypt.ACME.Simple {
    public class Binding
    {
        public string Hostname { get; set; }
        public string IPAddress { get; set; }
        public string WebRootPath { get; set; }

        public override string ToString() {
            return $"{Hostname}:{IPAddress} ({WebRootPath})";
        }
    }
}