[CmdletBinding()]
param (
        [Parameter(Mandatory=$true)] [System.Uri]
        $Uri,
        [Parameter(Mandatory=$true)] [string]
        $Name
      )

Set-PSDebug -Trace 2

try {
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    $webRequest = [Net.WebRequest]::Create($Uri)
    $webRequest.GetResponse()
    $cert = $webRequest.ServicePoint.Certificate
    $bytes = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    set-content -value $bytes -encoding byte -path "$pwd\$Name.cer"
} finally {
    Set-PSDebug -Off
}
