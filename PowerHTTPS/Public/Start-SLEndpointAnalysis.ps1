function Start-SLEndpointAnalysis
{
<#
.SYNOPSIS
    Starts an HTTPS security analysis on a given site.
.DESCRIPTION
    Startss an HTTPS security analysis on a given site.

    By default the results are not publicly shared, the switch -Public will allow public results.
    If the site you are analyzing has a mismatched certificate name and hostname use the -IgnoreMismatch switch to allow analysis to complete.

    All times are in UTC.
.EXAMPLE
    Start-SLEndpointAnalysis -Host incomplete-chain.badssl.com -Public

    Host                  : incomplete-chain.badssl.com
    Port                  : 443
    Protocol              : HTTP
    Public                : True
    Status                : DNS
    StartTime             : 11/21/2016 12:13:31 AM
    AnalysisTime          :
    EngineVersion         : 1.25.2
    RatingCriteriaVersion : 2009l
    Endpoints             :

    The example above will start an HTTPS security analysis and return partial results.
    To get the full results run the cmdlet Get-SLEndpointAnalysis verify that the Status proeprty reports either READY of ERROR.
.EXAMPLE
    PS C:\>Start-SLEndpointAnalysis -Host www.microsoft.com -IgnoreMismatch

    Host                  : www.microsoft.com
    Port                  : 443
    Protocol              : HTTP
    Public                : False
    Status                : DNS
    StartTime             : 11/21/2016 13:13:31 AM
    AnalysisTime          :
    EngineVersion         : 1.25.2
    RatingCriteriaVersion : 2009l
    Endpoints             :

    The example above will start an HTTPS security analysis and return partial results while ignoring any mismatch errors.
    To get the full results run the cmdlet Get-SLEndpointAnalysis verify that the Status proeprty reports either READY of ERROR.
.INPUTS
    System.String[]

    The hosts to analyze.

    System.Diagnostics.Switch

    When selected the Public parameter will allow the analysis to be seen publicly.
    When selected the IgnoreMismatch parameter will set the analysis to ignore certificate mismatches.
.OUTPUTS
    PowerHTTPS.Analysis
.NOTES
    This project is not officially affiliated with Qualys SSL Labs.
.LINK
    https://www.ssllabs.com/about/terms.html
#>
    [CmdletBinding(ConfirmImpact='Low',PositionalBinding=$true)]
    [Alias('sslea')]
    [OutputType('PowerHTTPS.Analysis')]
    Param
    (
        # The hostname of the endpoint to query for.
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias('Host','ComputerName')]
        [String[]]$Name,
        # Allow the analysis results to be publicly accessable.
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Switch]$Public,
        # Allow the analysis to continue after a certificate mismatch.
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Switch]$IgnoreMismatch
    )

    Begin
    {
        if($Public){ $publish = 'on' } else { $publish = 'off' }
        if($IgnoreMismatch){ $mismatch = 'on' } else { $mismatch = 'off' }
    }

    Process
    {
        foreach($ep in $Name)
        {
            try
            {
                [Uri]$apiUri = '{0}{1}' -f $script:apiUriBase, "analyze?host=$ep&publish=$publish&ignoreMismatch=$mismatch&all=done&startNew=on"
                $info = Invoke-RestMethod -Method Get -Uri $apiUri
                $returnInfo = [PSCustomObject]@{
                    'PSTypeName' = 'PowerHTTPS.Analysis'
                    'Host' = $info.host
                    'Port' = $info.port
                    'Protocol' = $info.protocol
                    'Public' = [bool]$info.isPublic
                    'Status' = $info.status
                    'StartTime' = ([datetime]'1/1/1970').AddMilliseconds($info.startTime)
                    'AnalysisTime' = if($info.testTime){ ([datetime]'1/1/1970').AddMilliseconds($info.testTime) } else { $null }
                    'EngineVersion' = [version]$info.engineVersion
                    'RatingCriteriaVersion' = [string]$info.criteriaVersion
                    'Endpoints' = foreach($p in $info.endpoints){
                        [PSCustomObject]@{
                            'PSTypeName' = 'PowerHTTPS.Endpoint'
                            'IPAddress' = [ipaddress]$p.ipAddress
                            'ServerDNSName' = $p.serverName
                            'Status' = $p.statusMessage
                            'Grade' = $p.grade
                            'GradeTrustIgnored' = $p.gradeTrustIgnored
                            'HasWarnings' = [bool]$p.hasWarnings
                            'IsExceptional' = [bool]$p.isExceptional
                            'HasWWWPrefix' = switch($p.delegation){ 1 { $false; break }; 2 { $true; break } }
                            'ScanProgress' = $p.progress
                            'ScanDuration' = $p.duration
                            'ScanETA' = $p.eta
                            'Details' = [PSCustomObject]@{
                            'PSTypeName' = 'PowerHTTPS.Endpoint.Details'
                            'ScanStartTime' = if($p.details.hostStartTime){ ([datetime]'1/1/1970').AddMilliseconds($p.details.hostStartTime) } else { $null }
                            'CertificateKey' = [PSCustomObject]@{
                                'PSTypeName' = 'PowerHTTPS.Key'
                                'Length' = $p.details.key.size
                                'Algorithm' = $p.details.key.alg
                                'Strength' = $p.details.key.strength
                                'WeakRNG' = [bool]$p.details.key.debianFlaw
                            }
                            'Certificate' = [PSCustomObject]@{
                                'PSTypeName' = 'PowerHTTPS.Certificate'
                                'Subject' = $p.details.cert.subject
                                'CommonNames' = [string[]]$p.details.cert.commonNames
                                'AlternativeNames' = [string[]]$p.details.cert.altNames
                                'NotBefore' = if($p.details.cert.notBefore){ ([datetime]'1/1/1970').AddMilliseconds($p.details.cert.notBefore) } else { $null }
                                'NotAfter' = if($p.details.cert.notAfter){ ([datetime]'1/1/1970').AddMilliseconds($p.details.cert.notAfter) } else { $null }
                                'IssuerSubject' = $p.details.cert.issuerSubject
                                'IssuerLabel' = $p.details.cert.issuerLabel
                                'SignatureAlgorithm' = $p.details.cert.sigAlg
                                'RevocationType' = switch($p.details.cert.revocationInfo){ 1 { 'CRL'; break }; 2 { 'OCSP'; break } }
                                'CRLUri' = [Uri[]]$p.details.cert.crlURIs
                                'OCSPUri' = [Uri[]]$p.details.cert.ocspURIs
                                'RevocationStatus' = switch($p.details.cert.revocationStatus){
                                    0 { 'Not Checked'; break }
                                    1 { 'Revoked'; break }
                                    2 { 'Not Revoked'; break }
                                    3 { 'Revocation Check Error'; break }
                                    4 { 'No Revocation Info'; break }
                                    5 { 'SSL Labs Error'; break }
                                }
                                'CRLRevocationStatus' = switch($p.details.cert.crlRevocationStatus){
                                    0 { 'Not Checked'; break }
                                    1 { 'Revoked'; break }
                                    2 { 'Not Revoked'; break }
                                    3 { 'Revocation Check Error'; break }
                                    4 { 'No Revocation Info'; break }
                                    5 { 'SSL Labs Error'; break }
                                }
                                'OCSPRevocationStatus' = switch($p.details.cert.ocspRevocationStatus){
                                    0 { 'Not Checked'; break }
                                    1 { 'Revoked'; break }
                                    2 { 'Not Revoked'; break }
                                    3 { 'Revocation Check Error'; break }
                                    4 { 'No Revocation Info'; break }
                                    5 { 'SSL Labs Error'; break }
                                }
                                'ServerGatedCryptography' = switch($p.details.cert.sgc){ 1 { 'Netscape SGC'; break }; 2 { 'Microsoft SGC'; break } }
                                'ValidationType' = $p.details.cert.validationType
                                'Issues' = switch($p.details.cert.issues){
                                    {$_ -band 1} {'No Chain of Trust'}
                                    {$_ -band 2} {''}
                                    {$_ -band 4} {'Expired Not After'}
                                    {$_ -band 8} {'Hostname Mismatch'}
                                    {$_ -band 16} {'Revoked'}
                                    {$_ -band 32} {'Bad Common Name'}
                                    {$_ -band 64} {'Self-signed'}
                                    {$_ -band 128} {'Blacklisted'}
                                    {$_ -band 256} {'Insecure Signature'}
                                }
                                'CertificateTransparency' = [bool]$p.details.cert.sct
                                'OCSPMustStaple' = switch($p.details.cert.mustStaple){
                                    0 { 'Not Supported'; break }
                                    1 { 'Supported, Not Enabled'; break }
                                    3 { 'Supported, Enabled'; break }
                                }
                                'SHA1Hash' = $p.details.cert.sha1Hash
                                'KeyPinningSHA256' = $p.details.cert.pinSha256
                            }
                            'CertificateChain' = [PSCustomObject]@{
                                'PSTypeName' = 'PowerHTTPS.Chain'
                                'Certificates' = foreach($i in $p.details.chain.certs){
                                    [PSCustomObject]@{
                                        'PSTypeName' = 'PowerHTTPS.Chain.ChainCert'
                                        'Subject' = $i.subject
                                        'Label' = $i.label
                                        'NotBefore' = if($i.notBefore){ ([datetime]'1/1/1970').AddMilliseconds($i.notBefore) } else { $null }
                                        'NotAfter' = if($i.notBefore){ ([datetime]'1/1/1970').AddMilliseconds($i.notAfter) } else { $null }
                                        'IssuerSubject' = $i.issuerSubject
                                        'IssuerLabel' = $i.issuerLabel
                                        'SignatureAlgorithm' = $i.sigAlg
                                        'Issues' = switch($i.issues){
                                            {$_ -band 2} { 'Incomplete Chain' }
                                            {$_ -band 4} { 'Chain Contains Unrelated or Duplicate Certificates' }
                                            {$_ -band 8} { 'Incorrect Chain Order' }
                                            {$_ -band 16} { 'Contains Self-signed Root Certificate' }
                                            {$_ -band 32} { 'Incomplete Chain' }
                                        }
                                        'KeyAlgorithm' = $i.keyAlg
                                        'KeyLength' = $i.keySize
                                        'KeyStrength' = $i.keyStrength
                                        'RevocationStatus' = switch($i.revocationStatus){
                                            0 { 'Not Checked'; break }
                                            1 { 'Revoked'; break }
                                            2 { 'Not Revoked'; break }
                                            3 { 'Revocation Check Error'; break }
                                            4 { 'No Revocation Info'; break }
                                            5 { 'SSL Labs Error'; break }
                                        }
                                        'CRLRevocationStatus' = switch($i.crlRevocationStatus){
                                            0 { 'Not Checked'; break }
                                            1 { 'Revoked'; break }
                                            2 { 'Not Revoked'; break }
                                            3 { 'Revocation Check Error'; break }
                                            4 { 'No Revocation Info'; break }
                                            5 { 'SSL Labs Error'; break }
                                        }
                                        'OCSPRevocationStatus' = switch($i.ocspRevocationStatus){
                                            0 { 'Not Checked'; break }
                                            1 { 'Revoked'; break }
                                            2 { 'Not Revoked'; break }
                                            3 { 'Revocation Check Error'; break }
                                            4 { 'No Revocation Info'; break }
                                            5 { 'SSL Labs Error'; break }
                                        }
                                        'SHA1Hash' = $i.sha1Hash
                                        'KeyPinningSHA256' = $i.pinSha256
                                        'RawCertifcate' = [string]$i.raw
                                    }
                                }
                            }
                            'HTTPSProtocols' = foreach($p in $p.details.protocols){
                                [PSCustomObject]@{
                                    'PSTypeName' = 'PowerHTTPS.Protocol'
                                    'ID' = $p.id
                                    'Name' = $p.name
                                    'Version' = [version]$p.version
                                    'SSLv2SuitesDisabled' = [bool]$p.v2SuitesDisabled
                                    'InsecureProtocol' = [bool]$p.q
                                }
                            }
                            'Suites' = foreach($s in $p.details.suites.list){
                                [PSCustomObject]@{
                                    'PSTypeName' = 'PowerHTTPS.Suite'
                                    'ID' = $s.id
                                    'Name' = $s.name
                                    'CipherStrength' = $s.cipherStrength
                                    'DHStrength' = $s.dhStrength
                                    'DHPComponent' = $s.dhP
                                    'DHGComponent' = $s.dhG
                                    'DHYsComponent' = $s.dhYs
                                    'ECDHBits' = $s.ecdhBits
                                    'ECDHStrength' = $s.ecdhStrength
                                    'InsecureSuite' = [bool]$s.q
                                }
                            }
                            'ServerSignature' = $p.details.serverSignature
                            'PrefixDelegation' = [bool]$p.details.prefixDelegation
                            'NonPrefixDelegation' = [bool]$p.details.nonPrefixDelegation
                            'BEASTVulnerability' = [bool]$p.details.vulnBeast
                            'RenegotiationSupport' = switch($p.details.renegSupport){
                                {$_ -band 1} { 'Insecure Client-initiated Supported' }
                                {$_ -band 2} { 'Secure Renegotiation Supported' }
                                {$_ -band 4} { 'Secure Client-initiated Supported' }
                                {$_ -band 8} { 'Secure Renegotiation Required by Server' }
                            }
                            'SessionResumption' = switch($p.details.sessionResumption){
                                0 { 'Session resumption is not enabled, session IDs are empty'; break }
                                1 { 'Session IDs are returned but sessions are not resumed'; break }
                                2 { 'Session Resumption is Enabled'; break }
                            }
                            'CompressionMethods' = switch($p.details.compressionMethods){ 0 { 'Deflate'; break } }
                            'SupportsNextProtocolNegotiation' = [bool]$p.details.supportsNpn
                            'NextProtocolNegotiationProtocols' = if($p.details.npnProtocols){ [string[]]$p.details.npnProtocols.Split(' ') } else { $null }
                            'ALPNSupported' = [bool]$p.details.supportsAlpn
                            'SessionTickets' = switch($p.details.sessionTickets){ 1 {'Supported';break }; 2 {'Broken Support';break }; 4 {'Not Supported';break } }
                            'OCSPStapling' = [bool]$p.details.ocspStapling
                            'StaplingRevocationStatus' = switch($p.details.cert.staplingRevocationStatus){
                                0 { 'Not Checked'; break }
                                1 { 'Revoked'; break }
                                2 { 'Not Revoked'; break }
                                3 { 'Revocation Check Error'; break }
                                4 { 'No Revocation Info'; break }
                                5 { 'SSL Labs Error'; break }
                            }
                            'SNIRequired' = [bool]$p.details.sniRequired
                            'HTTPStatusCode' = if($p.details.httpStatusCode){ $p.details.httpStatusCode } else { 'Failed' }
                            'HTTPForwarding' = $p.details.httpForwarding
                            'SupportsRC4' = [bool]$p.details.supportsRc4
                            'SupportsRC4ModernSuites' = [bool]$p.details.rc4WithModern
                            'SupportsOnlyRC4' = [bool]$p.details.rc4Only
                            'ForwardSecrecy' = switch($p.details.forwardSecrecy){ 1 { 'At Least One Client'; break }; 2 { 'All Modern Clients'; break }; 4 { 'All Clients'; break } }
                            'ProtocolIntolerance' = switch($p.details.protocolIntolerance){
                                {$_ -band 1} { 'TLS 1.0' }
                                {$_ -band 2} { 'TLS 1.1' }
                                {$_ -band 4} { 'TLS 1.2' }
                                {$_ -band 8} { 'TLS 1.3' }
                                {$_ -band 16} { 'TLS 1.152' }
                                {$_ -band 32} { 'TLS 2.152' }
                            }
                            'OtherIntolerance' = switch($p.details.miscIntolerance){ 1 { 'Extension'; break }; 2 { 'Long Handshake'; break }; 4 { 'Long Handshake Workaround Success'; break } }
                            'Simulations' = foreach($sim in $p.details.sims.results){
                                [PSCustomObject]@{
                                    'PSTypeName' = 'PowerHTTPS.Simulation'
                                    'Client' = [PSCustomObject]@{
                                        'PSTypeName' = 'PowerHTTPS.Simulation.Client'
                                        'ID' = $sim.client.id
                                        'Name' = $sim.client.name
                                        'Version' = $sim.client.version
                                        'Reference' = [bool]$sim.client.isReference
                                    }
                                    'HandshakeSuccess' = switch($sim.errorCode){ 0 { $true; break }; 1 { $false; break } }
                                    'AttemptCount' = $sim.attempts
                                }
                            }
                            'HeartbleedVulnerability' = [bool]$p.details.heartbleed
                            'HeartbeatEnabled' = [bool]$p.details.heartbeat
                            'OpenSSLCCSVulnerability' = switch($p.details.openSslCcs){
                                -1 { 'Test Failed'; break }
                                0 { 'Unknown'; break }
                                1 { 'Not Vulnerable'; break }
                                2 { 'Possibly Vulnerable Not Exploitable'; break }
                                3 { 'Exploitable'; break }
                            }
                            'OpenSSLLuckyMinus20Vulnerability' = switch($p.details.openSSLLuckyMinus20){
                                -1 { 'Test Failed'; break }
                                0 { 'Unknown'; break }
                                1 { 'Not Vulnerable'; break }
                                2 { 'Vulnerable'; break }
                            }
                            'POODLEVulnerability' = [bool]$p.details.poodle
                            'POODLETLSVulnerability' = switch($p.details.poodleTls){
                                -3 { 'Timeout'; break }
                                -2 { 'TLS Not Supported'; break }
                                -1 { 'Test Failed'; break }
                                0 { 'Unknown'; break }
                                1 { 'Not Vulnerable'; break }
                                2 { 'Vulnerable'; break }
                            }
                            'FallbackSignalingCipherSuiteValueSupported' = [bool]$p.details.fallbackScsv
                            'FREAKVulnerability' = [bool]$p.details.freak
                            'HasSCT' = switch($p.details.hasSct){ 1 { 'In Certificate'; break }; 2 { 'In OCSP Responce'; break }; 4 { 'In TLS Extension'; break }; Default { 'No'; break } }
                            'DiffieHellmanPrimes' = $p.details.dhPrimes
                            'DiffieHellmanUsesKnownPrimes' = switch($p.details.dhUsesKnownPrimes){ 0 { 'No'; break }; 1 { 'Uses Known Non-Weak Primes'; break }; 2 { 'Uses Known Weak Primes'; break } }
                            'DiffieHellmanEphemeralKeyReused' = [bool]$p.details.dhYsReuse
                            'LogjamVulnerability' = [bool]$p.details.logjam
                            'ClientChaCha20Preference' = if($p.details.chaCha20Preference){ [bool]$p.details.chaCha20Preference } else { $null }
                            'HTTPStrictTransportSecurityPolicy' = [PSCustomObject]@{
                                'PSTypeName' = 'PowerHTTPS.HSTSPolicy'
                                'LongMaxAge' = $p.details.hstsPolicy.LONG_MAX_AGE
                                'Header' = $p.details.hstsPolicy.header
                                'Status' = $p.details.hstsPolicy.status
                                'Error' = $p.details.hstsPolicy.error
                                'MaxAge' = $p.details.hstsPolicy.maxAge
                                'IncludesSubDomains' = [bool]$p.details.hstsPolicy.includeSubDomains
                                'Preload' = [bool]$p.details.hstsPolicy.preload
                                'Directives' = $p.details.hstsPolicy.directives
                            }
                            'HTTPStrictTransportSecurityPreloads' = foreach($preload in $p.details.hstsPreloads){
                                [PSCustomObject]@{
                                    'PSTypeName' = 'PowerHTTPS.HSTSPreload'
                                    'Source' = $preload.source
                                    'Hostname' = $preload.hostname
                                    'Status' = $preload.status
                                    'PreloadCheckTime' = if($preload.sourceTime){ ([datetime]'1/1/1970').AddMilliseconds($preload.sourceTime) } else { $null }
                                }
                            }
                            'HTTPPublicKeyPinningPolicy' = [PSCustomObject]@{
                                'PSTypeName' = 'PowerHTTPS.HPKPPolicy'
                                'Status' = $p.details.hpkpPolicy.status
                                'Header' = $p.details.hpkpPolicy.header
                                'Error' = $p.details.hpkpPolicy.error
                                'MaxAge' = $p.details.hpkpPolicy.maxAge
                                'IncludesSubDomains' = [bool]$p.details.hpkpPolicy.includeSubDomains
                                'ReportUri' = [uri]$p.details.hpkpPolicy.reportUri
                                'Pins' = $p.details.hpkpPolicy.pins
                                'MatchedPins' = $p.details.hpkpPolicy.matchedPins
                                'Directives' = $p.details.hpkpPolicy.directives
                            }
                            'DrownHosts' = foreach($h in $p.details.drownHosts){
                                [PSCustomObject]@{
                                    'PSTypeName' = 'PowerHTTPS.DrownHost'
                                    'IPAddress' = [ipaddress]$h.ip
                                    'Export' = [bool]$h.export
                                    'Port' = $h.port
                                    'OpenSSLVersionVulnerable' = [bool]$h.special
                                    'SSLv2Supported' = [bool]$h.sslv2
                                    'Status' = $h.status
                                }
                            }
                            'DrownErrors' = [bool]$p.details.drownErrors
                            'DrownVulnerable' = [bool]$p.details.drownVulnerable
                            }
                        }
                    }
                }

                Write-Output $returnInfo
            }
            catch
            {
                if($_.Exception.Response)
                {
                    # Convert a 400-599 error to something useable.
                    $errorDetail = (Resolve-HTTPResponse -Response $_.Exception.Response) | ConvertFrom-Json
                    foreach($m in $errorDetail.errors){ Write-Error -Message $m.message }
                }
                else
                {
                    # Return the error as is.
                    Write-Error -Message $_
                }
            }
        }
    }
}