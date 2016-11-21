Import-Module $PSScriptRoot\..\PowerHTTPS\PowerHTTPS.psd1 -Force

InModuleScope PowerHTTPS {
    Describe PowerHTTPS {
        It 'Retrieves engine and assessment metadata from SSL Labs' {
            $info = Get-SLInfo
            $info.EngineVersion | Should BeOfType [version]
            $info.RatingCriteriaVersion | Should Exist
            $info.MaxAssessments | Should Exist
            $info.ActiveAssessments | Should Exist
            $info.NewAssessmentCoolOff | Should Exist
            $info.Message | Should Exist
        }
        It 'Starts an HTTPS security analysis on a given site' {
            $pub = Start-SLEndpointAnalysis -Name www.microsoft.com -Public
            $pub.Host | Should BeExactly 'www.microsoft.com'
            $pub.Public | Should Be $true
            $pub.StartTime | Should BeOfType [datetime]
            $pub.StartTime | Should Not Be [datetime]'1/1/1970'
            $pub.EngineVersion | Should BeOfType [version]
            $pub.RatingCriteriaVersion | Should Exist
            $pub.Endpoints | Should Be $null
        }
        It 'Retrieves the data for a previously run analysis' {
            # Loop until the assessment completes.
            # After the 12th try the script will exit.
            $i=0
            do {
                Start-Sleep -Seconds 10
                $data = Get-SLEndpointAnalysis -Name www.microsoft.com -DisableCache
                $i++
                if($i -ge 13){ throw 'Unable to retrieve endpoint analysis with Get-SLEndpointAnalysis.' }
            } while ( $data.Status -ne 'READY' -or $data.Status -ne 'ERROR' )

            $data.Host | Should BeExactly 'www.microsoft.com'
            $data.Public | Should Be $true
            $data.StartTime | Should BeOfType [datetime]
            $data.StartTime | Should Not Be [datetime]'1/1/1970'
            $data.AnalysisTime | Should BeOfType [datetime]
            $data.AnalysisTime | Should Not Be [datetime]'1/1/1970'
            $data.EngineVersion | Should BeOfType [version]
            $data.RatingCriteriaVersion | Should Exist
            $data.Endpoints | Should Not Be $null
            foreach($ep in $data.Endpoints){
                $ep.Details | Should Not Be $null
                $ep.Details.ScanStartTime | Should BeOfType [datetime]
                $ep.Details.ScanStartTime | Should Not Be [datetime]'1/1/1970'
                $ep.Details.Certificate.NotAfter | Should BeOfType [datetime]
                $ep.Details.Certificate.NotAfter | Should Not Be [datetime]'1/1/1970'
                $ep.Details.Certificate.NotBefore | Should BeOfType [datetime]
                $ep.Details.Certificate.NotBefore | Should Not Be [datetime]'1/1/1970'
                foreach($cert in $ep.Details.CertificateChain.Certificates){
                    $cert.NotAfter | Should BeOfType [datetime]
                    $cert.NotBefore | Should BeOfType [datetime]
                }
                foreach($p in $ep.Details.HTTPSProtocols){
                    $p.Version | Should BeOfType [version]
                }
            }
        }
    }
}
