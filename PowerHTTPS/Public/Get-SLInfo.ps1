function Get-SLInfo
{
<#
.SYNOPSIS
    Retrieves engine and assessment metadata from SSL Labs.
.DESCRIPTION
    Retrieves engine and assessment metadata from SSL Labs.

    Ouputs the current simulation engine version number as well as the critria version string.

    Lists the current active and max assessment sessions along with the cool off period between assessments.

    Shows any message intended for the originaing IP address, private messages are prefixed with "[Private]".

    All times are in UTC.
.EXAMPLE
    Get-SLInfo

    EngineVersion         : 1.25.2
    RatingCriteriaVersion : 2009l
    MaxAssessments        : 25
    Activeassessments     : 0
    NewAssessmentCoolOff  : 1000
    Message               : This assessment service is provided free of charge by Qualys SSL Labs, subject to our terms and conditions:
                            https://www.ssllabs.com/about/terms.html

    The example above will return the stand output of the cmdlet.
.EXAMPLE
    PS C:\>$sslTestInfo = Get-SLInfo; if($sslTestInfo.ActiveAssessments -ge $sslTestInfo.MaxAssessments){'To many active sessions, please wait.'}

    The example above checks to see if the current active sessions has met or exceeded the limit.
.INPUTS
    None
.OUTPUTS
    PowerHTTPS.Info
.NOTES
    This project is not officially affiliated with Qualys SSL Labs.
.LINK
    https://www.ssllabs.com/about/terms.html
#>
    [CmdletBinding(ConfirmImpact='Low')]
    [Alias('gsli')]
    [OutputType('PowerHTTPS.Info')]
    Param ()

    Begin { [Uri]$apiUri = '{0}{1}' -f $script:apiUriBase, 'info' }

    Process
    {
        try
        {
            $info = Invoke-RestMethod -Method Get -Uri $apiUri
            $returnInfo = [PSCustomObject]@{
                'PSTypeName' = 'PowerHTTPS.Info'
                'EngineVersion' = [version]$info.engineVersion
                'RatingCriteriaVersion' = [string]$info.criteriaVersion
                'MaxAssessments' = $info.maxAssessments
                'ActiveAssessments' = $info.currentAssessments
                'NewAssessmentCoolOff' = $info.newAssessmentCoolOff
                'Message' = [string]$info.messages
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