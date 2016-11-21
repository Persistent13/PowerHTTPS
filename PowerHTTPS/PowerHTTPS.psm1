#Get public and private function definition files.
    $Public  = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue )
    $Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )

#Dot source the files
    Foreach($import in @($Public + $Private))
    {
        Try
        {
            . $import.fullname
        }
        Catch
        {
            Write-Error -Message "Failed to import function $($import.fullname): $_"
        }
    }

[hashtable]$manifest = Invoke-Expression -Command (Get-Content -Path $PSScriptRoot\PowerHTTPS.psd1 -Raw)

# Set the api uri constant
[Uri]$script:apiUriBase = 'https://api.ssllabs.com/api/v2/'

Export-ModuleMember -Function $Public.Basename -Alias $manifest.AliasesToExport
