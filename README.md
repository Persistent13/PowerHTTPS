# PowerHTTPS #

PowerHTTPS is a PowerShell module for the Qualys SSL Labs HTTPS API that allows you to programatically test HTTPS configurations of web sites.

## Installation

To install PowerHTTPS run the either of the following commands:

From an administrative PowerShell console:

```PowerShell
Install-Module -Name PowerHTTPS
```

From a standard PowerShell console:

```PowerShell
Install-Module -Name PowerHTTPS -Scope CurrentUser
```

## Usage

PowerHTTPS has three cmdlets:

- Get-SLInfo
- GET-SLEndpointAnalysis
- Start-SLEndpointAnalysis

### Get-SLInfo

![Get-SLInfo](/Media/Get-SLInfo.gif "Get-SLInfo")

Get-SLInfo retrieves engine and assessment metadata from SSL Labs.

### Get-SLEndpointAnalysis

![Get-SLEndpointAnalysis](/Media/Get-SLEndpointAnalysis.gif "Get-SLEndpointAnalysis")

Get-SLEndpointAnalysis retrieves the data for a previously run analysis. If the data is not present a new analysis will be initiated.

### Start-SLEndpointAnalysis

![Start-SLEndpointAnalysis](/Media/Start-SLEndpointAnalysis.gif "Start-SLEndpointAnalysis")

Start-SLEndpointAnalysis starts an HTTPS security analysis on a given site.

## Contributing

1. Fork it!
2. Create your feature branch: git checkout -b my-new-feature
3. Commit your changes: git commit -am 'Add some feature'
4. Push to the branch: git push origin my-new-feature
5. Submit a pull request ✨
