function Import-IEFPolicies {
    <#
    .SYNOPSIS
    Uploads IEF xml policies to a tenant
    
    .DESCRIPTION
    Uploads IEF xml policies to a tenant. Modifies the xml source prior to the upload by replacing IEF app symbolic names
    with actual app Ids from the tenant. Replaces other symbolic paramaters included in the xml with '{}' braces by corresponding
    values in the conf.json file. Injects a defined prefix into the name of the policy. Modified xml is saved in a separate directory after import.
    
    .PARAMETER sourceDirectory
    Directory with xml policies and (optinaly) conf.json file
    
    .PARAMETER configurationFilePath
    Name of file with configuration values if not conf.json
    
    .PARAMETER updatedSourceDirectory
    Directory updated policies are stored after upload
    
    .PARAMETER prefix
    Parameter to be injected into the name of each policy (e.g. B2C_1A_YOURPREFIXBase)
    
    .PARAMETER generateOnly
    Update xml files and store them in the updatedSourceDirectory but do not upload to the B2C tenant
    
    .EXAMPLE
        PS C:\> Import-IEFPolicies

        Upload policies from the current work directory using conf.json file for configuration data if it exists.
    
    .NOTES
    Please use connect-iefpolicies -tenant <tanant Name> before executing this command
    #>
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$tenantName,

        #[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$sourceDirectory = '.\',

        [ValidateNotNullOrEmpty()]
        [string]$configurationFilePath = '.\conf.json',

        [ValidateNotNullOrEmpty()]
        [string]$updatedSourceDirectory = '.\debug\',

        [ValidateNotNullOrEmpty()]
        [string]$prefix,

        [ValidateNotNullOrEmpty()]
        [switch]$generateOnly

    )


    # upload policies whose base id is given
    function Import-Children($baseId) {
        foreach($p in $policyList) {
            if ($p.BaseId -eq $baseId) {
                # Skip unchanged files
                #outFile = ""
                if (-not ([string]::IsNullOrEmpty($updatedSourceDirectory))) {
                    if(!(Test-Path -Path $updatedSourceDirectory )){
                        New-Item -ItemType directory -Path $updatedSourceDirectory
                        Write-Host "Updated source folder created"
                    }
                    if (-not $updatedSourceDirectory.EndsWith("\")) {
                        $updatedSourceDirectory = $updatedSourceDirectory + "\"
                    }
                    $envUpdatedDir = '{0}{1}' -f $updatedSourceDirectory, $b2cDomain
                    if(!(Test-Path -Path $envUpdatedDir)){
                        New-Item -ItemType directory -Path $envUpdatedDir
                        Write-Host "  Updated source folder created for " + $b2cDomain
                    }
                    $outFile = '{0}\{1}' -f $envUpdatedDir, $p.Source
                    if (Test-Path $outFile) {
                        if ($p.LastWrite.Ticks -le (Get-Item $outFile).LastWriteTime.Ticks) {
                            "{0}: is up to date" -f $p.Id
                            Import-Children $p.Id
                            continue;
                        }
                    }
                }
                $msg = "{0}: uploading" -f $p.Id
                Write-Host $msg  -ForegroundColor Green 
                # Replace tenant id but only if already there. It messes up xml formatting
                $xml = [xml] $p.Body
                $xml.PreserveWhitespace = $true
                try {
                    $resp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/organization" -Method Get -Headers $headers
                    $xml.TrustFrameworkPolicy.TenantObjectId = $resp.value[0].Id
                    $policy = $xml.OuterXml
                } catch {
                    # tenantId not used
                    $policy = $p.Body
                }
                $policy = $policy -replace "yourtenant", $b2cName 
                $policy = $policy -replace "ProxyIdentityExperienceFrameworkAppId", $iefProxy.appId
                $policy = $policy -replace "IdentityExperienceFrameworkAppId", $iefRes.appId
                $policy = $policy.Replace('PolicyId="B2C_1A_', 'PolicyId="B2C_1A_{0}' -f $prefix)
                $policy = $policy.Replace('/B2C_1A_', '/B2C_1A_{0}' -f $prefix)
                $policy = $policy.Replace('<PolicyId>B2C_1A_', '<PolicyId>B2C_1A_{0}' -f $prefix)

                # replace other placeholders, e.g. {MyRest} with http://restfunc.com. Note replacement string must be in {}
                if ($null -ne $conf) {
                    $special = @('IdentityExperienceFrameworkAppId', 'ProxyIdentityExperienceFrameworkAppId', 'PolicyPrefix')
                    foreach($memb in Get-Member -InputObject $conf -MemberType NoteProperty) {
                        if ($memb.MemberType -eq 'NoteProperty') {
                            if ($special.Contains($memb.Name)) { continue }
                            $repl = "{{{0}}}" -f $memb.Name
                            $policy = $policy.Replace($repl, $memb.Definition.Split('=')[1])
                        }
                    }
                }

                $policyId = $p.Id.Replace('_1A_', '_1A_{0}' -f $prefix)
                $isOK = $true
                if (-not $generateOnly) {
                    $exists = $true
                    try {
                        Invoke-RestMethod -Uri ("https://graph.microsoft.com/beta/trustFramework/policies/{0}" -f $policyId) -Method Get -Headers $headers| Out-Null
                    } catch {
                        $exists = $false
                    }
                    try {
                        if ($exists) {
                            "Replacing"
                            Invoke-RestMethod -Uri ("https://graph.microsoft.com/beta/trustFramework/policies/{0}/`$value" -f $policyId) -Method Put -Headers $headersXml -Body $policy| Out-Null 
                            #Set-AzureADMSTrustFrameworkPolicy -Content ($policy | Out-String) -Id $policyId | Out-Null
                        } else {
                            "New journey"
                            Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/trustFramework/policies" -Method Post -Headers $headersXml -Body $policy | Out-Null                           
                            #New-AzureADMSTrustFrameworkPolicy -Content ($policy | Out-String) | Out-Null
                        }
                    } catch {
                        $isOk = $false
                        $_
                        if(-Not $exists) {
                            "Use https://b2ciefsetup.azurewebsites.net to ensure the tenant is setup for IEF"
                        }
                        "Ending upload"
                    }
                }

                if ($isOK) {
                    out-file -FilePath $outFile -inputobject $policy
                    Import-Children $p.Id
                }
            }
        }
    }

    if ($sourceDirectory.EndsWith('\')) {
        $sourceDirectory = $sourceDirectory + '*' 
    } else {
        if (-Not $sourceDirectory.EndsWith('\*')) { 
            $sourceDirectory = $sourceDirectory + '\*' 
        }
    }

    if($null -eq $tokens) {
        "Please use Connect-IefPolicies -tenant <name> to login first"
        return
    }
    Refresh_token

    $headers = @{
        'Content-Type' = 'application/json';
        'Authorization' = ("Bearer {0}" -f $tokens.access_token);
    }
    $headersXml = @{
    'Content-Type' = 'application/xml';
    'Authorization' = ("Bearer {0}" -f $tokens.access_token);
    }
    $domains = Invoke-RestMethod -Uri https://graph.microsoft.com/v1.0/domains -Method Get -Headers $headers
    $b2cDomain = $domains.value[0].id
    $b2cName = $b2cDomain.Split('.')[0]
    
    try {
        $resp = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'IdentityExperienceFramework')" -Method Get -Headers $headers
        $iefRes = $resp.value[0]
        $resp = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'ProxyIdentityExperienceFramework')" -Method Get -Headers $headers
        $iefProxy = $resp.value[0]
    } catch {
        "Please ensure your B2C tenant is setup for using IEF (https://aka.ms/b2csetup)"
    }

    # load originals
    $files = Get-Childitem -Path $sourceDirectory -Include *.xml
    $policyList = @()
    foreach($policyFile in $files) {
        $policy = Get-Content $policyFile
        $xml = [xml] $policy
        $policyList= $policyList + @(@{ Id = $xml.TrustFrameworkPolicy.PolicyId; BaseId = $xml.TrustFrameworkPolicy.BasePolicy.PolicyId; Body = $policy; Source= $policyFile.Name; LastWrite = $policyFile.LastWriteTime })
    }
    "Source policies:"
    foreach($p in $policyList) {
        "Id: {0}; Base:{1}" -f $p.Id, $p.BaseId
    }
    if(Test-Path $configurationFilePath){
        $conf = Get-Content -Path $configurationFilePath | Out-String | ConvertFrom-Json
        if ([string]::IsNullOrEmpty($prefix)){ $prefix = $conf.Prefix }
    }

    # now start the upload process making sure you start with the base (base id == null)
    Import-Children($null)
}


function Export-IEFPolicies {
<#
    .SYNOPSIS
    Downloads IEF xml policy files from a B2C tenant

    .DESCRIPTION
    Downloads IEF xml policy files from a B2C tenant optionally selecting only files with specified prefix in their name

    .PARAMETER prefix
    Used to select only certain files for doanload, prefix="V1" will download all IEF files with names starting with "B2C_1A_V1"

    .PARAMETER destinationPath
    Directory where files should be downloaded to

    .EXAMPLE
        PS C:\> Export-IEFPolicies -prefix V10

        Download IEF policies with names starting with 'B2C_1A_V10'

    .NOTES
    Please use connect-iefpolicies -tenant <tanant Name> before executing this command
#>
    [CmdletBinding()]
    param(
        #[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$prefix,

        #[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$destinationPath
    )
    if($null -eq $tokens) {
        "Please use Connect-IefPolicies -tenant <name> to login first"
        return
    }

    Refresh_token

    $headers = @{
        'Content-Type' = 'application/json';
        'Authorization' = ("Bearer {0}" -f $tokens.access_token);
    }
    $headersXml = @{
    'Content-Type' = 'application/xml';
    'Authorization' = ("Bearer {0}" -f $tokens.access_token);
    }
    if ([string]::IsNullOrEmpty($desinationPath)) {
        $destinationPath = ".\"
    }

    if (-Not $destinationPath.EndsWith('\')) {
        $destinationPath = $destinationPath + '\' 
    }

    $prefix = "B2C_1A_" + $prefix
    $policies = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/trustFramework/policies/" -Method Get -Headers $headers
    foreach($policy in $policies.value | Where-Object {($_.id).startsWith($prefix)}) {
        $fileName = "{0}\{1}.xml" -f $destinationPath, $policy.Id
        $policyXml = Invoke-RestMethod -Uri ("https://graph.microsoft.com/beta/trustFramework/policies/{0}/`$value" -f $policy.id) -Method Get -Headers $headersXml
        $policyXml >> $fileName
        #Get-AzureADMSTrustFrameworkPolicy -Id $policy.Id >> $fileName
    }  
}

function Connect-IEFPolicies {
<#
    .SYNOPSIS
    Gets OAuth2 tokens needed to manage IEF Policies

    .DESCRIPTION
    Gets OAuth2 tokens needed to manage IEF Policies

    .PARAMETER tenant
    Tenant name, e.g. mytenant. .onmicrosoft.com is not needed.

    .EXAMPLE
        PS C:\> Connect-IEFPolicies -tenant abctenant

        Authorize to tenant abctenant.onmicrosoft.cvom

    .NOTES
    Nones
#>
    [CmdletBinding()]
    param(
        #[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$tenant
    )
    if ([string]::IsNullOrEmpty($tenant)) {
        $tenantName = "organizations"
    } else {
         if ($tenant.EndsWith(".onmicrosoft.com")) {
            $tenantName = $tenant
        } else {
            $tenantName = "{0}.onmicrosoft.com" -f $tenant
        }
    }
    $hdrs = @{
        'Content-Type' = "application/x-www-form-urlencoded"
    }
    $uri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/devicecode" -f $tenantName
    $body = "client_id=5ca00daf-7851-4276-b857-6b3de7b83f72&scope=user.read Policy.ReadWrite.TrustFramework Application.Read.All Directory.Read.All offline_access"
    $resp = Invoke-Webrequest -Method 'POST' -Uri $uri -Headers $hdrs -Body $body
    $codeResp = $resp.Content | ConvertFrom-Json
    $codeResp.message
    #if(-not (Get-Host).Name.StartsWith('Visual Studio Code Host')) {
    if(-not $env:TERM_PROGRAM -eq 'vscode') {        
        Start-Process "chrome.exe" $codeResp.verification_uri
    }
    for($iter = 1; $iter -le ($codeResp.expires_in / $codeResp.interval); $iter++) {
        Start-Sleep -Seconds $codeResp.interval
        try {
            $uri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $tenantName
            $body = "client_id=5ca00daf-7851-4276-b857-6b3de7b83f72&client_info=1&scope=user.read+offline_access&grant_type=device_code&device_code={0}" -f $codeResp.device_code
            $resp = Invoke-Webrequest -Method 'POST' -Uri $uri -Headers $hdrs -Body $body
            $global:tokens = $resp.Content | ConvertFrom-Json
            $global:token_expiry = (Get-Date).AddSeconds($global:tokens.expires_in)
            "Authorization completed"
            $headers = @{
                'Content-Type' = 'application/json';
                'Authorization' = ("Bearer {0}" -f $tokens.access_token);
            }
            $domains = Invoke-RestMethod -Uri https://graph.microsoft.com/v1.0/domains -Method Get -Headers $headers
            $b2cDomain = $domains.value[0].id
            $b2cName = $b2cDomain.Split('.')[0] 
            "Logged in to {0} tenant." -f $b2cName   
            try {
                $resp = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'IdentityExperienceFramework')" -Method Get -Headers $headers
                $iefRes = $resp.value[0]
                $resp = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'ProxyIdentityExperienceFramework')" -Method Get -Headers $headers
                $iefProxy = $resp.value[0]
                if ($null -eq $iefRes -or
                    $null -eq $iefProxy) {
                    throw
                }
            } catch {
                Write-Host -foreground Red "Your tenant is NOT setup for using IEF. Please visit https://aka.ms/b2csetup to set it up"
                $global:tokens = $null
            }                  
            break
        } catch {
            "Waiting..."
        }
    }
}

    # based on https://gist.github.com/chrisbrownie/f20cb4508975fb7fb5da145d3d38024a
function New-IEFPolicies {
<#
    .SYNOPSIS
    Download a starter pack for B2C StarterPack Git repo

    .DESCRIPTION
    Download a starter pack for B2C StarterPack Git repo. 

    .PARAMETER destinationPath
    Directory to download the files to. Default is current directory.

    .EXAMPLE
        PS C:\> New-IEFPolicies -destinationPath "c:\myPolicies"
    .NOTES
        None
#>
[CmdletBinding()]
param(
    #[Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$destinationPath
)
    $owner = "Azure-Samples"
    $repository = "active-directory-b2c-custom-policy-starterpack"
    if ([string]::IsNullOrEmpty($destinationPath)) {
        $destinationPath = "."
    }
    $path = $null
    while($null -eq $path) {
        $p = (Read-Host -Prompt "Package type: `n[L]ocal accounts only, `n[S] Social/federated only, `n[SL]ocal and social/federated, `n[M]FA social/federated and local with MFA? `n[Q]uit").ToUpper()
        switch($p) {
            "L" { $path = "LocalAccounts" }
            "S" { $path = "SocialAccounts" }
            "SL" { $path = "SocialAndLocalAccounts" }
            "M" { $path = "SocialAndLocalAccountsWithMfa" }
            "Q" { Exit }
        }
    }

    $url = "https://api.github.com/repos/{0}/{1}/contents/{2}" -f $owner, $repository, $path
    $wr = Invoke-WebRequest -Uri $url
    $objects = $wr.Content | ConvertFrom-Json
    $files = $objects | Where-Object {$_.type -eq "file"} | Select-Object -exp download_url
    $directories = $objects | Where-Object {$_.type -eq "dir"}
    
    $directories | ForEach-Object { 
        DownloadFilesFromRepo -Owner $Owner -Repository $Repository -Path $_.path -DestinationPath $($DestinationPath+$_.name)
    }

    
    if (-not (Test-Path $destinationPath)) {
        # Destination path does not exist, let's create it
        try {
            New-Item -Path $destinationPath -ItemType Directory -ErrorAction Stop
        } catch {
            throw "Could not create path '$destinationPath'!"
        }
    }

    $count = 0
    foreach ($file in $files) {
        $fileDestination = Join-Path $destinationPath (Split-Path $file -Leaf)
        try {
            Invoke-WebRequest -Uri $file -OutFile $fileDestination -ErrorAction Stop -Verbose
            "Downloaded '$($file)' to '$fileDestination'"
            ++$count
        } catch {
            throw "Unable to download '$($file.path)'"
        }
    }
    if ($count -gt 0) {
        $destinationPath = '.'
        $fileDestination = Join-Path $destinationPath 'conf.json'
        $conf = @{
            Prefix = "V1" 
            SomeProperty = "Use {SomeProperty} in your xml to have it replaced by this value"
        }
        $conf | ConvertTo-Json | Out-File -FilePath $fileDestination
    }
}

# based on https://gist.github.com/chrisbrownie/f20cb4508975fb7fb5da145d3d38024a
function Add-IEFPoliciesSample {
    <#
        .SYNOPSIS
        Download additional IEF policies from B2C Community samples to add a feature
    
        .DESCRIPTION
        Download additional policies from https://github.com/azure-ad-b2c/samples/tree/master/policies and add to the existing starter pack
    
        .PARAMETER destinationPath
        Directory to download the files to. Default is current directory.
    
        .EXAMPLE
            PS C:\> Add-IEFPoliciesSample -destinationPath "c:\myPolicies"
        .NOTES
            None
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$sampleName,

        [ValidateNotNullOrEmpty()]
        [string]$destinationPath
    )
    $owner = "Azure-Ad-b2c"
    $repository = "samples"
    if ([string]::IsNullOrEmpty($destinationPath)) {
        $destinationPath = "."
    }

    $url = "https://api.github.com/repos/{0}/{1}/contents/policies/" -f $owner, $repository
    $wr = Invoke-WebRequest -Uri $url
    $objects = $wr.Content | ConvertFrom-Json
    $sample = $objects | Where-Object {$_.type -eq "dir" -and $_.name.ToUpper() -eq $sampleName.ToUpper()} | Select-Object -first 1
    if($null -eq $sample) {
        "{0} sample not found. Please check https://github.com/azure-ad-b2c/samples/tree/master/policies for the name of the sample folder" -f $sampleName
        return
    }

    $wr = Invoke-WebRequest -Uri $sample.url
    $objects = $wr.Content | ConvertFrom-Json
    $policies = $objects | Where-Object {$_.type -eq "dir" -and $_.name -eq 'policy'} | Select-Object -first 1
    if($null -eq $policies) {
        "{0} sample does not contain policy folder"
        return
    }

    $wr = Invoke-WebRequest -Uri $policies.url
    $objects = $wr.Content | ConvertFrom-Json
    $files = $objects | Where-Object {$_.type -eq "file"} | Select-Object -exp download_url

    if (-not (Test-Path $destinationPath)) {
        # Destination path does not exist, let's create it
        try {
            New-Item -Path $destinationPath -ItemType Directory -ErrorAction Stop
        } catch {
            throw "Could not create path '$destinationPath'!"
        }
    }

    foreach ($file in $files) {
        $fileDestination = Join-Path $destinationPath (Split-Path $file -Leaf)
        try {
            Invoke-WebRequest -Uri $file -OutFile $fileDestination -ErrorAction Stop -Verbose
        } catch {
            throw "Unable to download '$($file.path)'"
        }
    }
}

function Refresh_token() {
    $limit_time = (Get-Date).AddMinutes(-5)
    if($limit_time -ge $global:token_expiry) {
        $uri = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token" -f $tenantName
        $body = "client_id=5ca00daf-7851-4276-b857-6b3de7b83f72&client_info=1&scope=user.read+offline_access&grant_type=refresh_token&refresh_token={0}" -f $global:tokens.refresh_token
        $resp = Invoke-Webrequest -Method 'POST' -Uri $uri -Headers $hdrs -Body $body
        $global:tokens = $resp.Content | ConvertFrom-Json
        $global:token_expiry = (Get-Date).AddSeconds($global:tokens.expires_in)
        "Token refreshed"
    }
}