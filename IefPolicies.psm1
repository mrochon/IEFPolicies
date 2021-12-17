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
    String injected into names of all uploaded policies

    .PARAMETER generateOnly
    Causes all policies to be updated with conf.json and prefix values and saved into the updatedSourceDirectory without import to B2C
    
    .NOTES
    Please use connect-iefpolicies -tenant <tanant Name> before executing this command
    #>
    [CmdletBinding()]
    param(
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
    function Import-Children($baseId, [bool] $force) {
        foreach($p in $policyList) {
            if ($p.BaseId -eq $baseId) {
                # Skip unchanged files
                #outFile = ""
                if ($updatedSourceDirectory) {
                    if(!(Test-Path -Path $updatedSourceDirectory )){
                        New-Item -ItemType directory -Path $updatedSourceDirectory
                        Write-Host "Updated source folder created"
                    }
                    if (-not $updatedSourceDirectory.EndsWith("\")) {
                        $updatedSourceDirectory = $updatedSourceDirectory + "\"
                    }
                    $envUpdatedDir = '{0}{1}' -f $updatedSourceDirectory, $script:b2cDomain
                    if(!(Test-Path -Path $envUpdatedDir)){
                        New-Item -ItemType directory -Path $envUpdatedDir
                        Write-Host "  Updated source folder created for " + $script:b2cDomain
                    }
                    $outFile = '{0}\{1}' -f $envUpdatedDir, $p.Source
                    if (Test-Path $outFile) {
                        if (($p.LastWrite.Ticks -le (Get-Item $outFile).LastWriteTime.Ticks) -and -not $force) {
                            Write-Host ("{0}: is up to date" -f $p.Id)
                            try {
                                Import-Children $p.Id $false
                            } catch {
                                throw
                            }
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
                    $resp = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/v1.0/organization" -Method Get -Headers $headers
                    $xml.TrustFrameworkPolicy.TenantObjectId = $resp.value[0].Id
                    $policy = $xml.OuterXml
                } catch {
                    # tenantId not used
                    $policy = $p.Body
                }
                $policy = $policy -replace "yourtenant", $script:b2cName 
                $policy = $policy -replace "ProxyIdentityExperienceFrameworkAppId", $iefProxy.appId
                $policy = $policy -replace "IdentityExperienceFrameworkAppId", $iefRes.appId
                $policy = $policy -replace "{tenantId}", $script:tenantId
                $policy = $policy.Replace('PolicyId="B2C_1A_', 'PolicyId="B2C_1A_{0}' -f $prefix)
                $policy = $policy.Replace('/B2C_1A_', '/B2C_1A_{0}' -f $prefix)
                $policy = $policy.Replace('<PolicyId>B2C_1A_', '<PolicyId>B2C_1A_{0}' -f $prefix)

                # replace other placeholders, e.g. {MyRest} with http://restfunc.com. Note replacement string must be in {}
                if ($null -ne $conf) {
                    $special = @('IdentityExperienceFrameworkAppId', 'ProxyIdentityExperienceFrameworkAppId', 'PolicyPrefix', 'tenantId')
                    foreach($memb in Get-Member -InputObject $conf -MemberType NoteProperty) {
                        if ($memb.MemberType -eq 'NoteProperty') {
                            if ($special.Contains($memb.Name)) { 
                                Write-Host ("{0} is a reserved replacement variable. It's value is determined by the signin context." -f $memb.Name)
                                continue 
                            }
                            $repl = "{{{0}}}" -f $memb.Name
                            $policy = $policy.Replace($repl, $memb.Definition.Split('=')[1])
                        }
                    }
                }

                $policyId = $p.Id.Replace('_1A_', '_1A_{0}' -f $prefix)
                if (-not $generateOnly) {
                    $exists = $true
                    try {
                        Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/trustFramework/policies/{0}" -f $policyId) -Method Get -Headers $headers| Out-Null
                    } catch {
                        $exists = $false
                    }
                    try {
                        if ($exists) {
                            Write-Host ("Replacing existing journey")
                            Invoke-WebRequest -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/trustFramework/policies/{0}/`$value" -f $policyId) -Method Put -Headers $headersXml -Body $policy| Out-Null 
                            #Set-AzureADMSTrustFrameworkPolicy -Content ($policy | Out-String) -Id $policyId | Out-Null
                        } else {
                            Write-Host ("New Journey")
                            Invoke-WebRequest -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/trustFramework/policies" -Method Post -Headers $headersXml -Body $policy | Out-Null                           
                            #New-AzureADMSTrustFrameworkPolicy -Content ($policy | Out-String) | Out-Null
                        }
                    } catch {
                        throw
                    }
                }

                out-file -FilePath $outFile -inputobject $policy
                Import-Children $p.Id $true
            }
        }
    }
  
    if(Test-Path $configurationFilePath){
        try {
            $conf = Get-Content -Path $configurationFilePath | Out-String | ConvertFrom-Json
            if (-not $prefix){ $prefix = $conf.Prefix }
            $confDir = Split-Path -Path $configurationFilePath
            $secretsPath = "{0}/secrets.json" -f $confDir
            if(Test-Path $secretsPath) {
                $secrets = Get-Content -Path $secretsPath | Out-String | ConvertFrom-Json
                foreach($memb in Get-Member -InputObject $secrets -MemberType NoteProperty) {
                    Add-Member -InputObject $conf -TypeName $memb.MemberType -NotePropertyName $memb.Name -NotePropertyValue ($memb.Definition.Split('=')[1])
                }
            }
        } catch {
            Write-Error "Failed to parse configuration json file"
        }
    }

    if ($sourceDirectory.EndsWith('\')) {
        $sourceDirectory = $sourceDirectory + '*' 
    } else {
        if (-Not $sourceDirectory.EndsWith('\*')) { 
            $sourceDirectory = $sourceDirectory + '\*' 
        }
    }

    if($null -eq $script:tokens) {
        throw "Please use Connect-IefPolicies -tenant <name> to login first"
        return
    }
    Refresh_token

    $headers = @{
        'Content-Type' = 'application/json';
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
    }
    $headersXml = @{
    'Content-Type' = 'application/xml';
    'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
    }
    
    try {
        $resp = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'IdentityExperienceFramework')" -Method Get -Headers $headers
        $iefRes = $resp.value[0]
        $resp = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'ProxyIdentityExperienceFramework')" -Method Get -Headers $headers
        $iefProxy = $resp.value[0]
    } catch {
        throw "Please ensure your B2C tenant is setup for using IEF (https://aka.ms/b2csetup)"
    }

    # load originals
    $files = Get-Childitem -Path $sourceDirectory -Filter '*.xml'
    $policyList = @()
    foreach($policyFile in $files) {
        $policy = Get-Content $policyFile.FullName
        try {
            $xml = [xml] $policy
            $id = $xml.TrustFrameworkPolicy.PolicyId
            if ($null -eq $id) { continue }
            $policyList= $policyList + @(@{ Id = $id; BaseId = $xml.TrustFrameworkPolicy.BasePolicy.PolicyId; Body = $policy; Source= $policyFile.Name; LastWrite = $policyFile.LastWriteTime })
        } catch {
            Write-Warning ("{0} is not an XML file. Ignored." -f $policyFile)
        }
    }
    Write-Host "Source policies:"
    foreach($p in $policyList) {
        Write-Host ("Id: {0}; Base:{1}" -f $p.Id, $p.BaseId)
    }

    # now start the upload process making sure you start with the base (base id == null)
    try {
        Import-Children $null $false
    } catch {
        throw
    }
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
    if($null -eq $script:tokens) {
        throw "Please use Connect-IefPolicies -tenant <name> to login first"
    }

    Refresh_token

    $headers = @{
        'Content-Type' = 'application/json';
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
    }
    $headersXml = @{
    'Content-Type' = 'application/xml';
    'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
    }
    if (-not $destinationPath) {
        $destinationPath = ".\"
    }

    if (-Not $destinationPath.EndsWith('\')) {
        $destinationPath = $destinationPath + '\' 
    }

    $prefix = "B2C_1A_" + $prefix
    $policies = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/trustFramework/policies/" -Method Get -Headers $headers
    foreach($policy in $policies.value | Where-Object {($_.id).startsWith($prefix)}) {
        $fileName = "{0}\{1}.xml" -f $destinationPath, $policy.Id
        $policyXml = Invoke-WebRequest -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/trustFramework/policies/{0}/`$value" -f $policy.id) -Method Get -Headers $headersXml
        $policyXml.Content >> $fileName
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

    .PARAMETER clientId
    OAuth2 client id; when using non-interactive (application) signin)

    .PARAMETER clientSecret
    OAuth2 client secret; when using non-interactive (application) signin)

    .PARAMETER allowInit
    Requests additional delegated scopes needed to create applications and keysets  

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
        [string]$tenant,
        [ValidateNotNullOrEmpty()]
        [string]$clientId,
        [ValidateNotNullOrEmpty()]
        [string]$clientSecret,
        [ValidateNotNullOrEmpty()]
        [switch]$allowInit
    )
    if (-not $tenant) {
        $script:tenantName = "organizations"
    } else {
         if ($tenant.EndsWith(".onmicrosoft.com")) {
            $script:tenantName = $tenant
        } else {
            $script:tenantName = "{0}.onmicrosoft.com" -f $tenant
        }
    }
    $hdrs = @{
        'Content-Type' = "application/x-www-form-urlencoded"
    }
    if ($clientId) {
        $uri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $script:tenantName
        $body = "client_id={0}&client_secret={1}&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&grant_type=client_credentials" -f $clientId, $clientSecret
        $resp = Invoke-WebRequest -UseBasicParsing  -Method 'POST' -Uri $uri -Headers $hdrs -Body $body
        $script:tokens = $resp.Content | ConvertFrom-Json
        $script:token_expiry = (Get-Date).AddSeconds($script:tokens.expires_in)
        "Authorization completed"
    } else {
        $uri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/devicecode" -f $script:tenantName
        if ($allowInit) {
            $body = "client_id=5ca00daf-7851-4276-b857-6b3de7b83f72&scope=user.read Policy.ReadWrite.TrustFramework TrustFrameworkKeySet.ReadWrite.All Application.ReadWrite.All Directory.Read.All offline_access"
        } else {
            $body = "client_id=5ca00daf-7851-4276-b857-6b3de7b83f72&scope=user.read Policy.ReadWrite.TrustFramework Application.Read.All Directory.Read.All TrustFrameworkKeySet.ReadWrite.All offline_access"
        }
        try {
            $resp = Invoke-WebRequest -UseBasicParsing  -Method 'POST' -Uri $uri -Headers $hdrs -Body $body
        } catch {
            throw
        }
        $codeResp = $resp.Content | ConvertFrom-Json
        $codeResp.message
        #if(-not (Get-Host).Name.StartsWith('Visual Studio Code Host')) {
        if(-not $env:TERM_PROGRAM -eq 'vscode') {        
            Start-Process "chrome.exe" $codeResp.verification_uri
        }
        $completed = $false
        for($iter = 1; $iter -le ($codeResp.expires_in / $codeResp.interval); $iter++) {
            Start-Sleep -Seconds $codeResp.interval
            try {
                $uri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $script:tenantName
                $body = "client_id=5ca00daf-7851-4276-b857-6b3de7b83f72&client_info=1&scope=user.read+offline_access&grant_type=device_code&device_code={0}" -f $codeResp.device_code
                $resp = Invoke-WebRequest -UseBasicParsing  -Method 'POST' -Uri $uri -Headers $hdrs -Body $body
                $completed = $true
                $script:tokens = $resp.Content | ConvertFrom-Json
                $script:token_expiry = (Get-Date).AddSeconds($script:tokens.expires_in)
                Write-Host "Authorization completed"
                $headers = @{
                    'Content-Type' = 'application/json';
                    'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
                }
                $domains = Invoke-RestMethod -UseBasicParsing  -Uri https://graph.microsoft.com/v1.0/domains -Method Get -Headers $headers
                $script:b2cDomain = $domains.value[0].id
                $script:b2cName = $script:b2cDomain.Split('.')[0]
                Write-Host ("Logged in to {0}." -f $script:b2cName)
                try {
                    $resp = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'IdentityExperienceFramework')" -Method Get -Headers $headers
                    $iefRes = $resp.value[0]
                    $resp = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'ProxyIdentityExperienceFramework')" -Method Get -Headers $headers
                    $iefProxy = $resp.value[0]
                    if ($null -eq $iefRes -or
                        $null -eq $iefProxy) {
                        throw
                    }
                } catch {
                    Write-Error "Your tenant is NOT setup for using IEF. Please execute Initialize-IefPolicies to set it up"
                }  

                try {
                    $resp = Invoke-RestMethod -UseBasicParsing -Uri ('https://login.microsoftonline.com/{0}.onmicrosoft.com/v2.0/.well-known/openid-configuration' -f $script:b2cName) -Method Get -Headers $headers
                    $script:tenantId = $resp.token_endpoint.Split('/')[3]
                }  catch {
                    Write-Error "Failed to get tenantid from .well-known"
                }             
                break
            } catch {
                if ($completed) { return }
                Write-Host "Waiting..."
            }
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
    if (-not $destinationPath) {
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
    $wr = Invoke-WebRequest -UseBasicParsing  -Uri $url 
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
            Invoke-WebRequest -UseBasicParsing  -Uri $file -OutFile $fileDestination -ErrorAction Stop -Verbose
            "Downloaded '$($file)' to '$fileDestination'"
            ++$count
        } catch {
            throw "Unable to download '$($file.path)'"
        }
    }
    if ($count -gt 0) {
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
    
        .PARAMETER owner
        Git repo owner name. Default 'Azure-Ad-B2C'.
    
        .PARAMETER repository
        Git repo folder name. default 'samples'.

        .EXAMPLE
            PS C:\> Add-IEFPoliciesSample mfa-email-or-phone
            Add 'https://github.com/azure-ad-b2c/samples/tree/master/policies/mfa-email-or-phone' sample.

        .NOTES
            Git repo names are case sensitive, e.g. 'samples' is not the same as 'Samples'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$sampleName,

        [ValidateNotNullOrEmpty()]
        [string]$destinationPath,

        [ValidateNotNullOrEmpty()]
        [string]$owner,

        [ValidateNotNullOrEmpty()]
        [string]$repository
    )
    if (-not $owner) {
        $owner = "Azure-Ad-b2c"
        $repository = "samples"
    }
    if (-not $destinationPath) {
        $destinationPath = "."
    }
    foreach($p in @("Policies","policies")) {
        try {
            $url = "https://api.github.com/repos/{0}/{1}/contents/{2}/" -f $owner, $repository, $p
            $wr = Invoke-WebRequest -UseBasicParsing  -Uri $url
            break
        } catch {
        }
    }

    $objects = $wr.Content | ConvertFrom-Json
    $sample = $objects | Where-Object {$_.type -eq "dir" -and $_.name.ToUpper() -eq $sampleName.ToUpper()} | Select-Object -first 1
    if($null -eq $sample) {
        throw "{0} sample not found. Please check https://github.com/azure-ad-b2c/samples/tree/master/policies for the name of the sample folder" -f $sampleName
    }

    $wr = Invoke-WebRequest -UseBasicParsing  -Uri $sample.url
    $objects = $wr.Content | ConvertFrom-Json
    $policies = $objects | Where-Object {$_.type -eq "dir" -and $_.name -eq 'policy'} | Select-Object -first 1
    if($null -eq $policies) {
        throw "{0} sample does not contain policy folder" -f $sample.url
    }

    if (-not (Test-Path $destinationPath)) {
        # Destination path does not exist, let's create it
        try {
            New-Item -Path $destinationPath -ItemType Directory -ErrorAction Stop
        } catch {
            throw "Could not create path '$destinationPath'!"
        }
    }

    $wr = Invoke-WebRequest -UseBasicParsing  -Uri $policies.url
    $objects = $wr.Content | ConvertFrom-Json
    $files = $objects | Where-Object {($_.type -eq "file") -and ($_.name.EndsWith('.xml'))} | Select-Object -exp download_url
    foreach ($file in $files) {
        $fileDestination = Join-Path $destinationPath (Split-Path $file -Leaf)
        try {
            Invoke-WebRequest -UseBasicParsing  -Uri $file -OutFile $fileDestination -ErrorAction Stop -Verbose
            Write-Host ("Downloaded {0}" -f $fileDestination)
        } catch {
            throw "Unable to download '$($file.path)'"
        }
    }

    # Is there a conf.json in the sample we need to merge?
    $sampleConfPath = $objects | Where-Object {($_.type -eq "file") -and ($_.name.EndsWith('.json'))} | Select-Object -first 1 -exp download_url
    if ($null -ne $sampleConfPath) {
        $confPath = Join-Path $destinationPath ("{0}.conf.json" -f $sampleName)
        Invoke-WebRequest -UseBasicParsing  -Uri $sampleConfPath -OutFile $confPath
        Write-Host ("Downloaded {0}" -f $confPath)        
    }
}
function Remove-IEFPolicies {
    <#
        .SYNOPSIS
        Delete policies from B2C
    
        .DESCRIPTION
        Deletes IEF xml policy files from a B2C tenant with the specified prefix in their name
    
        .PARAMETER prefix
        Used to select only certain files for delete, prefix="V1" will delete all IEF policies with names starting with "B2C_1A_V1"

        .EXAMPLE
            PS C:\> Delete-IEFPolicies -prefix V10
    
            Delete IEF policies with names starting with 'B2C_1A_V10'
    
        .NOTES
        Please use connect-iefpolicies -tenant <tanant Name> before executing this command
    #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$prefix
        )
        if($null -eq $script:tokens) {
            throw "Please use Connect-IefPolicies -tenant <name> to login first"
        }
        Refresh_token
        $headers = @{
            'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
        }
        $prefix = "B2C_1A_" + $prefix
        $policies = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/trustFramework/policies/" -Method Get -Headers $headers
        Write-Host "The following policies wil be deleted."
        foreach($policy in $policies.value | Where-Object {($_.id).startsWith($prefix)}) {
            Write-Host $policy.Id
        }  
        $resp = (Read-Host -Prompt "Enter 'yes' to confirm").ToUpper()
        try {
            if ("YES" -eq $resp) {
                foreach($policy in $policies.value | Where-Object {($_.id).startsWith($prefix)}) {
                    $url = "https://graph.microsoft.com/beta/trustFramework/policies/{0}" -f $policy.Id
                    $resp = Invoke-WebRequest -UseBasicParsing  -Method 'DELETE' -Uri $url -Headers $headers -ErrorAction Stop
                    if (204 -eq $resp.StatusCode) {
                        Write-Host ("Deleted: {0}" -f $policy.Id)
                    } else {
                        Write-Error $resp
                    }
                }              
            } else {
                Write-Host "Delete cancelled."
            }
        } catch {
            Write-Error $Error[0]
        }
    }
  
function Initialize-IefPolicies() {
    <#
        .SYNOPSIS
        Setup or verify setup fo b2C for IEF policy deployment (https://docs.microsoft.com/en-us/azure/active-directory-b2c/tutorial-create-user-flows?pivots=b2c-custom-policy&tabs=applications)
    
        .DESCRIPTION
        1. Creates IdentityExperienceFramework and ProxyuidentityFramework applications (if not already there)
        2. Creates TokenSigning- and TokenEncryption-Containers
        3. Creates a fake FB key unless one already there (to simplify use of social authentication starter packs, which all reference FB)
        4. Provides url for establishing proxy to resource consent
    
        .PARAMETER validateOnly
        Checks for above but does not create any new artifacts

        .EXAMPLE
            PS C:\> Initialize-IEFPolicies 
       
        .NOTES
        Please use connect-iefpolicies -tenant <tanant Name> -allowInit before executing this command
    #>
        [CmdletBinding()]
        param(
            [ValidateNotNullOrEmpty()]
            [switch]$validateOnly
        )
    if (-not $script:tokens.scope.Split(' ').Contains("Application.ReadWrite.All")) {
        Write-Error "Please signin agin for elevated privileges: Connect-IefPolicies -Tenant <tenantname> -allowInit"
        throw
    }
    $iefAppName = "IdentityExperienceFramework"
    $iefProxyAppName = "ProxyIdentityExperienceFramework"
    $iefApp = Get-Application $iefAppname
    $iefProxyApp = Get-Application $iefProxyAppName
    $ok = $true
    if ($validateOnly) {
        Write-Host "Validation only"
        if ($null -eq $iefApp) {
            Write-Warning ("{0} application is NOT defined" -f $iefAppName)
            $ok = $false
        } else {
            Write-Host ("{0} application is defined" -f $iefAppName)
        }
        if ($null -eq $iefProxyApp) {
            Write-Warning ("{0} application is NOT defined" -f $iefProxyAppName)
            $ok = $false
        } else {
            Write-Host ("{0} application is defined" -f $iefProxyAppName)
        }
        if($ok) {
            Write-Host "To grant/confirm application consent execute the following url: "
            Write-Host ("https://login.microsoftonline.com/{0}/adminconsent?client_id={1}" -f $script:tenantId, $iefProxyApp.appId)            
        }
        return
    } else {
        if(($null -ne $iefApp) -or ($null -ne $iefProxyApp)) {
            Write-Warning "IdentityExperienceFramework and/or ProxyidentityexperienceFramework apps already exist."
            Write-Warning "Please delete them first if you do want to re-initialize your B2C tenant anyway."
            return
        }
        try {
            $iefApp = New-Application $iefAppName
            Write-Host ("{0} created" -f $iefAppName)
            $iefProxyApp = New-Application $iefProxyAppName $iefApp
            Write-Host ("{0} created" -f $iefProxyAppName)

            New-IefPoliciesKey "TokenSigningKeyContainer" "sig"
            New-IefPoliciesKey "TokenEncryptionKeyContainer" "enc"
            New-IefPoliciesKey "FacebookSecret" "sig"
            Write-Host "Please wait for the setup to complete..."        
            Start-Sleep -Seconds 30
        } catch {
            Write-Error "Initialize failed"
            throw
        }
    }
    if($ok) {
        Write-Host "Please complete admin consent using the following link:"           
        Write-Host ("https://login.microsoftonline.com/{0}/adminconsent?client_id={1}" -f $script:tenantId, $iefProxyApp.appId)    
    }
}

function New-IefPoliciesCert {
    <#
        .SYNOPSIS
        Create a new, self-signed signing cert in B2C PolicyKeys
    
        .DESCRIPTION
        Creates a new self-signed certificte, uploads it (public and private keys) to B2C PolicyKeys.
        The CN name of the certificate will be <keyName>.<tenant domain name>
        An existing keyset with same will not be deleted. The new key will be added.
    
        .PARAMETER validateOnly
        Checks for above but does not create any new artifacts

        .EXAMPLE
            PS C:\> New-IEFPoliciesCert RESTAuth
       
        .NOTES
        You must use connect-iefpolicies -tenant <tanant Name> before executing this command
    #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]            
            [ValidateNotNullOrEmpty()]
            [string]$keyName,

            [ValidateNotNullOrEmpty()]
            [int]$validityMonths = 12,    
            
            [ValidateNotNullOrEmpty()]
            [int]$startValidInMonths = 0             
        )
        Refresh_token
        $headers = @{
            'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
            'Content-Type' = "application/json";        
        }
        $certSubject = ("CN={0}.{1}" -f $keyName, $script:b2cDomain)
        Write-Host ("Creating X509 cert {0}" -f $certSubject)
        $cert = New-SelfSignedCertificate `
            -KeyExportPolicy Exportable `
            -Subject ($certSubject) `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -KeyUsage DigitalSignature `
            -NotBefore (Get-Date).AddMonths($startValidInMonth) `
            -NotAfter (Get-Date).AddMonths($startValidInMonth+12) `
            -CertStoreLocation "Cert:\CurrentUser\My"
        [string]$pfxPwdPlain = Get-Random
        $pfxPwd = ConvertTo-SecureString -String $pfxPwdPlain -Force -AsPlainText
        $pfxPath = ".\RESTClientCert.pfx"
        $cert | Export-PfxCertificate -FilePath $pfxPath -Password $pfxPwd
        $pkcs12=[Convert]::ToBase64String([System.IO.File]::ReadAllBytes((get-childitem -path $pfxPath).FullName))
        #try {
        #    $key = Invoke-RestMethod -Uri ("https://graph.microsoft.com/beta/trustFramework/keySets/{0}" -f $keyName) -Method Delete -Headers $headers
        #} catch { 
        #    # ok if does not exist
        #}
        $body = @{
            id = $keyName
        }
        try {
            $keyset = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/trustFramework/keySets" -Method Post -Headers $headers -Body (ConvertTo-Json $body) -SkipHttpErrorCheck
            if(($null -ne $keyset.error) -and ($keyset.error.code -eq 'AADB2C95028')) {
                Write-Host "Adding cert to existing keyset"
                $keySetId = "B2C_1A_{0}" -f $keyName
            } else {
                Write-Host ("Keyset {0} created"  -f $keySetid)              
                $keySetId = $keyset.id
            }
            $url = ("https://graph.microsoft.com/beta/trustFramework/keySets/{0}/uploadPkcs12" -f $keySetId)
            $body = @{
                key = $pkcs12
                password = $pfxPwdPlain
            }
            $key = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body (ConvertTo-Json $body)
            Write-Host ("Certificate created and uploaded" -f $certSubject)
        } catch {
            Write-Error "Failed " +  $Error[0]
        }
}

function Get-IefPoliciesAADCommon() {
    <#
        .SYNOPSIS
        Get b2C extensions app app and object ids
    
        .DESCRIPTION
        Get b2C extensions app app and object ids

        .EXAMPLE
            PS C:\> Get-IEFPoliciesAADCommon
       
        .NOTES
        Please use connect-iefpolicies -tenant <tanant Name> -allowInit before executing this command
    #>
    $app = Get-Application "b2c-extensions-app. Do not modify. Used by AADB2C for storing user data."
    Write-Host "Configuration settings:"
    Write-Host ('"ExtAppId": "{0}",' -f $app.appId)
    Write-Host ('"ExtObjectId": "{0}"' -f $app.id)
    Write-Host
    Write-Host "Add this ClaimsProvider to your extensions file"
    Write-Host '<ClaimsProvider>
    <DisplayName>Azure Active Directory</DisplayName>
    <TechnicalProfiles>
        <TechnicalProfile Id="AAD-Common">
            <DisplayName>Azure Active Directory</DisplayName>
            <Metadata>
                <Item Key="ApplicationObjectId">{ExtObjectId}</Item>
                <Item Key="ClientId">{ExtAppId}</Item>
            </Metadata>
        </TechnicalProfile>
    </TechnicalProfiles>			
</ClaimsProvider>'
}

function New-Application {
    Param(
        [Parameter(Mandatory)]
        [string] $AppName,
        $API
    )
    Refresh_token
    $headers = @{
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
        'Content-Type' = "application/json";        
    }
    $app = Get-Application $AppName
    if ($null -ne $app) { return }
    $OIDCAccess = @{
        resourceAppId = "00000003-0000-0000-c000-000000000000";
        resourceAccess = @(
            @{
                id = "37f7f235-527c-4136-accd-4a02d197296e";
                type = "Scope"
            },
            @{
                id = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182";
                type = "Scope";
            }
        )
    } 

    if ($null -eq $API) {
        $body = @{
            displayName = $AppName;
            signInAudience = "AzureADMyOrg";
            requiredResourceAccess = @( $OIDCAccess );
        }  
        try {
            $app = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/v1.0/applications" -Method POST -Headers $headers -Body ($body | ConvertTo-Json -Depth 6)
        } catch {
            throw
        }
        $apiProps = @{
            identifierUris = @(("https://{0}/{1}" -f $script:b2cDomain, $app.appId));
            web = @{
                redirectUris = @( ("https://{0}.b2clogin.com/{1}" -f $script:b2cName, $script:b2cDomain))
            };
            api = @{
                oauth2PermissionScopes = @(
                    @{
                        adminConsentDescription = ("Allow the application to access {0} on behalf of the signed-in user." -f $AppName);
                        adminConsentDisplayName = ("Access {0}" -f $AppName);
                        id = [guid]::NewGuid();
                        isEnabled = $true;
                        type = "Admin";
                        value = "user_impersonation";
                    }
                )
            }
        }
        try {
            $resp = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/v1.0/applications/{0}" -f $app.id) -Method PATCH -Headers $headers -Body ($apiProps | ConvertTo-Json -Depth 6)
            $app.identifierUris = $apiProps.identifierUris
            $app.web = $apiProps.web
            $app.api = $apiProps.api
        } catch {
            throw
        }
    } else {
        $body = @{
            displayName = $AppName;
            signInAudience = "AzureADMyOrg";
            publicClient = @{ redirectUris = @( "myapp://auth" ) };
            isFallbackPublicClient = $true;
            requiredResourceAccess = @(
                @{
                    resourceAppId = $API.appId;
                    resourceAccess = @(
                        @{
                            id = $API.api.oauth2PermissionScopes[0].id;
                            type = "Scope";
                        }
                    )
                },
                $OIDCAccess
            )
        }
        try {
            $app = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/v1.0/applications" -Method POST -Headers $headers -Body ($body | ConvertTo-Json -Depth 6)
        } catch {
            throw
        }
    }
    $sp = @{ appId = $app.appId; displayName = $Appname }
    $resp = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals" -f $app.id) -Method POST -Headers $headers -Body ($sp | ConvertTo-Json -Depth 6)
    return $app
}

function Get-Application {
    Param(
        [Parameter(Mandatory)]
        [string] $AppName
    )
    Refresh_token
    $headers = @{
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
    }
    try {
        $resp = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '{0}'" -f $AppName) -Method Get -Headers $headers
        $app = $resp.value[0]
        return $app;
    } catch {
        return $null
    }
}
function New-IEFPoliciesKey {
    <#
    .SYNOPSIS
    Creates a B2C policy key
    
    .DESCRIPTION
    Creates a b2C policy key
    
    .PARAMETER name
    Key name
    
    .PARAMETER purpose
    Key purpose (sig or enc)

    .NOTES
    Please use connect-iefpolicies -tenant <tanant Name> before executing this command
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$name,

        [ValidateNotNullOrEmpty()]
        [string]$purpose = "sig")

    Refresh_token
    $headers = @{
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
        'Content-Type' = "application/json";        
    }
    try {
        $keyset = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/trustFramework/keySets/B2C_1A_{0}" -f $name) -Method GET -Headers $headers
    } catch {
        try {
            $keyset = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/trustFramework/keySets" -Method POST -Headers $headers -Body (@{ id = $name} | ConvertTo-Json)
            $keyset = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/trustFramework/keySets/{0}/generateKey" -f $keyset.id) -Method POST -Headers $headers -Body (@{ use = $purpose; kty = "RSA" } | ConvertTo-Json)
            Write-Host ("{0} generated" -f $name)
        } catch {
            throw
        }
    }
}
function Refresh_token() {
    $limit_time = (Get-Date).AddMinutes(-5)
    if($limit_time -ge $script:token_expiry) {
        if (-not $script:tokens.refresh_token) {
            throw "No refresh token. Please re-authenticate"
        }        
        $uri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $script:tenantName
        $body = "client_id=5ca00daf-7851-4276-b857-6b3de7b83f72&client_info=1&scope=user.read+offline_access&grant_type=refresh_token&refresh_token={0}" -f $script:tokens.refresh_token
        $resp = Invoke-WebRequest -UseBasicParsing  -Method 'POST' -Uri $uri -Headers $hdrs -Body $body
        $script:tokens = $resp.Content | ConvertFrom-Json
        $script:token_expiry = (Get-Date).AddSeconds($script:tokens.expires_in)
        Write-Host "Token refreshed"
    }
}
