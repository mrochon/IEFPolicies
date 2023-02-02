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
        [string]$updatedSourceDirectory = '.\debug\',

        [ValidateNotNullOrEmpty()]
        [string]$configurationFilePath,

        [ValidateNotNullOrEmpty()]
        [string]$prefix,

        [ValidateNotNullOrEmpty()]
        [switch]$generateOnly,

        [ValidateNotNullOrEmpty()]
        [switch]$noPrefix        

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
                        $lastFileUpdate = (Get-Item $outFile).LastWriteTime.Ticks
                        if (($p.LastWrite.Ticks -lt $lastFileUpdate) -and ($lastConfChange -lt $lastFileUpdate) -and -not $force) {
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
                if($noPrefix) {
                    $policyId = $p.Id
                } else {
                    $policyId = $p.Id.Replace('_1A_', '_1A_{0}' -f $prefix)
                }
                $msg = "Uploading $($p.Id) as $($policyId)"
                Write-Host $msg  -ForegroundColor Green 
                # Replace tenant id but only if already there. It messes up xml formatting
                $xml = [xml] $p.Body
                #$xml.PreserveWhitespace = $true
                # https://github.com/mrochon/IEFPolicies/issues/43
                if ($xml.TrustFrameworkPolicy.TenantObjectId) {
                    $resp = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/v1.0/organization" -Method Get -Headers $headers
                    $xml.TrustFrameworkPolicy.TenantObjectId = $resp.value[0].Id
                    $policy = $xml.OuterXml
                }
                else {
                    $policy = $p.Body
                }
                $policy = $policy -replace "yourtenant", $script:b2cName 
                $policy = $policy -replace "ProxyIdentityExperienceFrameworkAppId", $iefProxy.appId
                $policy = $policy -replace "IdentityExperienceFrameworkAppId", $iefRes.appId
                $policy = $policy -replace "{tenantId}", $script:tenantId
                $policy = $policy -replace "{ExtAppId}", $extApp.appId     
                $policy = $policy -replace "{ExtObjectId}", $extApp.id 
                if(-not $noPrefix) {                                        
                    $policy = $policy.Replace('PolicyId="B2C_1A_', 'PolicyId="B2C_1A_{0}' -f $prefix)
                    $policy = $policy.Replace('/B2C_1A_', '/B2C_1A_{0}' -f $prefix)
                    $policy = $policy.Replace('<PolicyId>B2C_1A_', '<PolicyId>B2C_1A_{0}' -f $prefix)
                }

                # replace other placeholders, e.g. {MyRest} with http://restfunc.com. Note replacement string must be in {}
                foreach($memb in $confProperties.GetEnumerator()) {
                    $repl = "{{{0}}}" -f $memb.Name
                    $policy = $policy.Replace($repl, $memb.Value)
                }

                if (-not $generateOnly) {
                    $resp = Invoke-WebRequest -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/trustFramework/policies/{0}/`$value" -f $policyId) -Method Put -Headers $headersXml -ContentType 'application/xml; charset=utf-8' -Body $policy -SkipHttpErrorCheck
                    if ($resp.StatusCode -eq 201) {
                        Write-Host "Created"
                    } elseif ($resp.StatusCode -eq 200) {
                        Write-Host "Updated"
                    } else {
                        Write-Error $resp.Content
                        throw
                    }
                }

                out-file -FilePath $outFile -inputobject $policy
                try {
                    Import-Children $p.Id $true
                } catch {
                    throw
                }
            }
        }
    }
    function Format-Config([string]$prefix, [PSObject]$parent) {
        foreach($p in Get-Member -InputObject $parent -MemberType NoteProperty) {
            $v = $parent | Select-Object -ExpandProperty $p.Name
            if($prefix) {
                $fullName = ("{0}:{1}" -f $prefix, $p.Name)
            } else {
                $fullName = $p.Name
            }
            if($v.GetType().Name -eq 'String') {
                $confProperties.Add($fullName, $v )
            } else {
                Format-Config $fullName $v
            }
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
    'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
    }

    if ([string]::IsNullOrEmpty($configurationFilePath)) {
        $configurationFilePath = (".\{0}.json" -f $script:b2cName)
        if(-not(Test-Path $configurationFilePath)){
            $configurationFilePath = ".\conf.json"
        }
    }
    Write-Host ("Configuration file: {0}" -f $configurationFilePath)

    $confProperties = @{}
    if(Test-Path $configurationFilePath){
        try {
            $lastConfChange = (Get-Item $configurationFilePath).LastWriteTime.Ticks
            $conf = Get-Content -Path $configurationFilePath | Out-String | ConvertFrom-Json
            if (-not $prefix -and $conf.Prefix) { 
                $prefix = $conf.Prefix 
            } else {
                $prefix = ""
            }
            Format-Config $null $conf
            $confDir = Split-Path -Path $configurationFilePath
            $secretsPath = "{0}/secrets.json" -f $confDir
            if(Test-Path $secretsPath) {
                $lastWrite = (Get-Item $secretsPath).LastWriteTime.Ticks
                if($lastWrite -gt $lastConfChange) {
                    $lastConfChange = $lastwrite
                }
                $secrets = Get-Content -Path $secretsPath | Out-String | ConvertFrom-Json
                Format-Config $null $secrets
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

    try {
        $resp = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'IdentityExperienceFramework')" -Method Get -Headers $headers
        $iefRes = $resp.value[0]
        $resp = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'ProxyIdentityExperienceFramework')" -Method Get -Headers $headers
        $iefProxy = $resp.value[0]
    } catch {
        throw "Please ensure your B2C tenant is setup for using IEF (https://aka.ms/b2csetup)"
    }
    $extApp = Get-Application "b2c-extensions-app. Do not modify. Used by AADB2C for storing user data."
    Write-Host 

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
    Used to select only certain files for doanload, prefix="V1_" will download all IEF files with names starting with "B2C_1A_V1_"

    .PARAMETER destinationPath
    Directory where files should be downloaded to

    .PARAMETER clean
    Remove tenant specific values from the xml, replace with placeholders import-iefpolicies understands

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
        [string]$destinationPath,
        [ValidateNotNullOrEmpty()]
        [switch]$clean
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
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
    }
    if (-not $destinationPath) {
        $destinationPath = ".\"
    }

    if (-Not $destinationPath.EndsWith('\')) {
        $destinationPath = $destinationPath + '\' 
    }

    $origPrefix = $prefix
    $prefix = "B2C_1A_" + $prefix
    $policies = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/trustFramework/policies/" -Method Get -Headers $headers
    foreach($policy in $policies.value | Where-Object {($_.id).startsWith($prefix)}) {
        $policyXml = Invoke-WebRequest -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/trustFramework/policies/{0}/`$value" -f $policy.id) -Method Get -Headers $headersXml
        $content = $policyXml.Content
        if($clean) {
            $content = $content.Replace($script:b2cName, "yourtenant")
            $content = $content.Replace($prefix, "B2C_1A_")
            $iefAppName = "IdentityExperienceFramework"
            $iefProxyAppName = "ProxyIdentityExperienceFramework"
            $extApp = Get-Application "b2c-extensions-app. Do not modify. Used by AADB2C for storing user data."
            $iefApp = Get-Application $iefAppname
            $iefProxyApp = Get-Application $iefProxyAppName         
            $content = $content.Replace($iefApp.appId, ("{0}AppId" -f $iefAppName))         
            $content = $content.Replace($iefProxyApp.appId, ("{0}AppId" -f $iefProxyAppName))   
            $content = $content.Replace($extApp.id, "{ExtObjectId}")  
            $content = $content.Replace($extApp.appId, "{ExtAppId}")  
            $conf = @{
                Prefix = $origPrefix
                SomeProperty = "Use {SomeProperty} in your xml to have it replaced by this value"
            }
            $conf | ConvertTo-Json | Out-File -FilePath ($destinationPath + "conf.json")                          
        }
        $fileName = "{0}\{1}.xml" -f $destinationPath, $policy.Id
        $fileName = $fileName.Replace($prefix, "B2C_1A_")
        $content >> $fileName
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
        [string]$clientSecret
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
        $resp = Invoke-RestMethod -UseBasicParsing  -Method 'POST' -Uri $uri -Headers $hdrs -Body $body -SkipHttpErrorCheck -StatusCodeVariable statusCode
        if (200 -eq $statusCode) {
            setupEnvironment $resp
        } else {
            Write-Error $resp
            throw
        }
    } else {
        $uri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/devicecode" -f $script:tenantName
        $body = "client_id=5ca00daf-7851-4276-b857-6b3de7b83f72&scope=User.Read Directory.AccessAsUser.All Policy.ReadWrite.TrustFramework TrustFrameworkKeySet.ReadWrite.All offline_access"
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
            
            # If the previous command does not exit successfully, print the verification URL in the window for the user to manually navigate to. 
            if (!$?) {
                Write-Warning "Chrome is not installed on this machine. Please navigate to the following URL for verification: {0}" -f $codeResp.verification_uri
            }
        }

        $uri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $script:tenantName
        $body = "client_id=5ca00daf-7851-4276-b857-6b3de7b83f72&client_info=1&scope=user.read+offline_access&grant_type=device_code&device_code={0}" -f $codeResp.device_code
        for($iter = 1; $iter -le ($codeResp.expires_in / $codeResp.interval); $iter++) {
            Start-Sleep -Seconds $codeResp.interval
            $resp = Invoke-RestMethod -UseBasicParsing  -Method 'POST' -Uri $uri -Headers $hdrs -Body $body -SkipHttpErrorCheck -StatusCodeVariable statusCode
            if (200 -eq $statusCode) {
                Write-Host "Got 200"
                setupEnvironment $resp
                break
            }
            Write-Host "Waiting..."
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
    [string]$destinationPath,

    [switch]$DisplayControls   
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
    if($DisplayControls) {
        $path = "Display%20Controls%20Starterpack/" + $path
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
        $fileName = Split-Path $file -Leaf
        $fileDestination = Join-Path $destinationPath $fileName
        try {
            if("TrustFrameworkExtensions.xml" -eq $fileName) {
                $ext = Invoke-RestMethod  -Uri $file -UseBasicParsing
                # Seems like there is an extra character at start
                $xml = [xml] $ext.Substring(1)
                $AADCommon = [xml](Get-Content "$PSScriptRoot\strings\AADCommon.xml")
                $node = $xml.TrustFrameworkPolicy.ClaimsProviders.OwnerDocument.ImportNode(($AADCommon).DocumentElement, $true)
                $xml.TrustFrameworkPolicy.ClaimsProviders.AppendChild($node)
                $dest = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($fileDestination)
                # Save does not understand relative path
                #$xml.PreserveWhitespace = $true
                $xml.Save($dest)
                Write-Warning "Added AAD-Common extensions app settings to TrustFrameworkExtensions.xml"
            } else {
                Invoke-WebRequest -UseBasicParsing  -Uri $file -OutFile $fileDestination -ErrorAction Stop -Verbose
            }
            if("TrustFrameworkBase.xml" -eq $fileName) {
                (Get-ChildItem $fileDestination).Set_IsReadOnly($True)
            }
            Write-Host "Downloaded '$($file)' to '$fileDestination'"
            ++$count
        } catch {
            throw ("Unable to download {0}: {1}" -f $file.path, $_)
        }
    }
    if ($count -gt 0) {
        if($script:b2cName) {
            $fileDestination = Join-Path $destinationPath "$($script:b2cName).json"   
        } else {
            $fileDestination = Join-Path $destinationPath 'conf.json'
        }
        $conf = @{
            Prefix = "V1_" 
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
        Used to select only certain files for delete, prefix="V1_" will delete all IEF policies with names starting with "B2C_1A_V1_"

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
        $delPolicies = $policies.value | Where-Object {($_.id).startsWith($prefix)}
        if($delPolicies.Count -eq 0) {
            Write-Warning ("No policies with prefix: {0} were found in this {1}" -f $prefix, $script:b2cDomain)
        } else {        
            Write-Host "The following policies wil be deleted."
            foreach($policy in $delPolicies) {
                Write-Host $policy.Id
            }  
            $resp = (Read-Host -Prompt "Enter 'yes' to confirm").ToUpper()
            try {
                if ("YES" -eq $resp) {
                    foreach($policy in $delPolicies) {
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
        None
    #>
        [CmdletBinding()]
        param(
            [ValidateNotNullOrEmpty()]
            [switch]$validateOnly
        )

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

        .PARAMETER keyName
        Used to name the certificate name (CN=keyname.yourtenant.onmicrosoft.com) and the policy container (B2C_1A_keyname)

        .PARAMETER validityMonths
        Cert validity in month (from start of validity - see below)

        .PARAMETER startValidInMonths
        Used to name the certificate name (CN=keyname.yourtenant.onmicrosoft.com) and the policy container (B2C_1A_keyname)
    
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
        try {
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
            $base64Cert = $([Convert]::ToBase64String($cert.Export('Cert'), [System.Base64FormattingOptions]::InsertLineBreaks))
            Set-Content -Path ".\ClientCert.cer" -Value $base64Cert
            Write-Host "ClientCert.cer file created"
        } catch {
            Write-Error "Error creating/writing or reading an X509 certificate."
            Write-Error ("Please create it using other tools and store in B2C Policy Key storage with container name: {0}" -f $keyName)
            return
        }
        $body = @{
            id = $keyName
        }
        $keyset = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/trustFramework/keySets" -Method Post -Headers $headers -Body (ConvertTo-Json $body) -SkipHttpErrorCheck -StatusCodeVariable httpStatus
        if (403 -eq $httpStatus) {
            Write-Error $keyset.error
            throw
        }
        if(($null -ne $keyset.error) -and ($keyset.error.code -eq 'AADB2C95028')) {
            Write-Host "Adding cert to an existing keyset"
            $keySetId = "B2C_1A_{0}" -f $keyName
        } else {
            Write-Host ("Keyset {0} created" -f $keySetid)              
            $keySetId = $keyset.id
        }
        $url = ("https://graph.microsoft.com/beta/trustFramework/keySets/{0}/uploadPkcs12" -f $keySetId)
        $body = @{
            key = $pkcs12
            password = $pfxPwdPlain
        }
        Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body (ConvertTo-Json $body) -SkipHttpErrorCheck -StatusCodeVariable httpStatus
        Write-Host ("Certificate created and uploaded" -f $certSubject)
        Write-Host ("Thumbprint: {0}" -f $cert.Thumbprint)

        Remove-Item $pfxPath
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
        None
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

function New-IefPoliciesPrincipal {
    <#
        .SYNOPSIS
        Register a Graph client with permissions required by IefPolicies
    
        .DESCRIPTION
        Registers an application in the b2C tenant for use in un-attended (CI/CD) use of Import-IefPolicies and
        other IEFPolicies functions.

        .PARAMETER name
        Application name

        .EXAMPLE
            PS C:\> New-IEFPoliciesPrincipal myClient
       
        .NOTES
        You must use connect-iefpolicies -tenant <tanant Name> before executing this command
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]            
        [ValidateNotNullOrEmpty()]
        [string]$name
    )
    Refresh_token
    $headers = @{
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
        'Content-Type' = "application/json";        
    }
    Write-Debug ("New-IefPoliciesPrincipal {0}" -f $name)
    $app = Get-Application $ame
    if ($null -ne $app) { 
        Write-Error ("App {0} exists already." -f $name)
        return $app 
    }

    # openid perms
    $permissions = @{
        resourceAppId  = "00000003-0000-0000-c000-000000000000";
        resourceAccess = @(
            @{
                id = "498476ce-e0fe-48b0-b801-37ba7e2685c6";
                type = "Role"
            },
            @{
                id = "4a771c9a-1cf2-4609-b88e-3d3e02d539cd";
                type = "Role"
            },
            @{
                id = "79a677f7-b79d-40d0-a36a-3e6f8688dd7a";
                type = "Role"
            },
            @{
                id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30";
                type = "Role"
            },
            @{
                id = "dbb9058a-0e50-45d7-ae91-66909b5d4664";
                type = "Role"
            }
        )
    } 
    $body = @{
        displayName = $name;
        signInAudience = "AzureADSingleOrg";
        requiredResourceAccess = @( $permissions );
    }  
    try {
        $app = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/v1.0/applications" -Method POST -Headers $headers -Body ($body | ConvertTo-Json -Depth 6)
    } catch {
        Write-Error $_.ErrorDetails.Message
        throw
    }
    # Create secret
    $parms = @{ passwordCredential = @{ displayName = "Created by New-IefPoliciesPrincipal" } }
    $secret = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/aadPassword" -f $app.id) -Method POST -Headers $headers -Body ($parms | ConvertTo-Json -Depth 6) 

    $sp = @{ appId = $app.appId; displayName = $Appname }
    Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals" -f $app.id) -Method POST -Headers $headers -Body ($sp | ConvertTo-Json -Depth 6) | Out-Null

    Write-Host "Created $($name) application."
    Write-Host "Id    : $($app.id)."   
    Write-Host "Secret: $($secret.secretText)."   
    Write-Host "Please make sure to grant admin permissions to this application."    
    return $app
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
    Write-Debug ("New-Application {0}" -f $Appname)
    $app = Get-Application $AppName
    if ($null -ne $app) { 
        Write-Debug ("App {0} already exists" -f $AppName)
        return $app 
    }
    # openid perms
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

    # if this is an API (not using other API, cannot in B2C anyway)
    if ($null -eq $API) {
        if ($AppName.EndsWith("-MT")) {
            $body = @{
                displayName = $AppName;
                signInAudience = "AzureADMultipleOrgs";
                requiredResourceAccess = @( $OIDCAccess );
                web = @{
                    redirectUris = @(("https://{0}.b2clogin.com/{0}.onmicrosoft.com/oauth2/authresp" -f $script:b2cName))
                }
            }  
            try {
                $app = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/v1.0/applications" -Method POST -Headers $headers -Body ($body | ConvertTo-Json -Depth 6)
            } catch {
                Write-Error $_.ErrorDetails.Message
                throw
            }
        } else { # IEFApp
            $body = @{
                displayName = $AppName;
                signInAudience = "AzureADMyOrg";
                requiredResourceAccess = @( $OIDCAccess );
            }  
            try {
                $app = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/v1.0/applications" -Method POST -Headers $headers -Body ($body | ConvertTo-Json -Depth 6)
            } catch {
                Write-Error $_.ErrorDetails.Message
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
                Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/v1.0/applications/{0}" -f $app.id) -Method PATCH -Headers $headers -Body ($apiProps | ConvertTo-Json -Depth 6) | Out-Null
                $app.identifierUris = $apiProps.identifierUris
                $app.web = $apiProps.web
                $app.api = $apiProps.api
            } catch {
                throw $_
            }
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
    Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals" -f $app.id) -Method POST -Headers $headers -Body ($sp | ConvertTo-Json -Depth 6) | Out-Null
    return $app
}

function Get-Application {
    Param(
        [Parameter(Mandatory)]
        [string] $AppName
    )
    Write-Debug "Get-Application"
    Refresh_token
    $headers = @{
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
    }
    try {
        $resp = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '{0}'" -f $AppName) -Method Get -Headers $headers  -SkipHttpErrorCheck -StatusCodeVariable httpStatus
        if(200 -ne $httpStatus) {
            Write-Error $resp.Error
            return $null
        }
        if($resp.value.Count -gt 0) {
            $app = $resp.value[0]
            Write-Debug ("Get-Application returning {0}" -f $app.appId)            
        } else {
             $app = $null 
             Write-Debug "App not found"
        }

        return $app;
    } catch {
        Write-Debug "Get-Application not found"        
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

    .PARAMETER value
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
        [string]$purpose = "sig",

        [ValidateNotNullOrEmpty()]
        [string]$keyType = "rsa",
        
        [ValidateNotNullOrEmpty()]
        [string]$value,

        [ValidateNotNullOrEmpty()]
        [int]$validityInMonths = 12,    
        
        [ValidateNotNullOrEmpty()]
        [int]$startValidityInMonths = 0
        )        

    Refresh_token
    $headers = @{
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
        'Content-Type' = "application/json";        
    }
    Write-Debug ("New-IefPoliciesKey: creating key container {0}" -f $name)
    $keyset = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/trustFramework/keySets" -Method POST -Headers $headers -Body (@{ id = $name} | ConvertTo-Json) -SkipHttpErrorCheck -StatusCodeVariable httpStatus
    if (403 -eq $httpStatus) {
        Write-Error $keyset.error
        throw
    }
    if(($null -ne $keyset.error) -and ($keyset.error.code -eq 'AADB2C95028')) {
        $keySetId = ("B2C_1A_{0}" -f $name)
        Write-Host ("Adding key to an existing keyset {0}." -f $keySetId)        
    } else {
        $keySetId = $keyset.id        
        Write-Host ("Created keyset {0}" -f $keySetid)              
    }
    $exp = [math]::Round((New-TimeSpan -Start (Get-Date "01/01/1970") -End (Get-Date).AddMonths($startValidityInMonths+$validityInMonths)).TotalSeconds)
    $nbf = [math]::Round((New-TimeSpan -Start (Get-Date "01/01/1970") -End (Get-Date).AddMonths($startValidityInMonths)).TotalSeconds)

    # Issue: https://github.com/mrochon/IEFPolicies/issues/22
    if([string]::IsNullOrEmpty($value)) {
        Write-Debug "New-IefPoliciesKeySet: generating key"
        $keyset = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/trustFramework/keySets/{0}/generateKey" -f $keySetId) `
            -Method Post -Headers $headers -Body (@{ use = $purpose; kty = $keyType; nbf = $nbf ; exp = $exp} | ConvertTo-Json)  -SkipHttpErrorCheck -StatusCodeVariable httpStatus
    } else {
        write-Debug "New-IefPoliciesKeySet: Uploading secret"
        $keyset = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/trustFramework/keySets/{0}/uploadSecret" -f $keySetId) `
            -Method Post -Headers $headers -Body (@{ use = $purpose; k = $value; nbf = $nbf ; exp = $exp} | ConvertTo-Json)  -SkipHttpErrorCheck -StatusCodeVariable httpStatus        
    }
    if(200 -eq $httpStatus) {
        Write-Host ("{0} created/updated" -f $name)
    } else {
        Write-Error $keyset.error
    }
}

function setupEnvironment() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $resp
    ) 
    $script:tokens = $resp
    $script:token_expiry = (Get-Date).AddSeconds($script:tokens.expires_in)
    Write-Host "Authorization completed. Setting up environment."
    $headers = @{
        'Content-Type' = 'application/json';
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
    }
    $domains = Invoke-RestMethod -UseBasicParsing  -Uri https://graph.microsoft.com/v1.0/domains -Method Get -Headers $headers
    foreach($d in $domains.value) {
        if($d.id.Contains(".onmicrosoft.com")) {
            $script:b2cDomain = $d.id
            $script:b2cName = $script:b2cDomain.Split('.')[0]  
            break          
        }
    }
    if($null -eq $script:b2cName) {
        Write-Error "Unable to find .onmicrosoft.com domain"
        throw
    }
    Write-Host ("Logged in to {0}." -f $script:b2cDomain)
    $resp = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'IdentityExperienceFramework')" -Method Get -Headers $headers -SkipHttpErrorCheck -StatusCodeVariable httpCode1
    $resp = Invoke-RestMethod -UseBasicParsing  -Uri "https://graph.microsoft.com/beta/applications?`$filter=startsWith(displayName,'ProxyIdentityExperienceFramework')" -Method Get -Headers $headers -SkipHttpErrorCheck -StatusCodeVariable httpCode2
    if ((200 -ne $httpCode1) -or (200 -ne $httpCode2)) {
        Write-Error "Your tenant is NOT setup for using IEF. Please execute Initialize-IefPolicies to set it up"
        throw
    }

    try {
        $resp = Invoke-RestMethod -UseBasicParsing -Uri ('https://login.microsoftonline.com/{0}.onmicrosoft.com/v2.0/.well-known/openid-configuration' -f $script:b2cName) -Method Get -Headers $headers
        $script:tenantId = $resp.token_endpoint.Split('/')[3]
    }  catch {
        Write-Error "Failed to get tenantid from .well-known"
        throw
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

function Add-IEFPoliciesIdP {
    <#
    .SYNOPSIS
    Add federated IdP as a token provider for this B2C
    
    .DESCRIPTION
    Adds an appropriate technical profile to request tokens from another IdP. Adds this profile as a selectable exchange in any
    existing journeys used by RelyingParties.
    
    .PARAMETER protocol
    Token protocol to use with this IdP: OIDC (default), SAML
    
    .PARAMETER name
    Name to use to reference this IdP in the policies (protocol name will be appended to this name)
    
    .PARAMETER sourceDirectoryPath
    Directory with current policies (defauly: .\)
        
    .PARAMETER updatedSourceDirectory
    Directory where policy files with the new IdP will be created (default: .\federations\
    
    .PARAMETER federationsPolicyFile
    Xml policy file where the new technical profile will be created (defaults: TrustExtensionsFramework.xml)
   
    #>
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$protocol = 'OIDC',

        [ValidateNotNullOrEmpty()]
        [string]$name = 'Contoso',

        [ValidateNotNullOrEmpty()]
        [string]$sourceDirectoryPath = '.\',
                
        [ValidateNotNullOrEmpty()]
        [string]$federationsPolicyFile = 'TrustFrameworkExtensions.xml',

        [ValidateNotNullOrEmpty()]
        [string]$updatedSourceDirectory = '.\federations\'
    )
    Write-Debug ("Protocol: {0}, name: {1}" -f $protocol, $name)
    if ($updatedSourceDirectory) {
        $updatedSourceDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($updatedSourceDirectory)
        if(!(Test-Path -Path $updatedSourceDirectory )){
            New-Item -ItemType directory -Path $updatedSourceDirectory | Out-Null
            Write-Host ("{0} folder created" -f $updatedSourceDirectory)
        }
        if (-not $updatedSourceDirectory.EndsWith("\")) {
            $updatedSourceDirectory = $updatedSourceDirectory + "\"
        }
    }

    if([string]::IsNullOrEmpty($script:b2cName)){
        $configurationFilePath = ("{0}{1}" -f $sourceDirectoryPath, "conf.json")
    } else {
        $configurationFilePath = ("{0}{1}.json" -f $sourceDirectoryPath, $script:b2cName)    
        if(-not(Test-Path $configurationFilePath)){
            $configurationFilePath = ("{0}{1}" -f $sourceDirectoryPath, "conf.json")
        }
    }

    try {
        $conf = Get-Content -Path $configurationFilePath | Out-String | ConvertFrom-Json
        Write-Host ("Using {0} configuration file" -f $configurationFilePath)
    } catch {
        Write-error ("Unable to read configuration json file" -f $configurationFilePath)
        throw
    }

    if($null -eq $conf) {
        write-Host ("Creating new {0} file." -f $configurationFilePath)
        $conf = @{ Prefix = "V1_" }
    }
    if(-not(Test-Path $federationsPolicyFile)){
        $federationsPolicPath = "$PSScriptRoot\strings\EmptyExtension.xml"
        $federations = [xml] (Get-Content $federationsPolicPath)
        Write-Host ("{0} file for federations created" -f $federationsPolicyFile)
    } else {
        $federationsPolicyPath = resolve-path ($sourceDirectoryPath + $federationsPolicyFile)
        $federations = [xml] (Get-Content -Path $federationsPolicyPath | Out-String)
    }
    Write-Host ("Using {0} for IdP Technical Pofile definitions" -f $federationsPolicyFile)


    # Get journeys requiring updates of federated providers
    $files = Get-ChildItem -Path $sourceDirectory -Filter '*.xml'
    $journeyList = @{}
    $rpList = @{}
    foreach($policyFile in $files) {
        $policy = Get-Content $policyFile.FullName
        try {
            $xml = [xml] $policy
            $id = $xml.TrustFrameworkPolicy.PolicyId
            if ($null -eq $id) { continue }
            # work out which journeys require updating for the new IdP
            if($xml.TrustFrameworkPolicy.UserJourneys) {
                foreach($j in $xml.TrustFrameworkPolicy.UserJourneys.ChildNodes) {
                    foreach($s in $j.OrchestrationSteps.ChildNodes) {
                        if(($s.Type -eq 'CombinedSignInAndSignUp') -or ($s.Type -eq 'ClaimsProviderSelection')) {
                            $journeyList.Add($j.Id, @{ Type = $s.Type; Order = [int]$s.Order; Id = $j.Id })
                            break;
                        }
                    }
                }
            }
        } catch {
            if($_.Exception.ErrorRecord.Exception.Message.StartsWith('Exception calling "Add" with')) {
                continue;
            } else {
                Write-Warning ("{0}: {1}." -f $policyFile, $_)
            }
        }
    }

    # which RPs are they used in?
    $singleRPFed = $false
    foreach($policyFile in $files) {
        # BUG: what if federations in an RP? modify just that one!
        $policy = Get-Content $policyFile.FullName
        try {
            $xml = [xml] $policy
            if($xml.TrustFrameworkPolicy.RelyingParty) {
                $rp = $xml.TrustFrameworkPolicy.RelyingParty
                if($journeyList.ContainsKey($rp.DefaultUserJourney.ReferenceId)) {
                    if($federationsPolicyPath.Path -ieq $policyFile.FullName) {
                        # if IdP is added to a file with RP, only this RP will be updated
                        $federations = $xml
                        $singleRPFed = $true
                        $rpList = @{}
                        $rpList.Add($policyFile.FullName, $journeyList.GetEnumerator().Where({ $_.Key -eq $rp.DefaultUserJourney.ReferenceId }, 'First').Value)
                        break
                    } else {
                        $rpList.Add($policyFile.FullName, $journeyList.GetEnumerator().Where({ $_.Key -eq $rp.DefaultUserJourney.ReferenceId }, 'First').Value)
                    }
                }
            }
        } catch {
            Write-Warning ("{0} is not an XML file. Ignored." -f $policyFile)
        }
    }

    # add technical profile
    $tpConf = @{ domainName = ("{0}.com" -f $name); displayName = ("{0} employees/users" -f $name) }
    $name = $name.ToUpper()
    switch($protocol) {
        "AAD" { # AAD, multi-tenant
            #  $DebugPreference = "Continue"
            Write-Host "Adding AAD multi-tenant support"
            Refresh_token
            $headers = @{
                'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
                'Content-Type' = "application/json";        
            }
            #Write-Debug $script:tokens.access_token
            # Must have -MT suffix to tell New-Application this is a MT app
            $aadCommon = New-Application -AppName ("{0}-MT" -f $name)
            Write-Host ("Created/found multi-tenant application: {0}-MT, appId:{1}" -f $name, $aadCommon.appId)    
            Write-Debug ("Checking for key {0}AppSecret" -f $name)   
            # assigning to $resp to prevent error output      
            $resp = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/trustFramework/keySets/B2C_1A_{0}AppSecret" -f $name) -Method GET -Headers $headers -SkipHttpErrorCheck -StatusCodeVariable httpStatus
            Write-Debug ("GET {0} returned status {1}" -f $name, $httpStatus)
            if (400 -eq $httpStatus) {
                Write-Debug "Creating new password"
                $appKey = (@{passwordCredential = @{ 
                    displayName = "Created by IefPolicies"
                }} | ConvertTo-Json -Depth 3)
                $password = Invoke-RestMethod -UseBasicParsing  -Uri ("https://graph.microsoft.com/beta/applications/{0}/addPassword" -f $aadCommon.id) `
                    -Method Post -Headers $headers -Body $appKey -SkipHttpErrorCheck -StatusCodeVariable httpStatus
                if(200 -ne $httpStatus) {
                    Write-Error ("Failed to create secret for application {0}. If this application already exists and has several secrets defined, this command may not be able to add a new one. Please delete one of the secrets and re-run." -f $name)
                } else {
                    Write-Debug ("Adding password to Policykeys: B2C_1A_{0}AppSecret" -f $name)
                    try {
                        New-IefPoliciesKey -name ("B2C_1A_{0}AppSecret" -f $name) -purpose "sig" -keyType "secret" -value $password.secretText
                        $keyMsg = ("App secret {0}AppSecret stored in policy keys" -f $name)                     
                    } catch {
                        $keyMsg = ("Error creating policy key {0}AppSecret for the multi-tenant AAD app secret" -f $name)
                    }
                }
            } 
            $str = Get-Content "$PSScriptRoot\strings\aadmulti.xml"
            $tpId = ("{0}-OIDC" -f $name)            
            $tpConf = @{ clientId = $aadCommon.appId } # no other properties are replaced
            #$keyMsg = ("{0}AppSecret policy key created/updated" -f $name)
        }        
        "OIDC" {
            $str = Get-Content "$PSScriptRoot\strings\OIDCtp.xml"
            $tpId = ("{0}-OIDC" -f $name)            
            $tpConf.Add("clientId", "apps.googleusercontent.com")
            $tpConf.Add("metadataUrl", "https://op.com/.well-known/openid-configuration")            
            $keyMsg = ("Ensure that the OAuth2 client secret is defined in a Policy Container named: B2C_1A_{0}OIDCSecret (key usage: sig)" -f $name)
        }
        "SAML" {
            $str = Get-Content "$PSScriptRoot\strings\SAMLIdP.xml"
            $tpId = ("{0}-SAML" -f $name)
            $keyMsg = ("Ensure that the SAML request signing key is defined in a Policy Container named: B2C_1A_{0}SAMLSigningCert" -f $name)
            $tpConf.Add("metadataUrl", "https://samlidp.com/.well-known/federationmetadata.xml")    
            Write-Host "-------------------------"
            Write-Host "B2C SAML metadata url:"
            if($null -eq $script:b2cName) {
                $b2cName = "<yourtenant>"
            } else {
                $b2cName = $script:b2cName
            }
            Write-Host ("https://{0}.b2clogin.com/{0}.onmicrosoft.com/B2C_1A_<signin journey>/samlp/metadata?idptp={1}-SAML" -f $b2cName, $name)
            Write-Host "-------------------------"            
        }
        default {
            $name = $protocol
            $path = "$PSScriptRoot\strings\$($protocol).xml"
            if(Test-Path $path) {
                $str = Get-Content $path
            } else {
                Write-Error "IdP type $($protocol) not found"
            }
            $regex = "TechnicalProfile Id=`"[`\w-]+`""
            $t = (Select-string -InputObject $str -Pattern $regex).Matches.Value     
            if($null -eq $t) {
                $tpId = $name
                $tpConf.Add("metadataUrl", "https://op.com/.well-known/openid-configuration")                  
            } else {
                $tpId = $t.Split("`"")[1]
            }
            $keyMsg = "Ensure that the client secret is added in a Policy Container named: B2C_1A_$($name)Secret"
        }  
    }
    Write-Debug ("Fixing TP name to {0}" -f $name)
    $str = ($str -f $name)
    if (-not $federations.TrustFrameworkPolicy.ClaimsProviders) { # RP xmls may not have it
        $claimsProviders = $federations.CreateElement("ClaimsProviders", "http://schemas.microsoft.com/online/cpim/schemas/2013/06")
        if($federations.TrustFrameworkPolicy.UserJourneys) {
            $claimsProviders = $federations.TrustFrameworkPolicy.InsertBefore($claimsProviders, $federations.TrustFrameworkPolicy.UserJourneys)
        } elseif($federations.TrustFrameworkPolicy.RelyingParty) {
            $claimsProviders = $federations.TrustFrameworkPolicy.InsertBefore($claimsProviders, $federations.TrustFrameworkPolicy.RelyingParty)
        } else {
            $claimsProviders = $federations.TrustFrameworkPolicy.AppendChild($claimsProviders)
        }
    } else {
        $claimsProviders = $federations.TrustFrameworkPolicy.ClaimsProviders
    }

    $node = $claimsProviders.OwnerDocument.ImportNode(([xml]$str).FirstChild, $true)
    $dummy = $claimsProviders.AppendChild($node)
    $dummy = $federations.TrustFrameworkPolicy.ClaimsProviders.AppendChild($node)
    if(-not $federations.TrustFrameworkPolicy.ClaimsProviders.ChildNodes.Where({$_.DisplayName -eq 'Session Management'}, 'First') -and ($protocol -eq 'SAML')) {
        $samlSessionString = Get-Content "$PSScriptRoot\strings\SAMLSession.xml"
        $node = $federations.TrustFrameworkPolicy.ClaimsProviders.OwnerDocument.ImportNode(([xml]$samlSessionString).FirstChild, $true)
        # prevents default output
        $node = $federations.TrustFrameworkPolicy.ClaimsProviders.AppendChild($node)
    }
    Add-Member -InputObject $conf -NotePropertyName $name -NotePropertyValue $tpConf
    $conf | ConvertTo-Json -Depth 4 | Out-File -FilePath ("{0}/{1}" -f $updatedSourceDirectory, $configurationFilePath)

    # add user journey steps
    foreach($rp in $rpList.GetEnumerator()) {
        if($singleRPFed) {
            $policy = $federations # the one and only file that needs updating
        } else {
            $policy = Get-Content $rp.Key
        }
        $xml = [xml] $policy
        $localOnly = $false        
        if($xml.TrustFrameworkPolicy.UserJourneys.UserJourney) { 
            $addToClaimsExchange = $false
            foreach($step in $xml.TrustFrameworkPolicy.UserJourneys.UserJourney.OrchestrationSteps.ChildNodes) {
                if("Element" -ne $step.NodeType) { continue }
                if(($step.Type -eq 'CombinedSignInAndSignUp') -or ($step.Type -eq 'ClaimsProviderSelection')) {
                    $selection = "<ClaimsProviderSelection TargetClaimsExchangeId=""{0}Exchange"" xmlns=""http://schemas.microsoft.com/online/cpim/schemas/2013/06"" />" -f $name
                    $node = $step.ClaimsProviderSelections.OwnerDocument.ImportNode(([xml]$selection).LastChild, $true)
                    $node = $step.ClaimsProviderSelections.AppendChild($node)
                    $addToClaimsExchange = $true
                    continue
                }
                if($addToClaimsExchange) {
                    try { # If no ClaimsExchanges, RPs referencing only local signin, e.g. PwdChange will not have a 2nd step with Claimsexchanges, ignore these when adding IdPs
                        $selection = "<ClaimsExchange Id=""{0}Exchange"" TechnicalProfileReferenceId=""{1}"" xmlns=""http://schemas.microsoft.com/online/cpim/schemas/2013/06"" />" -f $name, $tpId
                        $node = $step.ClaimsExchanges.OwnerDocument.ImportNode(([xml]$selection).LastChild, $true)
                        $node = $step.ClaimsExchanges.AppendChild($node)    
                    }  catch {
                        $localOnly = $true
                    }                        
                    break
                }
            }
        } else {
            $journeySteps = $rp.Value
            $rpNode = $xml.TrustFrameworkPolicy.RelyingParty
            if($journeySteps.Type -eq 'CombinedSignInAndSignUp') {
                $steps = Get-Content "$PSScriptRoot\strings\CombinedSignInSignUp.xml"
            } else {
                $steps = Get-Content "$PSScriptRoot\strings\ClaimsProvidersSelection.xml"
            }
            $steps = ($steps -f $journeySteps.Order, $name, ($journeySteps.Order + 1), $tpId, $journeySteps.Id)     
            $node = $xml.TrustFrameworkPolicy.OwnerDocument.ImportNode(([xml]$steps).FirstChild, $true)
            $dummy = $xml.TrustFrameworkPolicy.InsertBefore($node, $rpNode)
        }
        $rpFileName = (Split-Path -Path $rp.Key -Leaf)        
        if($localOnly) {
            Write-Host "$($rpFileName) skipped - uses local accounts only"
        } else {
            $xml.Save(("{0}{1}" -f $updatedSourceDirectory, $rpFileName))
            Write-Host ("{0} updated" -f $rpFileName)
        }
    }
    if(-not $singleRPFed) { # alread saved as RP
        #$federations.PreserveWhitespace = $true
        $federations.Save(("{0}{1}" -f $updatedSourceDirectory, $federationsPolicyFile))
    }
    Write-Host ("{0} updated" -f $federationsPolicyFile)
    Write-Host $keyMsg -ForegroundColor Yellow
    Write-Host "Please review files in the $($updatedSourceDirectory) folder and, if correct, update the conf.json file and copy them to the work folder" -ForegroundColor Yellow
}

function New-IEFPoliciesSamlRP {
    <#
    .SYNOPSIS
    Provide SAML SSO
    
    .DESCRIPTION
    Adds claims provider, RP and related artifacts to support SAML SSO
    
    .PARAMETER epName
    Endpoint name (default: SAML). Will be used as part of TechnicalProfile name as well.
     
    .PARAMETER signingKeyName
    Endpoint name (default: same as epName)

    .PARAMETER sourceDirectory
    Directory with current policies (defauly: .\)
        
    .PARAMETER extensionsFile
    Xml policy file where the new technical profile will be created (defaults: TrustExtensionsFramework.xml)

    #>
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$epName = 'SAML',

        [string]$signingKeyName,

        [ValidateNotNullOrEmpty()]
        [string]$sourceDirectoryPath = '.\',
                
        [ValidateNotNullOrEmpty()]
        [string]$extensionsFile = 'TrustFrameworkExtensions.xml'
    )
    if([string]::IsNullOrEmpty($epName)) {
        Write-Error "epName parameter may not be empty"
        throw "Endpoint name (epName) parameter may not be empty"
    }
    if([string]::IsNullOrEmpty($signingKeyName)) {
        $signingKeyName = ("B2C_1A_{0}SigningKey" -f $epName)
    }

    if(-not $configurationFilePath) {
        if($script:b2cName) {
            $configurationFilePath = ".\$($script:b2cName).json"   
        } else {
            $configurationFilePath = '.\conf.json'
        }  
    }
    if(-not(Test-Path $configurationFilePath)){
        $conf = @{
            Prefix = "V1_" 
            SomeProperty = "Use {SomeProperty} in your xml to have it replaced by this value"
        }
        Write-Host ("{0} configuration file created" -f $configurationFilePath)
    } else {
        $conf = Get-Content -Path $configurationFilePath | Out-String | ConvertFrom-Json
        Write-Host ("Using {0} configuration file" -f $configurationFilePath)
    }

    Refresh_token
    $headers = @{
        'Authorization' = ("Bearer {0}" -f $script:tokens.access_token);
        'Content-Type' = "application/json";        
    }
    # Ensure there is a token signing cert
    if(-not $signingKeyName.Startswith("B2C_1A_")) {
        $signingKeyName = ("B2C_1A_{0}" -f $signingKeyName)
    }
    $keyset = Invoke-RestMethod -Uri ("https://graph.microsoft.com/beta/trustFramework/keySets/{0}" -f $signingKeyName) -Method Get -Headers $headers -SkipHttpErrorCheck -StatusCodeVariable httpStatus
    if (400 -eq $httpStatus) {
        $keyset = New-IefPoliciesCert $signingKeyName
    }
    # Add SAML Assertion Issuer
    $extensions = [xml](Get-Content ($sourceDirectoryPath + $extensionsFile))
    $tpName = ("{0}AssertionIssuer" -f $epName)
    $exists = $false
    foreach($cp in $extensions.TrustFrameworkPolicy.ClaimsProviders.ChildNodes) {
        if($exists) { break }
        foreach($tp in $cp.TechnicalProfiles.ChildNodes) {
            if ($tp.Id -eq $tpName) {
                $exists = $true
                break
            }
        }
    }
    if($exists) {
        Write-Warning ("{0} already exists. {1} will not be updated" -f $tpName, $extensionsFile)
    } else {
        $SAMLAssertionIssuer = Get-Content "$PSScriptRoot\strings\SAMLAssertionIssuer.xml"
        $temp = $SAMLAssertionIssuer -f $epName, $signingKeyName
        $node = $extensions.TrustFrameworkPolicy.ClaimsProviders.OwnerDocument.ImportNode(([xml]$temp).FirstChild, $true)
        $node = $extensions.TrustFrameworkPolicy.ClaimsProviders.AppendChild($node)
        $dest = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($sourceDirectoryPath + $extensionsFile)
        #$extensions.PreserveWhitespace = $true
        $extensions.Save($dest)
        Write-Host ("{0}AssertionIssuer TechnicalProfile added to {1}" -f $epName, $extensionsFile)
    } 
    # Add RP
    # Which step in Base SUSI does sendclaims?
    $base = [xml](Get-Content -Raw ($sourceDirectoryPath + "TrustFrameworkBase.xml"))
    $susi = $base.TrustFrameworkPolicy.UserJourneys.ChildNodes | Where Id -eq "SignUpOrSignIn"
    $lastStepNo = ($susi.OrchestrationSteps.ChildNodes | Select-Object -Last 1).Order
    $samlRP = Get-Content "$PSScriptRoot\strings\SAMLRP.xml"
    $temp = $samlRP -f $epName, $laststepNo
    $rpFileName = ("{0}{1}_SUSI.xml" -f $sourceDirectory, $epName)
    $temp | Out-File -FilePath $rpFileName
    Write-Host ("{0} added/replaced" -f $rpFileName)    
    Write-Host ("Metadata: https://{0}.b2clogin.com/{0}.onmicrosoft.com/B2C_1A_{1}{2}_SUSI/samlp/metadata" -f $script:b2cName, $conf.Prefix,  $epName)
    # Update conf file
    $tpConf = @{ samlResponseIssuerUri = ("https://{0}/{1}" -f $script:b2cDomain, $epName) }
    Add-Member -InputObject $conf -NotePropertyName $epName -NotePropertyValue $tpConf
    $conf | ConvertTo-Json | Out-File -FilePath ("{0}conf.json" -f $sourceDirectoryPath)
    Write-Host ("{0} updated" -f $configurationFilePath)
}

function Debug-IEFPolicies {
    <#
    .SYNOPSIS
    Does a static code analysis of a policy set looking for common errors
    
    .DESCRIPTION
    Static code analysis of a policy set. Looks for errors or potential errors which are not be detected during policy load. Checks for:
    1. Unknown claim names in preconditions
    2. Use of a claim name in ClaimEquals precondition where a literal is expected
    3. Duplicate key values in Metadata elements
    4. Missing IncludeClaimResolvingInClaimsHandling in TechnicalProfiles using ClaimsResolvers.    
    
    .PARAMETER sourceDirectory
    Directory with xml policies (default is current directory)
    
    #>
    [CmdletBinding()]
    param(
        #[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$sourceDirectory = '.\'
    )
    # load originals
    LoadPolicies $sourceDirectory
    Write-Output "Policy structure"
    Write-Output "----------------"
    ShowPolicyTree $script:policies.Root

    $claims = New-Object Collections.Generic.List[String]
    foreach($policy in $script:policies.List) {
        $xml = [xml] $policy.Body
        foreach($c in $xml.TrustFrameworkPolicy.BuildingBlocks.ClaimsSchema.ChildNodes) {
            if("Element" -ne $c.NodeType) { continue }
            $name = $c.Attributes["Id"].Value
            if($claims.Contains($name)) { continue }
            $claims.Add($name)                
        }
    }

    $script:errorCount = 0
    Write-Output "----------------"    
    Write-Output "Tests:"
    Write-Output "1. Duplicate metadata keys."
    Write-Output "2. Use of claim names in fields where literals are expected."
    Write-Output "3. Invalid claim names in preconditions."
    Write-Output "4. Missing IncludeClaimResolvingInClaimsHandling in TechnicalProfiles using ClaimsResolvers."
    Write-Output "----------------"

    foreach($policy in $script:policies.List) {
        Select-Xml -Content $policy.Body -NameSpace @{ dflt = 'http://schemas.microsoft.com/online/cpim/schemas/2013/06' } -XPath "//dflt:Metadata" | foreach {
            # Look for duplicate Metadata key values
            $keys = New-Object Collections.Generic.List[String]
            foreach($k in $_.node.ChildNodes) {
                if("Element" -ne $k.NodeType) { continue }
                if($keys.Contains($k.Key)) {
                    Write-Host ("{1}: Metadata for '{0}' contains duplicate key '{2}'" -f $_.node.ParentNode.Attributes["Id"].Value, $policy.Source, $k.Key)
                    ++$script:errorCount
                }
                $keys.Add($k.Key)
            }
        }
        # Look for mis-spelled claim names or claim names used in Claimequals comparison value in Preconditions

        Select-Xml -Content $policy.Body -NameSpace @{ dflt = 'http://schemas.microsoft.com/online/cpim/schemas/2013/06' } -XPath "//dflt:Preconditions" | foreach {
            foreach($p in $_.node.ChildNodes) {
                if("Element" -ne $p.NodeType) { continue }
                $type = $p.Type
                $clauseNo = 0
                foreach($c in $p.ChildNodes) {
                    if("Element" -ne $c.NodeType) { continue }
                    $val = $c.InnerXml
                    if ($clauseNo -eq 0) {
                        if(-not $claims.Contains($val)) {
                            Write-Host ("{0}: A precondition contains an unknown claim '{1}'" -f $policy.Source, $val)
                            ++$script:errorCount
                        }
                        if ($type -eq "ClaimsExist") { break } # check only the first Value element
                    } else {
                        if($claims.Contains($val)) {
                            Write-Host ("{0}: A ClaimEquals precondition is testing against a name of an existing claim type {1}. Test value must be a literal." -f $policy.Source, $val)
                            ++$script:errorCount
                        }
                        break
                    }
                    ++$clauseNo
                }
            }
        }
    }
    CheckInheritedAttrs (New-Object Collections.Generic.List[String]) $script:policies.Root    

    Write-Host ("Found {0} possible issues" -f $script:errorCount)
}

function ConvertTo-IefPolicies {
    <#
    .SYNOPSIS
    Converts VSCode B2C Extensions policy settings json into settings used by Import-IefPolicies
    
    .DESCRIPTION
    Converts VSCode B2C Extensions policy settings json file into one or more setting files in the format 
     used by Import-IefPolicies.    
   
    .PARAMETER extensionsFilePath
    Path of configuration file used by B2C VSCode Extensions (default: ./appSettings.json)
    
    .PARAMETER IefPoliciesDirectory
    Directory where configuration files(s) in the format used by IefPolicies Import-IefPolicies command will be stored (default: ./).
    Each file will be named <b2cTanantName>.json, e.g. mytenant.json

    #>
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$extensionsFilePath = '.\appSettings.json',

        [ValidateNotNullOrEmpty()]
        [string]$IefPoliciesDirectory = '.\'
    )

    # $DebugPreference = "Continue"
    $appSettings = Get-Content -Path $extensionsFilePath | Out-String | ConvertFrom-Json
    foreach($env in $appSettings.Environments) {
        Write-Debug "Environment: $($env.Name)"
        $b2cName = $env.Tenant.Split('.')[0]
        Write-Debug "   Tenant: $($b2cName)"
        $conf = @{ Prefix = "V1_" }

        foreach($prop in ($env.PolicySettings | Get-Member -MemberType NoteProperty)) {
            Write-Debug "   - $($prop.Name) : $($env.PolicySettings.$($prop.Name))"
            if(($prop.Name -ne "ProxyIdentityExperienceFrameworkAppId") -and ($prop.Name -ne "IdentityExperienceFrameworkAppId")) {
                $conf.Add($prop.Name, $env.PolicySettings.$($prop.Name))
            } else {
                Write-Host "$($prop.Name) ignored. Import-IefPolicies will use values based on B2C tenant used."
            }
        }
        $confPath = ("{0}/{1}.json" -f $IefPoliciesDirectory, $b2cName)
        $conf | ConvertTo-Json -Depth 4 | Out-File -FilePath $confPath
        Write-Host "$($confPath) created"
    }
    Write-Host ""
    Write-Host "Please make the following global string replacements in your current policy xml files."
    Write-Host "(Values of these properties are no longer needed in your configuration json files. They will be obtained"
    Write-Host " during the execution of Import-IefPolicies command, based on the B2C tenant you are logged into at that time.)"
    Write-Host ""
    Write-Host "1. '{Settings:' with '{'"
    Write-Host "2. '<b2cname>.onmicrosoft.com' with 'yourtenant.onmicrosoft.com', where <b2cname> is the name of a B2C tenant"
    Write-Host "3. '{Settings:IdentityExperienceFrameworkAppId}' with 'IdentityExperienceFrameworkAppId'"
    Write-Host "4. '{Settings:ProxyIdentityExperienceFrameworkAppId}' with 'ProxyIdentityExperienceFrameworkAppId'"    
}

function LoadPolicies([string]$sourceDirectory = "./") {
    $files = Get-Childitem -Path $sourceDirectory -Filter '*.xml'
    $policyList = @()
    foreach($policyFile in $files) {
        $policy = [string](Get-Content $policyFile.FullName)
        try {
            $xml = [xml] $policy
            $id = $xml.TrustFrameworkPolicy.PolicyId
            if ($null -eq $id) { continue }
            $base = $xml.TrustFrameworkPolicy.BasePolicy.PolicyId
            $policyDef = @{ Id = $id; BaseId = $base; Body = $policy; Source= $policyFile.Name; LastWrite = $policyFile.LastWriteTime; Children = @() }
            if (-not $base) {
                if($policySetRoot) {
                    Write-Error "Duplicate base policies fund. There must only be one xml policy with no BasePolicy element"
                    throw
                }
                $policySetRoot = $policyDef
            }
            $policyList= $policyList + @($policyDef)
        } catch {
            Write-Warning ("{0} is not an XML file. Ignored." -f $policyFile)
        }
    }
    if(-not $policySetRoot) {
        Write-Error "Root policy not found in set. There must be exactly one xml policy with no BasePolicy element"
        throw
    }
    #return @{List = $policyList; Root = $policySetRoot}
    $script:policies = @{List = $policyList; Root = $policySetRoot}
    BuildPolicyTree $policyList $policySetRoot
}

function BuildPolicyTree([PSObject] $policyList, [PSObject] $parent) {
    Write-Debug ("Parent: {0}" -f $parent.Id)
    foreach($p in $policyList) {
        if($p.BaseId -eq $parent.Id) {
            Write-Debug ("   Found child: {0}" -f $p.Id)
            $parent.Children += $p
            BuildPolicyTree $policyList $p
        }
    }
}

function ShowPolicyTree([PSObject] $parent, [uint16] $indent = 0) {
    Write-Output ("{0}{1}({2})" -f ("`t" * $indent), $parent.Id, $parent.Source)
    foreach($p in $script:policies.List) {
        if($p.BaseId -eq $parent.Id) {
            ShowPolicyTree $p ($indent+1)
        }
    }
}

$ClaimsResolvers = @("Culture", "Policy", "Context", "Claim", "OIDC", "OAUTH-KV", "SAML", "oauth2" )
function CheckInheritedAttrs([Collections.Generic.List[String]] $tps, [PSObject] $parent) {
    Write-Debug ("CheckInheritedAttrs, parent: {0}" -f $parent.Id)
    $xml = [xml] $parent.Body
    foreach($t in $xml.TrustFrameworkPolicy.ClaimsProviders.ClaimsProvider.TechnicalProfiles.ChildNodes) {
        if("Element" -ne $t.NodeType) { continue }        
        $tp_id = $t.Attributes["Id"].Value    
        Write-Debug ("   TechnicalProfile: {0}" -f $tp_id)    
        if($t.Metadata) {
            foreach($m in $t.Metadata.ChildNodes) {
                if("Element" -ne $m.NodeType) { continue }
                if("IncludeClaimResolvingInClaimsHandling" -eq $m.Attributes["Key"].Value) {
                    Write-Debug "      Found IncludeClaimResolvingInClaimsHandling"                        
                    if("true" -eq $m.InnerXml) {
                        Write-Debug "        is True"
                        $tps.Add($t.Attributes["Id"].Value)
                    }
                }
            }
        }
        $tp_string = $t.InnerXml
        foreach($cr in $ClaimsResolvers) {
            if(-not $tp_string.Contains("{$($cr):")) { continue }
            if($tps -and $tps.Contains($tp_id)) { continue }
            Write-Host "TechnicalProfile $($tp_id) uses ClaimsResolver $($cr) but its metadata does not include the IncludeClaimResolvingInClaimsHandling=true setting"
            ++$script:errorCount
        }
    }    
    foreach($p in $script:policies.List) {
        if($p.BaseId -eq $parent.Id) {
            CheckInheritedAttrs $tps $p                  
        }      
    }
}


$script:policies = $null