# IEF Policies PowerShell module

## General

### Purpose
Aids in the development and deployment of the Azure B2C Identity Experience Policy (IEF) xml files. Provides cmdlets to initiate a
new policy set from the starter packs, add OIDC and SAML IdP technical profiles and journey updates, add SAML RPs, merge community and other samples into the set, perform static code analysis and deploy to B2C with no need for deployment-specific source changes. Also, includes commands for
downloading existing policy sets or deleting them from a B2C tenant. Includes a command that may be used to setup a new B2C tenant for use with IEF.
Makes it easy to re-deploy the same set of xml policies to multiple tenants (dev, test, etc.) by just adjusting the 
configuration file used by the import cmdlet. Supports either interactive or un-attended (client credentials) authentication to a B2C tenant.

[This repo](https://github.com/mrochon/B2CPipeline) shows how to use this module in an Azure Pipeline for continous deployment of custom journeys.

### Installation

This module can be installed from the [PowerShell Gallery](https://www.powershellgallery.com/packages/IefPolicies/)

### Change log

| Name  | Description  |
|---|---|
| 3.1.13 | Added support for some new idP types (Amazon, Git, etc.) |
| 3.1.12 | Added DisplayControls flag to New-IefPolicies; AAD returns email claim |
| 3.1.11 | Improved Debug- cmd, bug fixes for AddIdP |
| 3.1.9 | Minor mods: display SAML metadata url for new IdP, fix bug when running on Mac |
| 3.1.7 | Fixes: SAML RP created wrong policy key; AAD MT failed at runtime |
| 3.1.5 | New: noPrefix flag in Import-IefPolicies |
| 3.1.4 | New: list policy structure as part of Debug-IefPolicies output |
|  | Fix: reverted back to specifying all needed permissions instead of AccessAsUser |
|  | Change: Add-IefPoliciesIdp -protocol aad adds AAD MT support to a policy set |
| 3.1.3  | New: Debug-IefPolicies |
| 3.1.2  | New: New-IefPoliciesSamlRP |
| 3.1.0  | Change: import adds AAD-Common extensions app TP to Extensions.xml |
| 3.0.6  | Change: import all policies if conf file changed since last upload |
|  | New: Add-IefPoliciesIdP adds a SAMl or OIDC IdP to an existing policy set and updates journey definitions with the new exchange |
|  | Update: Import-IefPolicies will replace *{ExtAppId}* and *{ExtObjectId}* strings with the correct *B2C extensions app* values |
| 3.0.5 | Update: Export-IefPolicies -clean option modifies downloaded files to startpack-like content |
| 3.0.3 | Update: Import-IefPolicies will first look for .\yourtenantname.json before .\conf.json |
| 3.0.2 | Update: New-iefPoliciesKey allows providing a value |
|   | New: New function: New-IefPoliciesCert |
| 3.0.0   | New: Requires PS 7.x. |
| 2.2.11   | New: Initialize-IefPolicies and Get-IefPoliciesAADCommon |
| 2.2.10   | New: use values from secrets.json in same directory as conf file |
| 2.2.9   | New: Include sample conf.json in the Add-IefPoliciesSample operation |
| 2.2.8   | New: Remove-IefPolicies |
|   | Improved: exception handling and error reporting |
| 2.2.7  | Modified: check conf.json validity to avoid null prefix setting |
| 2.2.6  | Fixed: breaking change in MS Graph no longer returning tenantid in @odata.id |
| 2.2.4  | Added support for using {tenantId} as automatic replacement property ({Policy:TrustFrameworkTenantId} defined in IEF cannot be used in some policy properties) |       

### Use examples

**Note**: these commands may be in a stand-alone PowerShell console (must be ver 7 or higher) or from VSCode Terminal (PowerShell) console.
**Note**: all examples below assume that the PowerShell console is positioned on a working directory (here  *demo*) where xml policies are or are to be stored.

#### Tenant setup
If your B2C is not yet setup for using IEF as per [instructions provided in the official documentation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/custom-policy-get-started) execute:
```Powershell
Connect-IefPolicies myb2ctenant 
Initialize-IefPolicies
```
or use use [the IEF setup website](https://aka.ms/b2csetup/). 

#### Deploy SocialAndLocal starter pack

```PowerShell
PS C:\demo> New-IefPolicies
Package type: 
\[L\]ocal accounts only,
\[S\] Social/federated only,
\[SL\]ocal and social/federated,
\[M\]FA social/federated and local with MFA?
\[Q\]uit: SL
PS C:\demo> connect-iefpolicies myb2ctenant
PS C:\demo> import-iefpolicies
```

#### Add a SAML IdP

```PowerShell
PS C:\demo> New-IefPolicies
Package type: 
\[L\]ocal accounts only,
\[S\] Social/federated only,
\[SL\]ocal and social/federated,
\[M\]FA social/federated and local with MFA?
\[Q\]uit: SL
PS C:\demo> connect-iefpolicies myb2ctenant
PS C:\demo> Add-IefPoliciesIdP SAML -name Contoso
PS C:\demo> copy ./federation .
PS C:\demo> import-iefpolicies
```

#### Add a SAML RP

```PowerShell
PS C:\demo> New-IefPolicies
Package type: 
\[L\]ocal accounts only,
\[S\] Social/federated only,
\[SL\]ocal and social/federated,
\[M\]FA social/federated and local with MFA?
\[Q\]uit: SL
PS C:\demo> connect-iefpolicies myb2ctenant
PS C:\demo> New-IefPoliciesSamlRP -issuerName Contoso
PS C:\demo> copy ./federation .
PS C:\demo> import-iefpolicies
```

#### Perform static code analysis of the policies

```PowerShell
Debug-IefPolicies
```

#### Merge in a sample policy

The following script will deploy a new SocialAndLocalWithMFA starter pack, augmented with [a journey supporting sign in/up, profile edit and password reset in one RelyingParty](https://github.com/mrochon/b2csamples/tree/master/Policies/AllInOne). The uploaded
policies will be named *B2C_1A_V1_* unless the *V1_* string is changed in the associated conf.json file.

```PowerShell
cd 'c:\some empty directory'
New-IefPolicies
*select M when prompted*
Add-IefPoliciesSample AllInOne -owner mrochon -repo b2csamples
Connect-IefPolicies yourb2c
Import-IefPolicies
```

## Cmdlets

1. [Add-IEFPoliciesSample](https://github.com/mrochon/IEFPolicies#add-iefpoliciessample)
1. [Add-IEFPoliciesIdP](https://github.com/mrochon/IEFPolicies#add-iefpoliciesidp)
2. [Connect-IEFPolicies](https://github.com/mrochon/IEFPolicies#connect-iefpolicies)
2. [Debug-IEFPolicies](https://github.com/mrochon/IEFPolicies#debug-iefpolicies)
3. [Export-IEFPolicies](https://github.com/mrochon/IEFPolicies#export-iefpolicies)
4. [Get-IEFPoliciesAADCommon](https://github.com/mrochon/IEFPolicies#get-iefpoliciesaadcommon)
5. [Import-IEFPolicies](https://github.com/mrochon/IEFPolicies#import-iefpolicies)
6. [Initialize-IEFPolicies](https://github.com/mrochon/IEFPolicies#initialize-iefpolicies)
7. [New-IEFPolicies](https://github.com/mrochon/IEFPolicies#new-iefpolicies)
8. [New-IEFPoliciesCert](https://github.com/mrochon/IEFPolicies#new-iefpoliciescert)
9. [New-IEFPoliciesKey](https://github.com/mrochon/IEFPolicies#new-iefpolicieskey)
9. [New-IEFPoliciessamlRP](https://github.com/mrochon/IEFPolicies#new-iefpoliciessamlrp)
10. [Remove-IEFPolicies](https://github.com/mrochon/IEFPolicies#remove-iefpolicies)


### Add-IEFPoliciesSample

Downloads policy files from one of the [B2C Community samples](https://github.com/azure-ad-b2c/samples). Only xml policy files are downloaded. Since these do not include the base xml file, and individual files are named uniquely to the sample type, you can **usually**
add them to an existing startr pack set. You should check which starter pack they are based on.

The following example add a single policy [from a specific B2C Community](https://github.com/azure-ad-b2c/samples/tree/master/policies/default-home-realm-discovery) to the current folder.

```PowerShell
cd 'c:\your directory with the IEF policies'
Add-IEFPoliciesSample default-home-realm-discovery
Add-IefPoliciesSample ConditionalAccess -owner mrochon -repo b2csamples
```

Parameters:

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| sampleName | Y | Name of the sub-folder within the *policies* folder which contains the sample |
| destinationPath | N | Directory to download the files to. Current directory by default. |
| owner | N | Git repo owner (default: Azure-ad-b2) |
| repository | N | Repo name (default: samples). IEF policies must be in a *policies* folder |

### Add-IEFPoliciesIdP

Adds a standard SAMl or OIDC IdP to an existing policy set and updates journeys to usereference it. The new policy xml files are created in a separate folder. You can then relace the existing policy files with the new ones.

As part of the process, this command adds a new object to the configuration file with data that needs to be provided before the policies are imported

*Add-IefPolicies -protocol aad* adds AAD multi-tenant support to the policy set. If not already in existence, this command will register a new application called *AADCommon* and store it's secret in *B2C_1A_AADAppSecret* policy container.

The following command will add a new OIDC TechnicalProfile named *Contoso-OIDC* to the TrustFrameworkExtension.xml and add references to it to all journeys referenced by relying parties defined in this policy set. It will also extend the conf.json file with some additional settings (e.g. metadata url) to be used when importing these files to B2C. 

```PowerShell
cd 'c:\your directory with the IEF policies'
Add-IEFPoliciesIdP OIDC -Name Contoso
```

Parameters:

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| protocol | N | IdP type name: *OIDC* (default), *AAD* (multi-tenant), *SAML*, *ADFS*, *Amazon*, *eBay*, *Git*, *Google*, *LinkedIn*, *MSA*, *Ping*, *Twitter* |
| Name | Y | Issuer name |
| sourceDirectoryPath | N | Current policies source xml files |
| updatedSourceDirectory | N | Directory where any new/updated files will be stored (default: ./federations) |
| fedeationsPolicyFile | N | File name (may not exist) where new technical profile will be added (default: TrustFrameworkExtensions.xml) |
| configurationFilePath | N | Variable configuration data file (default: ./conf.json) |

### Connect-IEFPolicies

Use *Connect-IEFPolicies* cmdlet to sign in to your B2C tenant and obtain access tokens needed to execute other
cmdlets (*import-* and *export-*) in this module which require Graph access to the tenant. You can sign in either
interactively using user credentials or using application credentials (id and secret). For the former, the user must be
have a directory role with sufficient privileges to execute requested actions. 

To use the OAuth2 Client Credentials tokens, using application id and secret, [register the application for use with Microsoft Graph](https://docs.microsoft.com/en-us/azure/active-directory-b2c/microsoft-graph-get-started) and grant it the following **application** permissions:
1. Application.Read.All 
2. Domain.Read.All
3. Organization.Read.All
4. Policy.ReadWrite.TrustFramework
5. TrustFrameworkKeySet.ReadWrite.All (if module used to create policy keys or initialize the tenant)

For interactive signin you do **not** need to register the application. This module is already registered as an AAD multi-tenant app.

E.g.

```PowerShell
Connect-IefPolicies -tenant myTenant  
Connect-IefPolicies -tenant myTenant -clientId "registered app id" -clientSecret "secret"
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| tenant | N | Name of tenant you want to sign into. '.onmicrosoft.com' is not required. This parameter is required if you are signing in with an account which is an invited guest in your B2C tenant |
| clientId | N | id of an application registered in your tenant for non-interactive signin |
| clientSecret | N | Secret generated for the app |

### Debug-IEFPolicies

*Debug-IEFPolicies* performs static code analysis on a policy set, looking for common errors for which the policy load process does not provide any or adequate debugging information:

1. Duplicate key names in a Metadata element (load reports that a duplicate key was found but does not specify where) 
2. Invalid claim names in Preconditions (these are not caught by the load process)
3. Using claim names as the 2nd operand in a ClaimEquals condition in the mistaken expectation that values of claims will be compared. The comparison requires a literal value in that operand.
4. 

```PowerShell
Debug-IefPolicies -sourceDirectoryPath  'c:\temp\ief'
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| sourceDirectoryPath | N | Directory path with policy set xml files (default: current working directory) |

### Export-IEFPolicies

Use *Export-IEFPolicies* function to download your IEF policies from the B2C tenant to a local folder.

E.g. download policies using V1 prefix ('B2C_1A_V1...') to current folder and remove tenant-specific identifiers (IEF App ids, etc.) from the xml.

```PowerShell
cd C:\LocalAccounts\policies
Export-IEFPolicies V1 -clean  `
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| prefix | Y | Download policies whose name starts with *"B2C_1A_prefix"* |
| destinationPath | N | Directory path where your xml policies are stored. Must already exist |
| clean | N | Modify xml to make it tenant independant, remove tenant-specific ids |

**Note:** when using the *-clean* option, this command will attempt to make the contents of the policy files tenant neutral, as similar to what you see in the [B2C starter packs](https://github.com/Azure-Samples/active-directory-b2c-custom-policy-starterpack) as possible. In particular, it will:
1. replace all occurrences of the B2C tenant name (the first part of the abc.onmicrosoft.com) url with *yourtenant* literal
2. replace all occurrences of the application ids of the IdentityExperienceFramework and ProxyIdentityExpereinceFramework with that name suffixed with *AppId*
3. replace all occurences of the *B2C extensions app* app id and object id with *{ExtAppId}* and *{ExtObjectId}*
4. create a *conf.json* file with the prefix setting

You should be able to *connect-iefpolicies* to a different B2C tenant and *import-iefpolicies* to that tenant with no further changes. If there are tenant-specific url REST function references or policy key container name referneces these will need to be changed manually before uploading.

### Get-IEFPoliciesAADCommon

*This command is no longer needed: Import-IefPolicies will automatically replace references to {ExtAppId} and {ExtObjectId} with the tenant's 'b2c extensions app'*

Displays application and object ids of a special B2C extensions application. These values are needed if your policies [store or retrieve custom user attributes](https://docs.microsoft.com/en-us/azure/active-directory-b2c/user-flow-custom-attributes?pivots=b2c-custom-policy#azure-ad-b2c-extensions-app) as [for example in this sample](https://github.com/mrochon/b2csamples/tree/master/Policies/PersistCustomAttr)

E.g.

```PowerShell
Get-IefPoliciesAADCommon
```

Parameters: none

### Import-IEFPolicies 

#### Description
Use *Import-IEFPolicies* function to upload your IEF policies to the B2C tenant you are currently signed into. 

Before uploading, the cmdlet will modify your xml files and store the new versions in the directory identified by the
*updatedSourceDirectory* (*.debug/<yourtenantName>* by default). The cmdlet will replace any occurrences of *yourtenant* string
(used in all StarterPolicies) with the name of the tenant you have logged in using *Connect-IefPolicies*. It will use a json configuration file (if provided, by default it will look for conf.json in the current directory) to make other changes as well. The Json
file defines values to be replaced in the original xml files. E.g.

```Json
{
    "Prefix": "V1",
    "MyRESTUrl": "https://mywebsite.com/users",
    "Contoso": {
        "ClientId": "123"
    }
}
```
will cause this cmdlet to:

1. inject *V1* into names of all policies, i.e. *B2C_1A_TrustFrameworkBase* will become *B2C_1A_V1TrustFrameworkBase*, etc. 
2. Replace occurrences of *{ExtAppId}* and *{ExtObjectId}* in xml the appId and objectId of the *B2C extensions app* in this B2C tenant
3. Replace all occurrences of a string enclosed in curly braces, e.g. *{MyRESTUrl}* above, with the corresponding value (if present) in the *.json* file, e.g. above url (*https://mywebsite.com/users*). 
4. Replace occurrences of *{Contoso:ClientId}* with *123*

If the same folder contains a secrets.json file, the attributes it defines will be added to those in the above configuration file. That allows you to configure your *.gitignore* file to **not** upload any confidential data 
(e.g. AppInsights key used for journey debugging) to your repos.

#### Example

```PowerShell
Connect-IefPolicies -Tenant yourtenant
cd 'c:\your directory with the IEF policies'
Import-IEFPolicies 
```

#### Parameters

Parameters:

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| sourceDirectory | N | Directory path where your xml policies are stored (default: current directory) |
| updatedSourceDirectory | N | Directory path where the policies updated by this script will be stored. Also used to prevent uploading unmodified policies. Default: ./debug/yourtenant subfolder. |
| configurationFilePath | N | json file with additional replacement strings. Default: *.\b2cname>.json*, otherwise  *.\conf.json*. The script will match any property in this file with a string with format *{<property name>}* and replace it with the value of the property. See above about a *secrets.json* file |
| generateOnly | N | If used, the script will only generate policy files but not upload them to B2C |
| prefix | N | String inserted into the name of generated policies, e.g. the new base policy name will be *B2C_1A_XYZTrustFrameBase, where XYZ is the value of the provided prefix. Can also be set in the conf.json file |
| noprefix | N | Flag. When used, does not inject a prefix into thee policy names |

### Initialize-IEFPolicies
Performs [B2C tenant setup as descibed in the official documentation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/custom-policy-get-started). This setup is needed only once. This command will also add a **fake** Facebook
policy key (B2C_1A_FacebookSecret) to allow uloading of policy sets with social provider support - they all use Facebook as example of a social provider. 

```PowerShell
Connect-IefPolicies <b2c name>
Initialize-IEFPolicies
```
**NOTE:** at completion this command displays a url which, when executed through a browser will allow an administrator to grant admin consent to one of the required applications (IEFProxy) have signin permissons to another. It is **important** to
execute this consent as otherwise any uploaded policies will not work for local signin.


Parameters:
| Property name | Required | Purpose |
| -------- | ------ | ----- |
| validateOnly | N | Checks for presence of IEF-required applications |

### New-IEFPolicies

Use *New-IEFPolicies* function to download a set of policies from the [Azure B2C StarterPack](https://github.com/Azure-Samples/active-directory-b2c-custom-policy-starterpack). The cmdlet will prompt you for which of the starter packs (local, social, etc.)
to download. A TechnicalProfile with references to teh b2C extension app (needed by persistent custom attributes) will be added to teh TrustFrameworkExtensions.xml.

E.g.

```PowerShell
New-IefPolicies -destinationPath $dest 
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| destinationPath | N | Directory path where your xml policies are stored. Will be created if does not already exist. Current directory is default |
| displayControls | N | Use the DisplayControls starter pack directory |

### New-IEFPoliciesCert

Creates and deploys into Policy Keys a new, self-signed signing certificate. A copy of the cert is stored locally in CurrentUser/My certificate storage.

E.g.

```PowerShell
New-IEFPoliciesCert MyB2C `
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| keyName| Y | Policy key storage name. Used to create CName of the cert: *keyName.b2cname*.onmicrosoft.com |
| validityMonths | N | How long valid (default is 12 months) |
| startValidInMonths | N | How many months hence must the cert start being valid (default is 0 months) |

### New-IEFPoliciesKey

Creates a new key Policy Key secret.

E.g.

```PowerShell
New-IefPoliciesKey AzureFuncKey -purpose sig -value "<Azure Function key value>" -validityInMonths 12
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| name | Y | key name |
| purpose | N | Purpose (default: *sig*; *enc*) |
| keyType | N | Key type (default: *rsa*; *oct*) |
| value | N | Secret, will be generated if not provided |
| startValidityInMonths | N | Valid from: number of months from now (default: 0) |
| validityInMonths | N | Validity period from valid from date (default: 12) |

### New-IEFPoliciesSamlRp

Creates a new Saml Relying Party endpoint

E.g.

```PowerShell
New-IefPoliciessamlRp -issuerName Contoso
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| epName | N | Used to construct B2C signup/signin endpoint name: B2C_1A_[epName]_SUSI (default: SAML) |
| signingKeyName | N | Used to construct B2C issuing cert policy key container: B2C_1A_[epName]SigningKey (default: same as epName) |
| sourceDirectory | N | Policy set source (default: ./) |
| extensionFile | N | Policy file where to create the TechnicalProfile (default: TrustFrameworkExtensions,xml) |
| configurationFilePath | N | Path for conf.json file (default: ./conf.json) |


### Remove-IEFPolicies

Delete a set of policies, whose name starts with the specified prefix from the tenant. User connfirmation will be requested before files are deleted.

For example, the following deletes all policies whose name starts with B2C_1A_V1. 

```PowerShell
Remove-IefPolicies V1
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| prefix | Y | Policy name prefix |

