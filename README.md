# IEF Policies PowerShell module

## Purpose
Aids in the development and deployment of the Azure B2C Identity Experience Policy xml files. Provides cmdlets to initiate a
new IEF project from the starter pack, augment it with additional sample-sourced files an deploy these to a tenant. The import cmdlet 
does on-the-fly substitution of source elements which vary from tenant to tenant, e.g. tenant name, IEFApplication and ProxyIEFApplication
application ids. Effectively, it allows the developer to deploy a starter pack to their B2C tenant with no code modification whatsoever.
It also makes it easier to re-deploy the same set of xml policies to multiple tenants (dev, test, etc.) by just adjusting the 
configuration file used by the import cmdlet.

[This repo](https://github.com/mrochon/B2CPipeline) shows how to use this module in an Azure Pipeline for continous deployment of custom journeys.

## Change log

| Name  | Description  |
|---|---|
| 2.2.4  | Added support for using {tenantId} as automatic replacement property ({Policy:TrustFrameworkTenantId} defined in IEF cannot be used in some policy properties) |
| 2.2.6  | Fixed: breaking change in MS Graph no longer returning tenantid in @odata.id |
| 2.2.7  | Modified: check conf.json validity to avoid null prefix setting |
|   | Improved: exception handling and error reporting |
| 2.2.8   | New: Remove-IefPolicies |
| 2.2.9   | New: Include sample conf.json in the Add-IefPoliciesSample operation |
| 2.2.10   | New: use values from secrets.json in same directory as conf file |


## Installation

This module can be instaled from the [PowerShell Gallery](https://www.powershellgallery.com/packages/IefPolicies/)

## Tenant setup

If you have never set up your B2C to use IEF policies you can use [the IEF setup website](https://aka.ms/b2csetup/) or follow [instructions provided in the official documentation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/custom-policy-get-started) to do so. 

## Cmdlets
### New-IEFPolicies

Use *New-IEFPolicies* function to download a set of policies from the [Azure B2C StarterPack](https://github.com/Azure-Samples/active-directory-b2c-custom-policy-starterpack). The cmdlet will prompt you for which of the starter packs (local, social, etc.)
to download.

E.g.

```PowerShell
$dest = 'C:\LocalAccounts\policies'
New-IefPolicies -destinationPath $dest  `
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| destinationPath | N | Directory path where your xml policies are stored. Will be created if does not already exist. Current directory is default |

### Connect-IEFPolicies

Use *Connect-IEFPolicies* cmdlet to sign in to your B2C tenant and obtain access tokens needed to execute other
cmdlets (*import-* and *export-*) in this module which require Graph access to the tenant. You can sign in either
interactively using user credentials or using application credentials (id and secret). For the former, the user must be
able to consent to permissions to operate on the trust framework policies, read domains used by the tenant and read applications registered in the tenant. To use application id and secret, [register an application using Graph](https://docs.microsoft.com/en-us/azure/active-directory-b2c/microsoft-graph-get-started) and grant it the following **application** permissions:
1. Application.Read.All 
2. Domain.Read.All
3. Organization.Read.All
4. Policy.ReadWrite.TrustFramework

For interactive signin you do **not** need to regsiter an application. This module is already registered as a multi-tenant app.

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

### Add-IEFPoliciesSample

Downloads policy files from one of the [B2C Community samples](https://github.com/azure-ad-b2c/samples). Only xml policy files are downloaded. Since these do not include the base xml file, and individual files are named uniquely to the sample type, you can **usually**
add them to an existing startr pack set. You should check which starter pack they are based on.

The following example add a single policy [from a specific B2C Community](https://github.com/azure-ad-b2c/samples/tree/master/policies/default-home-realm-discovery) to the current folder.

```PowerShell
Add-IefPoliciesSample 
cd 'c:\your directory with the IEF policies'
Add-IEFPoliciesSample default-home-realm-discovery
```

Parameters:

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| sampleName | Y | Name of the sub-folder within the *policies* folder which contains the sample |
| destinationPath | N | Directory to download the files to. Current directory by default. |
| owner | N | Git repo owner (default: Azure-ad-b2) |
| repository | N | Repo name (default: samples). IEF policies must be in a *policies* folder |


### Import-IEFPolicies 

Use *Import-IEFPolicies* function to upload your IEF policies to the B2C tenant you are currently signed into. 

Before uploading, the cmdlet will modify your xml files and store the new versions in the directory identified by the
*updatedSourceDirectory* (*.debug/<yourtenantName>* by default). The cmdlet will replace any occurrences of *yourtenant* string
(used in all StarterPolicies) with the name of the tenant you have logged in using *Connect-IefPolicies*. It will use a json configuration file (if provided, by default it will look for conf.json in the current directory) to make other changes as well. The Json
file defines values to be replaced in the original xml files. E.g.

```Json
{
    "Prefix": "V1",
    "MyRESTUrl": "https://mywebsite.com/users"
}
```
will cause this cmdlet to inject *V1* into names of all policies, i.e. *B2C_1A_TrustFrameworkBase* will become *B2C_1A_V1TrustFrameworkBase*, etc. and any occurrences of *{MyRESTUrl}* in your xml policies to be replaced with
the above url. If the same folder contains a secrets.json file, the attributes it defines will be added to those in the above configuration file. That allows you to configure your *.gitignore* file to **not** upload your 
secrets (e.g. AppInsights key used for journey debugging) to your repos.

E.g.

```PowerShell
Connect-IefPolicies -Tenant yourtenant
cd 'c:\your directory with the IEF policies'
Import-IEFPolicies 
```

Parameters:

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| sourceDirectory | N | Directory path where your xml policies are stored (default: current directory) |
| updatedSourceDirectory | N | Directory path where the policies updated by this script will be stored. Also used to prevent uploading unmodified policies. Default: ./debug/yourtenant subfolder. |
| configurationFilePath | N | json file with additional replacement strings. Default: *.\conf.json*. The script will match any property in this file with a string with format *{<property name>}* and replace it with the value of the property. See above about a *secrets.json* file |
| generateOnly | N | If used, the script will only generate policy files but not upload them to B2C |
| prefix | N | String inserted into the name of generated policies, e.g. the new base policy name will be *B2C_1A_XYZTrustFrameBase, where XYZ is the value of the provided prefix. Can also be set in the conf.json file |

### Export-IEFPolicies

Use *Export-IEFPolicies* function to download your IEF policies from the B2C tenant to a local folder.

E.g.

```PowerShell
$dest = 'C:\LocalAccounts\policies'
Connect-IefPolicies -Tenant yourtenant.onmicrosoft.com
Export-IEFPolicies  -destinationPath $dest  `
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| destinationPath | N | Directory path where your xml policies are stored. Must already exist |
| prefix | N | Download only policies whose name starts with *"B2C_1A_prefix"* |


