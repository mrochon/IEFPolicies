# IEF Policies PowerShell module

## Purpose
PowerShell script with several functions:
1. Download a starter pack (local, social, etc.)
1. Configure and upload policies
1.1 Modifies the xml of a set of IEF policies replacing them with values from the target B2C tenant and an optional configuration (useful if policies need to be used in different tenants - Dev, QA, etc. - with different REST urls, key names, etc.) 
1.2. Optionally uploads the files to a B2C tenants
1.3. Automatically updates the xml source with the name of the current tenant and the values for IEF App and Proxy app.
1.4. Updates xml source by replacing any {} bound strings with the values of attributes named with the same string in a configuration file
1.5. The updated source is stored in a separate directory before upload
2. Download existing custom journeys from a tenant
4. Signin to a tenant and obtain access tokens needed by the previous two commands.
5. Download a sample policies from the B2C Community site: [https://github.com/azure-ad-b2c/samples](https://github.com/azure-ad-b2c/samples)

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
| destinationPath | Y | Directory path where your xml policies are stored. Will be created if does not already exist |

### Connect-IEFPolicies

Use *Connect-IEFPolicies* cmdlet to sign in to your B2C tenant and obtain access tokens needed to execute other
cmdlets (*import-* and *export-*) in this module which require Graph access to the tenant.

E.g.

```PowerShell
Connect-IefPolicies -tenant myTenant  `
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| tenant | N | Name of tenant you want to sign into. '.onmicrosoft.com' is not required. This parameter is required
if you are signing in with an account which is an invited guest in your B2C tenant |

### import-IEFPolicies

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
will cause this cmdlet to inject *V1* into names of all policies, i.e. *B2C_1A_TrustFrameworkBase* will become *B2C_1A_V1TrustFrameworkBase*, etc. and any occurrence of *{MyRESTUrl}* in your xml policies to be replaced with
the above url.

E.g.

```PowerShell
Connect-IefPolicies -Tenant yourtenant
cd 'c:\your directory with the IEF policies'
Import-IEFPolicies 
```

Parameters:

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| sourceDirectory | Y | Directory path where your xml policies are stored |
| updatedSourceDirectory | N | Directory path where the policies updated by this script will be stored. Also used to prevent uploading unmodified policies |
| configurationFilePath | N | json file with additional replacement strings. Default: *.\conf.json*. The script will match any property in this file with a string with format *{<property name>}* and replace it with the value of the property |
| generateOnly | N | If used, the script will only generate policy files but not upload them to B2C |
| prefix | N | String inserted into the name of generated policies, e.g. the new base policy name will be *B2C_1A_XYZTrustFrameBase, where XYZ is the value of the provided prefix |

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


