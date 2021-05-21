# IEF Policies PowerShell module

PowerShell module for handling B2C custom journeys. Install it from the [PowerShell Galery](https://www.powershellgallery.com/packages/IefPolicies).

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


### Tenant setup

If you have never set up your B2C to use IEF policies you can use [my IEF setup website](https://b2ciefsetup.azurewebsites.net/) or follow [instructions provided in the official documentation](https://docs.microsoft.com/en-us/azure/active-directory-b2c/custom-policy-get-started) to do so. 

### Script Setup
1. In your PowerShell environment, install the module from the [PowerShell Galery](https://www.powershellgallery.com/packages/IefPolicies).
2. Optionally, add a conf.json file to the folder where you keep your xml policies. In this file you can define a value for the Prefix attribute (see below) as well as any other strings you wish to replace in your policies. **Note:** that the *yourtenant* string will be repalced automatically by the name of the tenant you are logged into when running the script.
1. Log in to your B2C tenant using Connect-AzureAD (V1) or Connect-IefPolicies (V2)
4. 


The script will use the following string replacement rules to apply your *appSettings.json* values.

| conf.json property | effect on policy source |
| -------- | ------ |
| Prefix | Inserted into the name of policies, e.g. *B2C_1A_MyTrustBase* where *My* is the value of the PolicyPrefix. Makes it easier to handle several sets of IEF policies in the tenant |
| *name* | Replace any occurrence of '{*name*}' in policy with the value of this attribute in conf.json |

### New-IEFPolicies

Use *New-IEFPolicies* function to download a set of polciies from the [Azure B2C StarterPack](https://github.com/Azure-Samples/active-directory-b2c-custom-policy-starterpack).

E.g.

```PowerShell
$dest = 'C:\LocalAccounts\policies'
New-IefPolicies -destinationPath $dest  `
```

| Property name | Required | Purpose |
| -------- | ------ | ----- |
| destinationPath | Y | Directory path where your xml policies are stored. Will be created if does not already exist |

### Upload-IEFPolicies

Use *Import-IEFPolicies* function to upload your IEF policies to the B2C tenant you are currently signed into.

E.g.

```PowerShell
Connect-IefPolicies -Tenant yourtenant.onmicrosoft.com
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
| destinationPath | Y | Directory path where your xml policies are stored. Must already exist |
| tenantName | N | Prefix part of your tenant name, e.g. *mytenant* represent *mytenant.onmicrosoft.com* |


