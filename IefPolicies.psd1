@{

# Script module or binary module file associated with this manifest.
RootModule = 'IefPolicies.psm1'

# Version number of this module.
ModuleVersion = '2.1.1'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '037d0382-a043-46a7-b420-a8eae3f4734b'

# Author of this module
Author = 'Marius Rochon'

# Company or vendor of this module
CompanyName = 'Microsoft'

# Copyright statement for this module
Copyright = '(c) Marius Rochon. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Intelligently upload and download xml IEF policies used for custom journeys in Azure AD B2C. See https://github.com/mrochon/IEFPolicies'

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    'New-IEFPolicies'
    'Connect-IEFPolicies'
    'Export-IEFPolicies'
    'Import-IEFPolicies'
    'Add-IefPoliciesSample'
)

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{
        #Prerelease = 'alpha'

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    } # End of PSData hashtable

} # End of PrivateData hashtable

}

