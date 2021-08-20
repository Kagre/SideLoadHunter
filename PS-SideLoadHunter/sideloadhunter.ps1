<#
.SYNOPSIS
Profiles the endpoint executables for sideloading.

.DESCRIPTION
SideLoadHunter-PS is a PowerShell script which will profile the endpoint for 
DLLs and executables within user’s profiles, System32, and SysWow64. Once the 
executables and DLLs have been profiled, comparative analysis is performed to 
identify possible evidence of DLL sideloading through file names, hash values, 
and internal names. Additionally, program execution artifacts data are parsed 
and analyzed for evidence of sideloaded executables that no longer exist on disk.

The main functions of SideLoadHunter are:
+Get-SideLoadDetect
+Get-SusShimcache
+Get-SusExecs
+Get-SusDlls

Upon completion of the analysis, the results will be exported into CSV files to a folder named with the hostname value and current date.

Get-SideLoadDetect – Comparative analysis function designed to identify situations where a System32/SysWow64 executable is located in a userland directory along with a DLL that matches a System32/SysWow64 DLL name but is not signed by Microsoft.

Get-SusShimcache – To provide some detection capabilities for sideloaded executables that are no longer on disk, SusShimcache will analyze ShimCache entries for System32 and SysWow64 executables have executed from a non-standard location.

Get-SusExec & Get-SusDLLs – Profiles a system to locate System32 and SysWow64 executables and DLL files that do not exist within their default location.


.LINK
SideLoadHunter-PSv23.ps1

.LINK
SideLoadHunter-PSv45.ps1

.EXAMPLE
sideloadhunter.ps1
#>param([switch]$AutoRun)

if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
  {Write-Output 'Running as Administrator!'}
else{
  Write-Output 'Rerun Script as Administrator'
  exit 
}

#Importing Get-Hash helper function for ps2 systems from jaredcatkinson. Credit: https://gist.github.com/jaredcatkinson/7d561b553a04501238f8e4f061f112b7
function Get-Hash
{
    <#
    .SYNOPSIS
    Get-Hash is a PowerShell Version 2 port of Get-FileHash that supports hashing files, as well as, strings.
    .PARAMETER InputObject
    This is the actual item used to calculate the hash. This value will support [Byte[]] or [System.IO.Stream] objects.
    .PARAMETER FilePath
    Specifies the path to a file to hash. Wildcard characters are permitted.
    .PARAMETER Text
    A string to calculate a cryptographic hash for.
    .PARAMETER Encoding
    Specified the character encoding to use for the string passed to the Text parameter. The default encoding type is Unicode. The acceptable values for this parameter are:
    - ASCII
    - BigEndianUnicode
    - Default
    - Unicode
    - UTF32
    - UTF7
    - UTF8
    .PARAMETER Algorithm
    Specifies the cryptographic hash function to use for computing the hash value of the contents of the specified file. A cryptographic hash function includes the property that it is not possible to find two distinct inputs that generate the same hash values. Hash functions are commonly used with digital signatures and for data integrity. The acceptable values for this parameter are:
    
    - SHA1
    - SHA256
    - SHA384
    - SHA512
    - MACTripleDES
    - MD5
    - RIPEMD160
    
    If no value is specified, or if the parameter is omitted, the default value is SHA256.
    For security reasons, MD5 and SHA1, which are no longer considered secure, should only be used for simple change validation, and should not be used to generate hash values for files that require protection from attack or tampering.
    .NOTES
    
    This function was adapted from https://p0w3rsh3ll.wordpress.com/2015/02/05/backporting-the-get-filehash-function/
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    .EXAMPLE
    Get-Hash -Text 'This is a string'
    .EXAMPLE
    Get-Hash -FilePath C:\This\is\a\filepath.exe
    #>

    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [string]
        [ValidateNotNullOrEmpty()]
        $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
        [string]
        [ValidateNotNullOrEmpty()]
        $Text,

        [Parameter(ParameterSetName = 'Text')]
        [string]
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Default', 'Unicode', 'UTF32', 'UTF7', 'UTF8')]
        $Encoding = 'Unicode',

        [Parameter()]
        [string]
        [ValidateSet("MACTripleDES", "MD5", "RIPEMD160", "SHA1", "SHA256", "SHA384", "SHA512")]
        $Algorithm = "SHA256"
    )

    switch($PSCmdlet.ParameterSetName)
    {
        File
        {
            try
            {
                $FullPath = Resolve-Path -Path $FilePath -ErrorAction Stop
                $InputObject = [System.IO.File]::OpenRead($FilePath)
                Get-Hash -InputObject $InputObject -Algorithm $Algorithm
            }
            catch
            {
                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $null
                }
            }
        }
        Text
        {
            $InputObject = [System.Text.Encoding]::$Encoding.GetBytes($Text)
            Get-Hash -InputObject $InputObject -Algorithm $Algorithm
        }
        Object
        {
            if($InputObject.GetType() -eq [Byte[]] -or $InputObject.GetType().BaseType -eq [System.IO.Stream])
            {
                # Construct the strongly-typed crypto object
                $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)

                # Compute file-hash using the crypto object
                [Byte[]] $computedHash = $Hasher.ComputeHash($InputObject)
                [string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''

                $retVal = New-Object -TypeName psobject -Property @{
                    Algorithm = $Algorithm.ToUpperInvariant()
                    Hash = $hash
                }

                $retVal
            }
        }
    }
}

Write-Host "Creating output folder in current working directory"
$CollectionPath =".\" + $ENV:COMPUTERNAME + "_" + (Get-Date).tostring("yyyyMMdd")
New-Item $CollectionPath -Type Directory -Force
$LRInvocation = $MyINvocation.InvocationName

Write-Host "Gathering collection of userland DLLs"
if($PSVersionTable.PSVersion.Major -lt 4){
  . (join-path $PSScriptRoot 'SideLoadHunter-PSv23.ps1')
}else{
  . (join-path $PSScriptRoot 'SideLoadHunter-PSv45.ps1')
}

start-process $CollectionPath -Verb Open
