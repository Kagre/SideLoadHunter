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

Upon completion of the analysis, the results will be exported into CSV files to
 a folder named with the hostname value and current date.

Get-SideLoadDetect 
  Comparative analysis function designed to identify situations where a 
  System32/SysWow64 executable is located in a userland directory along with a 
  DLL that matches a System32/SysWow64 DLL name but is not signed by Microsoft.

Get-SusShimcache 
  To provide some detection capabilities for sideloaded executables that are no
  longer on disk, SusShimcache will analyze ShimCache entries for System32 and 
  SysWow64 executables have executed from a non-standard location.

Get-SusExec & Get-SusDLLs 
  Profiles a system to locate System32 and SysWow64 executables and DLL files 
  that do not exist within their default location.

.LINK
SideLoadHunter-PSv23.ps1

.LINK
SideLoadHunter-PSv45.ps1

.EXAMPLE
sideloadhunter.ps1

.NOTES
ToDo:
+ test for UNC pathing issues
#>param([switch]$AutoRun)

if(!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
  {throw 'Rerun Script as Administrator'}

#region Helper Functions
#feedback helper-function
if(!$AutoRun){
  function write-automated{
    param([parameter(ValueFromPipeline=$true)]$message)process{
    try{[Console]::WriteLine($message)}catch {$message|write-host}
  }}
}else{
  function write-automated([parameter(ValueFromPipeline=$true)]$message){process{}}
}

#hashing helper-function
$MD5    = [System.Security.Cryptography.HashAlgorithm]::Create('MD5')
$SHA1   = [System.Security.Cryptography.HashAlgorithm]::Create('SHA1')
$SHA256 = [System.Security.Cryptography.HashAlgorithm]::Create('SHA256')
function HashThis{
  param([byte[]]$bar)process{
  if($bar -eq $null){return $null}
  write-output (@{
    MD5    = [BitConverter]::ToString($MD5.ComputeHash($bar)).Replace('-','')
    SHA1   = [BitConverter]::ToString($SHA1.ComputeHash($bar)).Replace('-','')
    SHA256 = [BitConverter]::ToString($SHA256.ComputeHash($bar)).Replace('-','')
  })
}}

function OrganizeThis{
  param(
    [hashtable]$collection,
    [string[]]$keys,
    [parameter(ValueFromPipeline=$true)]
    $value
  )
  begin{
    if($keys.Count -lt 1){return}
    $at = $collection
    for($i=0;$i -lt $keys.Count - 1;$i++){
      $k = $keys[$i]
      if($at.$k -eq $null)
        {$at.$k = @{}}
      $at = $at.$k
    }
    $k = $keys[$i]
    if($at.$k -eq $null)
      {$at.$k = new-object System.Collections.ArrayList}
  }process{
    $null = $at.$k.Add($value)
  }
}
#endregion

write-automated "Creating output folder in current working directory"
$CollectionPath = ".\${ENV:COMPUTERNAME}_{0}" -f (Get-Date -format 'yyyyMMdd')
$CollectionPath = New-Item $CollectionPath -Type Directory -Force
$CollectionPath = $CollectionPath.FullName
$LRInvocation = $MyINvocation.InvocationName

write-automated "Gathering collection of userland DLLs"
if($PSVersionTable.PSVersion.Major -lt 4){
  . (join-path $PSScriptRoot 'SideLoadHunter-PSv23.ps1')
}else{
  . (join-path $PSScriptRoot 'SideLoadHunter-PSv45.ps1')
}

start-process $CollectionPath -Verb Open
