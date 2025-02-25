<#
.LINK
sideloadhunter.ps1
#>param([switch]$AutoRun)

#Importing Get-Hash helper function for ps2 systems from jaredcatkinson. Credit: https://gist.github.com/jaredcatkinson/7d561b553a04501238f8e4f061f112b7
function Get-Hash{
<#
.SYNOPSIS
Get-Hash is a PowerShell Version 2 port of Get-FileHash that supports hashing files, as well as, strings.

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
  param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
    #This is the actual item used to calculate the hash. This value will support [Byte[]] or [System.IO.Stream] objects.
    $InputObject,

    [Parameter(Mandatory = $true, ParameterSetName = 'File')]
    [string]
    [ValidateNotNullOrEmpty()]
    #Specifies the path to a file to hash. Wildcard characters are permitted.
    $FilePath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Text')]
    [string]
    [ValidateNotNullOrEmpty()]
    #A string to calculate a cryptographic hash for.
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

  $retVal = New-Object -TypeName psobject -Property @{
    Algorithm = $Algorithm.ToUpperInvariant()
    Hash      = $null
  }
  switch($PSCmdlet.ParameterSetName){
   File{
    try{
      $FullPath = Resolve-Path -Path $FilePath -ErrorAction Stop
      $InputObject = [System.IO.File]::OpenRead($FilePath)
      $retVal = Get-Hash -InputObject $InputObject -Algorithm $Algorithm
    }catch {}
    break
   }
   
   Text{
    $InputObject = [System.Text.Encoding]::$Encoding.GetBytes($Text)
    $retVal = Get-Hash -InputObject $InputObject -Algorithm $Algorithm
    break
   }
   
   Object{
    if($InputObject -is [Byte[]] -or $InputObject -is [System.IO.Stream]){
       # Construct the strongly-typed crypto object
       $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)

       # Compute file-hash using the crypto object
       [Byte[]] $computedHash = $Hasher.ComputeHash($InputObject)
       [string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''

       $retVal.Hash = $hash
    }
    break
   }
  }
  return $retVal
}

#region Start Shimcache Functions
function Get-SusShimCachePS23
{
    ## Importing Helper Functions from PS-DigitalForensics https://github.com/davidhowell-tx/PS-DigitalForensics Credit: David Howell ##
    write-host "Analyzing Program Execution Evidence"
    $SusShimCacheArray = @()
    $count = 0


    # Initialize Array to store our data
    $EntryArray=@()
    $AppCompatCache=$Null

switch($PSCmdlet.ParameterSetName) {
	"Path" {
		if (Test-Path -Path $Path) {
			# Get the Content of the .reg file, only return lines with Hexadecimal values on them, and remove the backslashes, spaces, and wording at the start
			$AppCompatCache = Get-Content -Path $Path | Select-String -Pattern "[A-F0-9][A-F0-9]," | ForEach-Object { $_ -replace "(\\|,|`"AppCompatCache`"=hex:|\s)","" }
			# Join all of the hexadecimal into one big string
			$AppCompatCache = $AppCompatCache -join ""
			# Convert the Hexadecimal string to a byte array
			$AppCompatCache = $AppCompatCache -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [System.Convert]::ToByte( $_, 16 ) }
			# Thanks to beefycode for that code snippet: http://www.beefycode.com/post/Convert-FromHex-PowerShell-Filter.aspx
		}
	}
	
	Default {
		if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
			New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
		}
		# This command gets the current AppCompat Cache, and returns it in a Byte Array.
		if (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatCache\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache) {
			# This is the Windows 2003 and later location of AppCompatCache in the registry
			$AppCompatCache = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatCache\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache
            $AppCompatPath = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatCache\' -ErrorAction SilentlyContinue 
            $AppCompatPath = $AppCompatPath.PSPath.ToString()
		} else {
			# If the normal area is not available, try the Windows XP location.
			# Note, this piece is untested as I don't have a Windows XP system to work with.
			$AppCompatCache = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache
            $AppCompatPath = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache' -ErrorAction SilentlyContinue 
            $AppCompatPath = $AppCompatPath.PSPath.ToString()
		}
	}
}

Write-Host "Collecting Shimcache for $env:ComputerName"
write-host $AppCompatPath


if ($AppCompatCache -ne $null) {

	# Initialize a Memory Stream and Binary Reader to scan through the Byte Array
	$MemoryStream = New-Object System.IO.MemoryStream(,$AppCompatCache)
	$BinReader = New-Object System.IO.BinaryReader $MemoryStream
	$UnicodeEncoding = New-Object System.Text.UnicodeEncoding
	$ASCIIEncoding = New-Object System.Text.ASCIIEncoding

	# The first 4 bytes of the AppCompatCache is a Header.  Lets parse that and use it to determine which format the cache is in.
	$Header = ([System.BitConverter]::ToString($BinReader.ReadBytes(4))) -replace "-",""

	switch ($Header) {
    #Windows 8
        "80000000" {
			$Offset = [System.BitConverter]::ToUInt32($AppCompatCache[0..3],0)
			$Tag = [System.BitConverter]::ToString($AppCompatCache[$Offset..($Offset+3)],0) -replace "-",""
			
			if ($Tag -eq "30307473" -or $Tag -eq "31307473") {
				# 64-bit
				$MemoryStream.Position = ($Offset)
				
				# Complete loop to parse each entry
				while ($MemoryStream.Position -lt $MemoryStream.Length) {
					# I've noticed some random gaps of space in Windows 8 AppCompatCache
					# We need to verify the tag for each entry
					# If the tag isn't correct, read through until the next correct tag is found
					
					# First 4 Bytes is the Tag
					$EntryTag = [System.BitConverter]::ToString($BinReader.ReadBytes(4),0) -replace "-",""
					
					if ($EntryTag -eq "30307473" -or $EntryTag -eq "31307473") {
						# Skip 4 Bytes
						$BinReader.ReadBytes(4) | Out-Null
						$TempObject = "" | Select-Object -Property Name, Time
						$JMP = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$SZ = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($SZ + 2))
						$BinReader.ReadBytes(8) | Out-Null
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$BinReader.ReadBytes(4) | Out-Null
						$TempObject
					} else {
						# We've found a gap of space that isn't an AppCompatCache Entry
						# Perform a loop to read 1 byte at a time until we find the tag 30307473 or 31307473 again
						$Exit = $False
						
						while ($Exit -ne $true) {
							$Byte1 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
							if ($Byte1 -eq "30" -or $Byte1 -eq "31") {
								$Byte2 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
								if ($Byte2 -eq "30") {
									$Byte3 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
									if ($Byte3 -eq "74") {
										$Byte4 = [System.BitConverter]::ToString($BinReader.ReadBytes(1),0) -replace "-",""
										if ($Byte4 -eq "73") {
											# Verified a correct tag for a new entry
											# Scroll back 4 bytes and exit the scan loop
											$MemoryStream.Position = ($MemoryStream.Position - 4)
											$Exit = $True
										} else {
											$MemoryStream.Position = ($MemoryStream.Position - 3)
										}
									} else {
										$MemoryStream.Position = ($MemoryStream.Position - 2)
									}
								} else {
									$MemoryStream.Position = ($MemoryStream.Position - 1)
								}
							}
						}
					}
				}
				
			} elseif ($Tag -eq "726F7473") {
				# 32-bit
				
				$MemoryStream.Position = ($Offset + 8)
				
				# Complete loop to parse each entry
				while ($MemoryStream.Position -lt $MemoryStream.Length) {
					#Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property Name, Time
					
					$JMP = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$SZ = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($SZ))
					$EntryArray += $TempObject
				}
			}
			#$EntryArray | Select Name, Time
		}
		# BADC0FEE in Little Endian Hex - Windows 7 / Windows 2008 R2
		"EE0FDCBA" {
			# Number of Entries at Offset 4, Length of 4 bytes
			$NumberOfEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			# Move BinReader to the Offset 128 where the Entries begin
			$MemoryStream.Position=128
			
			# Get some baseline info about the 1st entry to determine if we're on 32-bit or 64-bit OS
			$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
			$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
			$Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			
			# Move Binary Reader back to the start of the entries
			$MemoryStream.Position=128
			
			if (($MaxLength - $Length) -eq 2) {
				if ($Padding -eq 0) {
					# 64-bit Operating System
					
					# Use the Number of Entries it says are available and iterate through this loop that many times
					for ($i=0; $i -lt $NumberOfEntries; $i++) {
						# Parse the metadata for the entry and add to a custom object
						$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Padding, Offset0, Offset1, Time, Flag0, Flag1
						$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Offset0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Offset1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# calculate the modified date/time in this QWORD
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# Use the Offset and the Length to read the File Name
						$TempObject.Name = ($UnicodeEncoding.GetString($AppCompatCache[$TempObject.Offset0..($TempObject.Offset0+$TempObject.Length-1)])) -replace "\\\?\?\\",""
						# Seek past the 16 Null Bytes at the end of the entry header
						# This is Blob Size and Blob Offset according to: https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf
						$Nothing = $BinReader.ReadBytes(16)
						$EntryArray += $TempObject
					}
				} else {
					# 32-bit Operating System
					
					# Use the Number of Entries it says are available and iterate through this loop that many times
					for ($i=0; $i -lt $NumberOfEntries; $i++) {
						# Parse the metadata for the entry and add to a custom object
						$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Offset, Time, Flag0, Flag1
						$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
						$TempObject.Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# calculate the modified date/time in this QWORD
						$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
						$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
						# Use the Offset and the Length to read the File Name
						$TempObject.Name = ($UnicodeEncoding.GetString($AppCompatCache[$TempObject.Offset0..($TempObject.Offset0+$TempObject.Length-1)])) -replace "\\\?\?\\",""
						# Seek past the 16 Null Bytes at the end of the entry header
						# This is Blob Size and Blob Offset according to: https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf
						$Nothing = $BinReader.ReadBytes(16)
						$EntryArray += $TempObject
					}
					
				}
			}
			
			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			#$EntryArray | Format-Table -AutoSize -Property Name, Time, Flag0, Flag1
		}
		
		# BADC0FFE in Little Endian Hex - Windows XP 64-bit, Windows Server 2003 through Windows Vista and Windows Server 2008
		"FE0FDCBA" {
		#### THIS AREA NEEDS WORK, TESTING, ETC.
		
			# Number of Entries at Offset 4, Length of 4 bytes
			$NumberOfEntries = [System.BitConverter]::ToUInt32($AppCompatCache[4..7],0)
			
			# Lets analyze the padding of the first entry to determine if we're on 32-bit or 64-bit OS
			$Padding = [System.BitConverter]::ToUInt32($AppCompatCache[12..15],0)
			
			# Move BinReader to the Offset 8 where the Entries begin
			$MemoryStream.Position=8
			
			if ($Padding -eq 0) {
				# 64-bit Operating System
				
				# Use the Number of Entries it says are available and iterate through this loop that many times
				for ($i=0; $i -lt $NumberOfEntries; $i++) {
					# Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property Name, ModifiedTime, FileSize, Executed
					$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$BinReader.ReadBytes(4) | Out-Null
					$TempObject.ModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$TempObject.FileSize = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
					$TempObject.Name = $Unicode.GetString($AppCompatCache[$Offset..($Offset + $Length)])
					if ($TempObject.FileSize -gt 0) {
						$TempObject.Executed = $True
					} else {
						$TempObject.Executed = $False
					}
					$EntryArray += $TempObject
					Remove-Variable Length
					Remove-Variable Padding
					Remove-Variable MaxLength
					Remove-Variable Offset
					Remove-Variable TempObject
				}
			} else {
				# 32-bit Operating System
				
				# Use the Number of Entries it says are available and iterate through this loop that many times
				for ($i=0; $i -lt $NumberOfEntries; $i++) {
					# Parse the metadata for the entry and add to a custom object
					$TempObject = "" | Select-Object -Property FileName, ModifiedTime, FileSize
					$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.ModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
					$TempObject.FileSize = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
					$TempObject.FileName = $Unicode.GetString($AppCompatCache[$Offset..($Offset + $Length)])
					$EntryArray += $TempObject
					Remove-Variable Length
					Remove-Variable MaxLength
					Remove-Variable Offset
					Remove-Variable TempObject
				}
			}
			
			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			#$EntryArray | Format-Table -AutoSize -Property Name, Time, Flag0, Flag1
		}
		
		# DEADBEEF in Little Endian Hex - Windows XP 32-bit
		"EFBEADDE" {
			# Number of Entries
			$NumberOfEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			# Number of LRU Entries
			$NumberOfLRUEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			# Unknown
			$BinReader.ReadBytes(4) | Out-Null
			# LRU Array Start
			for ($i=0; $i -lt $NumberOfLRUEntries; $i++) {
				$LRUEntry
			}
			
			# Move to the Offset 400 where the Entries begin
			$MemoryStream.Position=400
			
			# Use the Number of Entries it says are available and iterate through this loop that many times
			for ($i=0; $i -lt $NumberOfEntries; $i++) {
				# Parse the metadata for the entry and add to a custom object
				$TempObject = "" | Select-Object -Property Name, LastModifiedTime, Size, LastUpdatedTime
				# According to Mandiant paper, MAX_PATH + 4 (260 + 4, in unicode = 528 bytes)
				$TempObject.Name = ($UnicodeEncoding.GetString($BinReader.ReadBytes(528))) -replace "\\\?\?\\",""
				$TempObject.LastModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				# I'm not fully confident in the Size value without having a Windows XP box to test. Mandiant Whitepaper only says Large_Integer, QWORD File Size. Harlan Carveys' script parses as 2 DWORDS.
				$TempObject.FileSize = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
				$TempObject.LastUpdatedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				$EntryArray += $TempObject
			}
			
			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			#return $EntryArray
		}

	}

    foreach($Entry in $EntryArray)
    {
           $ShimFileName = Split-Path $Entry.Name -leaf
           $check=""
           $check64=""
           if(@($64BinsOnly| %{$_.InputObject}) -contains $ShimFileName)
           {
                [array]$check = $Sys64BinList | where {$_.Name -eq $ShimFileName}
                if($check.Length -gt 1)
                {
                        foreach($bin in $check)
                        {
                            [string]$checkps2 = @($bin| %{$_.FullName})
                            [string]$stringpath = $Entry.Name
                            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                            {
           
                                $SusShimCacheObject = New-Object psobject
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $stringpath
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                                $SusShimCacheArray += $SusShimCacheObject
                            }
                        }
                 }
                 if($check.Length -eq 1)
                 {
                        
                        [string]$stringpath = $Entry.Name
                        if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                        {
           
                            $SusShimCacheObject = New-Object psobject
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $Entry.Name
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                            $SusShimCacheArray += $SusShimCacheObject
                        }
                 }
           }
           elseif (@($Sys32BinList| %{$_.Name}) -contains $ShimFileName)
           {
                [array]$check = $Sys32BinList | where {$_.Name -eq $ShimFileName}
                [string]$checkps2 = @($check| %{$_.FullName})
                if (@($Sys64BinList| %{$_.Name}) -contains $ShimFileName)
                {
                    [array]$check64 = $Sys64BinList | where {$_.Name -eq $ShimFileName}
                    [string]$check64ps2 = @($check64 | %{$_.FullName})
                }
                
                if($check.Length -gt 1)
                {
                        
                        foreach($bin in $check)
                        {
                            [string]$stringpath = $bin.Name
                            [string]$checkps2 = @($bin| %{$_.FullName})
                            if($check64)
                            {
                                if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0) -and ($checkps264.ToLower() -ne $stringpath.ToLower()))
                                {
                                $SusShimCacheObject = New-Object psobject
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.Name
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSys64Match" -Value $check64ps2
                                $SusShimCacheArray += $SusShimCacheObject
                                }
                            }
                            elseif (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                            {
                                
                                $SusShimCacheObject = New-Object psobject
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.Name
                                $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                                $SusShimCacheArray += $SusShimCacheObject
                             }
                        }
                }
                if($check.Length -eq 1)
                {
                        [string]$stringpath = $Entry.Name
                        
                        if($check64)
                        {
                                                      
                            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0) -and ($check64ps2.ToLower() -ne $stringpath.ToLower()))
                            {
      
                            $SusShimCacheObject = New-Object psobject
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $Entry.Name
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSys64Match" -Value $check64ps2
                            $SusShimCacheArray += $SusShimCacheObject
                            }
                        }
                        elseif (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                        {

                            $SusShimCacheObject = New-Object psobject
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $Entry.Name
                            $SusShimCacheObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                            $SusShimCacheArray += $SusShimCacheObject
                        }
                }
           }
            
    }
    $SusShimCacheArray | Export-csv -NoTypeInformation $CollectionPath\SuspiciousShimCacheEntries.csv  
}

}
##End Shimcache Functions
#endregion

#region Start side load detects
Function Get-SideLoadDetectsPS23
{
$SideLoadDetectArray = @()
$count = 0

foreach($UserLandDLL in $UserLandDLLs)
{
    
   if (@($Sys32DLLList| %{$_.Name}) -contains $UserLandDLL.Name)
   {
        $UserLandExes=""
        [array]$check = $Sys32DLLList | where {$_.Name -eq $UserLandDLL.Name}
        if($check.Length -gt 1)
        {
            foreach($dll in $check)
            {
                $DllSigResult = Get-AuthenticodeSignature $dll.FullName -ErrorAction Ignore
                $CertSubject = Get-AuthenticodeSignature $dll.FullName | ` Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
                $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                if ($CertSubject.Subject -ne $MSSubject)
                {
                    $UserLandExes = Get-ChildItem $dll.Directory -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue
                    foreach($UserLandExe in $UserLandExes)
                    {
                        if($UserLandExe.VersionInfo.OriginalFileName)
                        {
                            [string]$UserLandExeOGName = $UserLandExe.VersionInfo.OriginalFileName.replace(".MUI","")
                        }
                       
                       
                        if ((@($Sys32BinList| %{$_.Name}) -contains $UserLandExeOGName) -or (@($Sys32BinList| %{$_.Name}) -contains $UserLandExe.Name))
                        {
                            if ($PSVersionTable.PSVersion.Major -lt 4)
                            {
                                $DllHash = Get-Hash -Algorithm MD5 -FilePath $UserLandDLL.FullName -ErrorAction SilentlyContinue
                            }
                            else
                            {
                                $DllHash = Get-FileHash -Algorithm MD5 $UserLandDLL.FullName -ErrorAction SilentlyContinue
                            }
                            
                            $SideLoadDetectObject = New-Object psobject
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExe" -Value $UserLandExe.FullName
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExeOriginalFilename" -Value $UserLandExeOGName
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadDLL" -Value $dll.FullName
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "DLLHash" -Value $dll.Hash
                            $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SigStatus" -Value $DllSigResult.Status
                            $SideLoadDetectArray += $SideLoadDetectObject
                        }
                    }
                }
            }
        }
        if($check.Length -eq 1)
        {

               $DllSigResult = Get-AuthenticodeSignature $UserLandDLL.FullName -ErrorAction Ignore
               $CertSubject = Get-AuthenticodeSignature $UserLandDLL.FullName | ` Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
               $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"     
               $UserLandExes = Get-ChildItem $UserLandDLL.Directory -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue
               foreach($UserLandExe in $UserLandExes)
               {
                [string]$UserLandExeName = @($UserLandExe| %{$_.Name})
                [string]$UserLandExeFullName = @($UserLandExe| %{$_.FullName})
                
                if($UserLandExe.VersionInfo.OriginalFileName)
                {
                    [string]$UserLandExeOGName = $UserLandExe.VersionInfo.OriginalFileName.replace(".MUI","")
                }
                
                                
                if ($CertSubject.Subject -ne $MSSubject)
                {

                    if ((@($Sys32BinList| %{$_.Name}) -contains $UserLandExeOGName) -or (@($Sys32BinList| %{$_.Name}) -contains $UserLandExe.Name))
                    {
                       
                        if ($PSVersionTable.PSVersion.Major -lt 4)
                            {
                                $DllHash = Get-Hash -Algorithm MD5 -FilePath $UserLandDLL.FullName -ErrorAction SilentlyContinue
                            }
                            else
                            {
                                $DllHash = Get-FileHash -Algorithm MD5 $UserLandDLL.FullName -ErrorAction SilentlyContinue
                            }
                        
                        $SideLoadDetectObject = New-Object psobject
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExe" -Value $UserLandExeFullName
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadExeOriginalFilename" -Value $UserLandExeOGName
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SideLoadDLL" -Value $UserLandDLL.FullName
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "DLLHash" -Value $DllHash.Hash
                        $SideLoadDetectObject | Add-Member -MemberType NoteProperty -Name "SigStatus" -Value $DllSigResult.Status
                        $SideLoadDetectArray += $SideLoadDetectObject
                        
                    }
                 }
               }
                        
        }
    }
    

}


$SideLoadDetectArray | Export-csv -NoTypeInformation $CollectionPath\SideLoadDetections.csv


}
## End Sideload Detects
#endregion

#region Start Suspicious Bin Audit
Function Get-SusExecsPS23
{
write-host "Analyzing binaries in userland"
$SusBinListArray = @()
$ErrorActionPreference = "SilentlyContinue"
$count = 0

#Start Find possible sideloaded exes
foreach($UserLandBin in $UserLandBins)
{
    
     if($UserLandBin.VersionInfo.OriginalFileName)
    {
        [string]$UserLandExeOGName = $UserLandBin.VersionInfo.OriginalFileName.replace(".MUI","")
    }      
    if((@($64BinsOnly| %{$_.InputObject}) -contains $UserLandExeOGName) -or (@($64BinsOnly| %{$_.InputObject}) -contains $UserLandBin.Name))
    {
        if (@($Sys64BinList| %{$_.Name}) -contains $UserLandExeOGName) 
       { 
            [array]$check = $Sys64BinList | where {$_.Name -eq $UserLandExeOGName}
       }
       else
       {
            [array]$check = $Sys64BinList | where {$_.Name -eq $UserLandBin.Name}
       }
       if($check.Length -gt 1)
       {
            foreach($bin in $check)
            {
                
                [string]$stringpath = $UserLandBin.FullName
                [string]$checkps2 = @($check| %{$_.FullName})
                if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $UserLandHash = Get-Hash -Algorithm MD5 -FilePath $bin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $UserLandHash = Get-FileHash -Algorithm MD5 $bin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
                    $SusBinListObject = New-Object psobject
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.FullName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $bin.VersionInfo.OriginalFileName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $UserLandHash.Hash
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64BinHash.Hash
                    $SusBinListArray += $SusBinListObject
                }
            }
       }
       if($check.Length -eq 1)
       {
            [string]$stringpath = $UserLandBin.FullName
            [string]$checkps2 = @($check| %{$_.FullName})
            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $UserLandHash = Get-Hash -Algorithm MD5 -FilePath $UserLandBin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $UserLandHash = Get-FileHash -Algorithm MD5 $UserLandBin.FullName -ErrorAction SilentlyContinue
                        $Sys64BinHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
            $SusBinListObject = New-Object psobject
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $UserLandBin.FullName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $UserLandBin.VersionInfo.OriginalFileName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $UserLandHash.Hash
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64BinHash.Hash
            $SusBinListArray += $SusBinListObject
            }
       }
    }
    elseif ((@($Sys32BinList| %{$_.Name}) -contains $UserLandExeOGName) -or (@($Sys32BinList| %{$_.Name}) -contains $UserLandBin.Name))
    {
       if (@($Sys32BinList| %{$_.Name}) -contains $UserLandExeOGName)
       {
            [array]$check = $Sys32BinList | where {$_.Name -eq $UserLandExeOGName}
       }
       else
       {
            [array]$check = $Sys32BinList | where {$_.Name -eq $UserLandBin.Name}
       }
       
              
       if($check.Length -gt 1)
       {
            foreach($bin in $check)
            {
                [string]$stringpath = $UserLandBin.FullName
                [string]$checkps2 = @($check| %{$_.FullName})
                if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $UserLandHash = Get-Hash -Algorithm MD5 -FilePath $bin.FullName -ErrorAction SilentlyContinue
                        $Sys32BinHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $UserLandHash = Get-FileHash -Algorithm MD5 $bin.FullName -ErrorAction SilentlyContinue
                        $Sys32BinHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
                    $SusBinListObject = New-Object psobject
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $bin.FullName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $bin.VersionInfo.OriginalFileName
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $UserLandHash.Hash
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                    $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32BinHash.Hash
                    $SusBinListArray += $SusBinListObject
                }
            }
       }
       if($check.Length -eq 1)
       {
            [string]$stringpath = $UserLandBin.FullName
            [string]$checkps2 = @($check| %{$_.FullName})
            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $UserLandHash = Get-Hash -Algorithm MD5 -FilePath $UserLandBin.FullName -ErrorAction SilentlyContinue
                        $Sys32BinHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $UserLandHash = Get-FileHash -Algorithm MD5 $UserLandBin.FullName -ErrorAction SilentlyContinue
                        $Sys32BinHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
            $SusBinListObject = New-Object psobject
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $UserLandBin.FullName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeOGName" -Value $UserLandBin.VersionInfo.OriginalFileName
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $UserLandHash.Hash
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
            $SusBinListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32BinHash.Hash
            $SusBinListArray += $SusBinListObject
            }
       }
       
       
    }

    
    

}


$SusBinListArray | Export-csv -NoTypeInformation $CollectionPath\SuspiciousBinsList.csv

# End of PRocess Dump
}
## End Suspicious Bin Audit
#endregion

#region Start Suspicious DLL Audit
Function Get-SusDllsPS23
{
write-host "Analyzing DLLs in userland"
$SusDllListArray = @()
$ErrorActionPreference = "SilentlyContinue"
$count = 0

#Start Find possible sideloaded Dlls
foreach($UserLandDll in $UserLandDLLs)
{    
    if((@($64DllsOnly | %{$_.InputObject}) -contains $UserLandDll.Name))
    {
      $DllSigResult = Get-AuthenticodeSignature $UserLandDll.FullName -ErrorAction Ignore
      $CertSubject = Get-AuthenticodeSignature $UserLandDll.FullName | ` Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
      $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
      if ($CertSubject.Subject -ne $MSSubject)
      {  
       [array]$check = $Sys64DLLList | where {$_.Name -eq $UserLandDll.Name}
       
       if($check.Length -gt 1)
       {
            foreach($bin in $check)
            {
                
                [string]$stringpath = $UserLandDll.FullName
                [string]$checkps2 = @($bin| %{$_.FullName})
                if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $UserLandHash = Get-Hash -Algorithm MD5 -FilePath $stringpath -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $UserLandHash = Get-FileHash -Algorithm MD5 $stringpath -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
                    $SusDllListObject = New-Object psobject
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDll" -Value $stringpath
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDllHash" -Value $UserLandHash.Hash
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64DllHash.Hash
                    $SusDllListArray += $SusDllListObject
                }
            }
       }
       if($check.Length -eq 1)
       {
            [string]$stringpath = $UserLandDll.FullName
            [string]$checkps2 = @($check| %{$_.FullName})
            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    { 
                        $UserLandHash = Get-Hash -Algorithm MD5 -FilePath $UserLandDll.FullName -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $UserLandHash = Get-FileHash -Algorithm MD5 $UserLandBin.FullName -ErrorAction SilentlyContinue
                        $Sys64DllHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
            $SusDllListObject = New-Object psobject
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDll" -Value $UserLandDll.FullName
            
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDllHash" -Value $UserLandHash.Hash
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys64DllHash.Hash
            $SusDllListArray += $SusDllListObject
            }
       }
      }
    }
    elseif (@($Sys32DLLList| %{$_.Name}) -contains $UserLandDll.Name)
    {
      $DllSigResult = Get-AuthenticodeSignature $UserLandDll.FullName -ErrorAction Ignore
      $CertSubject = Get-AuthenticodeSignature $UserLandDll.FullName | ` Select-Object -Property @{Name='Subject';Expression={($_.SignerCertificate.Subject)}}
      $MSSubject = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
      if ($CertSubject.Subject -ne $MSSubject)
      {  
       [array]$check = $Sys32DLLList | where {$_.Name -eq $UserLandDll.Name}
                    
       if($check.Length -gt 1)
       {
            foreach($bin in $check)
            {
                [string]$stringpath = $UserLandDll.FullName
                [string]$checkps2 = @($bin | %{$_.FullName})
                if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
                {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $UserLandHash = Get-Hash -Algorithm MD5 -FilePath $bin.FullName -ErrorAction SilentlyContinue
                        $Sys32DllHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $UserLandHash = Get-FileHash -Algorithm MD5 $bin.FullName -ErrorAction SilentlyContinue
                        $Sys32DllHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
                    $SusDllListObject = New-Object psobject
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDll" -Value $bin.FullName
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusDllHash" -Value $UserLandHash.Hash
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
                    $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32DllHash.Hash
                    $SusDllListArray += $SusDllListObject
                }
            }
       }
       if($check.Length -eq 1)
       {
            [string]$stringpath = $UserLandDll.FullName
            [string]$checkps2 = @($check| %{$_.FullName})
            if (($checkps2.ToLower() -ne $stringpath.ToLower()) -and ($stringpath.Length -gt 0))
            {
           
                    if ($PSVersionTable.PSVersion.Major -lt 4)
                    {
                        $UserLandHash = Get-Hash -Algorithm MD5 -FilePath $UserLandDll.FullName -ErrorAction SilentlyContinue
                        $Sys32DllHash = Get-Hash -Algorithm MD5 -FilePath $checkps2 -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        $UserLandHash = Get-FileHash -Algorithm MD5 $UserLandDll.FullName -ErrorAction SilentlyContinue
                        $Sys32DllHash = Get-FileHash -Algorithm MD5 $checkps2 -ErrorAction SilentlyContinue
                    }
            $SusDllListObject = New-Object psobject
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $env:COMPUTERNAME
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusExe" -Value $UserLandDll.FullName
            
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "SusExeHash" -Value $UserLandHash.Hash
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysMatch" -Value $checkps2
            $SusDllListObject | Add-Member -MemberType NoteProperty -Name "WinSysHash" -Value $Sys32DllHash.Hash
            $SusDllListArray += $SusDllListObject
            }
       }
      }
       
    }

    
    

}


$SusDLLListArray | Export-csv -NoTypeInformation $CollectionPath\SuspiciousDllsList.csv


}
## End suspicious DLL Audit
#endregion

$ErrorActionPreference = "SilentlyContinue"
$Sys32BinList = Get-ChildItem $env:SystemRoot\system32\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue | Select Name, FullName
$Sys64BinList = Get-ChildItem $env:SystemRoot\syswow64\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue | Select Name, FullName
$PS2_32Test = @($Sys32BinList | %{$_.Name})
$PS2_64Test = @($Sys64BinList | %{$_.Name})
$64BinsOnly = Compare-Object -ReferenceObject $PS2_64Test -DifferenceObject $PS2_32Test  | Where-Object {$_.SideIndicator -eq "<="} | Select InputObject
$UserLandBins = Get-ChildItem -Path $env:HOMEDRIVE\Users , $env:HOMEDRIVE\ProgramData, $env:HOMEDRIVE\Intel, $env:HOMEDRIVE\Recovery -Force -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".exe")} -ErrorAction SilentlyContinue 
$Sys32DLLList = Get-ChildItem $env:SystemRoot\system32\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".dll")} -ErrorAction SilentlyContinue | Select Name, FullName
$Sys64DLLList = Get-ChildItem $env:SystemRoot\syswow64\ -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".dll")} -ErrorAction SilentlyContinue | Select Name, FullName
$PS2_32Dlls = @($Sys32DLLList | %{$_.Name})
$PS2_64Dlls = @($Sys64DLLList | %{$_.Name})
$64DllsOnly = Compare-Object -ReferenceObject $PS2_64Dlls -DifferenceObject $PS2_32Dlls  | Where-Object {$_.SideIndicator -eq "<="} | Select InputObject
$UserLandDLLs = Get-ChildItem -Path $env:HOMEDRIVE\Users , $env:HOMEDRIVE\ProgramData, $env:HOMEDRIVE\Intel, $env:HOMEDRIVE\Recovery -Force -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Extension -like ".dll")} -ErrorAction SilentlyContinue 
Get-SideLoadDetectsPS23
Get-SusShimCachePS23
Get-SusExecsPS23
Get-SusDllsPS23
