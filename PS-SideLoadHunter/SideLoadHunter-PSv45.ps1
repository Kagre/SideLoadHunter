<#
.LINK
sideloadhunter.ps1
#>param([switch]$AutoRun)

#region Start side load detects
Function Get-SideLoadDetectsPS45{
<#
.DESCRIPTION
Get-SideLoadDetect 
  Comparative analysis function designed to identify situations where a 
  System32/SysWow64 executable is located in a userland directory along with a 
  DLL that matches a System32/SysWow64 DLL name but is not signed by Microsoft.

.NOTES
ToDo:
+ Confirm process accounts for any unsigned system DLL in a user folder
#>
  param(
    [string]
    #Specifies the path to the new report file
    $Destination = (join-path $CollectionPath 'SideLoadDetections.csv')
  )
  
  $UserLandBins.where{$_.Name.ToUpperInvariant() -in $SysBinNames -or ($_.OGName -ne $null -and $_.OGName.ToUpperInvariant() -in $SysBinNames)}.foreach{
    $uBIN  = $_
    $uDLLs = $InfoByPathByType.($uBIN.Path).dll
    $uDLLs.where{!$_.SaysMS -and $_.Name.ToUpperInvariant() -in $SysDLLNames}.foreach{
      $uDLL = $_
      write-output ([PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        SideLoadExe  = $uBIN.FullName
        SideLoadExeOriginalFilename = $uBIN.File.VersionInfo.OriginalFileName
        SideLoadDLL  = $uDLL.FullName
        DLLHash      = $uDLL.Hash.MD5
        SigStatus    = $uDLL.Sig.Status
      })
    }
  } | Export-csv -NoTypeInformation $Destination
}
#endregion Sideload Detects

#region Start Shimcache Functions
function Get-SusShimCachePS45{
<#
.DESCRIPTION
Get-SusShimcache 
  To provide some detection capabilities for sideloaded executables that are no
  longer on disk, SusShimcache will analyze ShimCache entries for System32 and 
  SysWow64 executables have executed from a non-standard location.
#>
  param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
    [string]
    #Use this parameter to run against a .reg file export of the Shim Cache.
    $Path
  )

  ## Importing Helper Functions from PS-DigitalForensics https://github.com/davidhowell-tx/PS-DigitalForensics Credit: David Howell ##
  write-host "Analyzing Program Execution Evidence"
  # Initialize Array to store our data
  $ShimCacheBins  = new-object System.Collections.ArrayList
  $AppCompatCache = $Null

  switch($PSCmdlet.ParameterSetName) {
    "Path" {
      if (Test-Path -Path $Path) {
        # Get the Content of the .reg file, only return lines with Hexadecimal values on them, and remove the backslashes, spaces, and wording at the start
        $hex = (get-content -Path $Path -raw) -replace '(.|\s)*?"AppCompatCache"=hex:([^"]*)(.|\s)*','$2' -replace '[^0-9a-f]',''
        $AppCompatCache = new-object byte[] ($hex.Length/2)
        for($i=0;$i -lt $hex.Length;$i+=2){
          $AppCompatCache[$i/2] = [System.Convert]::ToByte($hex.Substring($i,2),16)
        }
      }
    }
    
    Default {
      if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
        New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
      }
      # This command gets the current AppCompat Cache, and returns it in a Byte Array.
      push-location 'HKLM:\System\CurrentControlSet\Control\Session Manager'
      if(test-path '.\AppCompatCache'){
        # This is the Windows 2003 and later location of AppCompatCache in the registry
        $AppCompatCache = (Get-ItemProperty '.\AppCompatCache').AppCompatCache
      }elseif(test-path '.\AppCompatibility\AppCompatCache'){
        # If the normal area is not available, try the Windows XP location.
        # Note, this piece is untested as I don't have a Windows XP system to work with.
        $AppCompatCache = (Get-ItemProperty '.\AppCompatibility\AppCompatCache').AppCompatCache
      }
      pop-location
    }
  }

  if($AppCompatCache.Count -le 0){return}

	# Initialize a Memory Stream and Binary Reader to scan through the Byte Array
	$MemoryStream    = [System.IO.MemoryStream]::new($AppCompatCache)
	$BinReader       = [System.IO.BinaryReader]::new($MemoryStream)
	$UnicodeEncoding = [System.Text.Encoding]::Unicode
#	$ASCIIEncoding   = [System.Text.Encoding]::ASCII

	# The first 4 bytes of the AppCompatCache is a Header.  Lets parse that and use it to determine which format the cache is in.
	switch ($BinReader.ReadInt32()) {
    0x00000034 { # Windows 10 Creators update
    
      #read past header
      $null = $BinReader.ReadBytes(48)
  
      #$NumberOfEntries = 760 # can't locate the number of entries in header - read until error
      while($True){
        try{
          $TempObject = @{}
          $TempObject.Tag          = $BinReader.ReadBytes(4)
          $null                    = $BinReader.ReadBytes(4)
          $CacheEntrySize          = $BinReader.ReadUInt32()
          $NameLength              = $BinReader.ReadUInt16()
          $TempObject.FullName     = $UnicodeEncoding.GetString($BinReader.ReadBytes($NameLength))
          $TempObject.Name         = (split-path $TempObject.Name -Leaf).ToUpperInvariant()
          $TempObject.Path         = (split-path $TempObject.Name).ToUpperInvariant()
          $TempObject.Time         = [DateTime]::FromFileTime($BinReader.ReadUInt64())
          $DataLength              = $BinReader.ReadUInt32()
          $TempObject.Data         = $BinReader.ReadBytes($DataLength)
          $TempObject.EntryNumber  = $ShimCacheBins.Add($TempObject)
        }catch [System.IO.EndOfStreamException]{
          break
        }catch {
          $_ | format-list * -force | out-string | write-error
          break
        }
      }
      break
    }
<# These didn't pertain to me, but you do you...
		0x00000030 { # Windows 10
			# Finish Reading Header
			$BinReader.ReadBytes(32) | Out-Null
			$NumberOfEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
			$BinReader.ReadBytes(8) | Out-Null
			
			# Complete loop to parse each entry
			for ($i=0; $i -lt $NumberOfEntries; $i++) {
				$TempObject = "" | Select-Object -Property Name, LastModifiedTime, Data
				$TempObject | Add-Member -MemberType NoteProperty -Name "Tag" -Value ($ASCIIEncoding.GetString($BinReader.ReadBytes(4)))
				$BinReader.ReadBytes(4) | Out-Null
				$CacheEntrySize = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
				$NameLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
				# This probably needs to be NameLength * 2 if the length is the number of unicode characters - need to verify
				$TempObject.Name = $UnicodeEncoding.GetString($BinReader.ReadBytes($NameLength))
				$TempObject.LastModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				$DataLength = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
				$TempObject.Data = $ASCIIEncoding.GetString($BinReader.ReadBytes($DataLength))
				$EntryArray += $TempObject
			}
                #$EntryArray | Select Name, LastModifiedTime
                write-host "win 10"
		}
	
		0x00000080 { # Windows 8
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
			#$EntryArray | Select-Object -Property Name, Time
            write-host "win 8"

		}
	
		0xbadc0fee { # Windows 7 / Windows 2008 R2
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
			#$EntryArray | Format-Table -AutoSize -Property Name, Time
            write-host "win 7"
		}
		
		0xbadc0ffe { # Windows XP 64-bit, Windows Server 2003 through Windows Vista and Windows Server 2008
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
					$TempObject = "" | Select-Object -Property Name, Time, FileSize, Executed
					$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$BinReader.ReadBytes(4) | Out-Null
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
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
					$TempObject = "" | Select-Object -Property FileName, Time, FileSize
					$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
					$Offset = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
					$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
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
			#$EntryArray | Format-Table -AutoSize -Property Name, Time
            write-host "win xp 64"

		}
		
		0xdeadbeef { # Windows XP 32-bit
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
				$TempObject = "" | Select-Object -Property FileName, LastModifiedTime, Size, LastUpdatedTime
				# According to Mandiant paper, MAX_PATH + 4 (260 + 4, in unicode = 528 bytes)
				$TempObject.FileName = ($UnicodeEncoding.GetString($BinReader.ReadBytes(528))) -replace "\\\?\?\\",""
				$TempObject.LastModifiedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				# I'm not fully confident in the Size value without having a Windows XP box to test. Mandiant Whitepaper only says Large_Integer, QWORD File Size. Harlan Carveys' script parses as 2 DWORDS.
				$TempObject.FileSize = [System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)
				$TempObject.LastUpdatedTime = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
				$EntryArray += $TempObject
			}
			
			# Return a Table with the results.  I have to do this in the switch since not all OS versions will have the same interesting fields to return
			#return $EntryArray
            write-host "win xp 32 bit"
		}

#>

    default{throw ('Unknown Application Compatibility Cache header format: 0x{0:x8}' -f $_)}
	}
  
  $SysBinNames = ($32BinNames + $64BinNames | sort-object -Unique).where{$_ -ne 'DISMHOST.EXE'}

  $ShimCacheBins.where{$_.Name -ne $null -and $_.Name -in $SysBinNames}.foreach{$shBIN = $_
    $SysBinPaths = $SysInfoByName.($shBIN.Name).Path.ToUpperInvariant() | sort-object -Unique
    if($shBIN.Path.ToUpperInvariant() -in $SysBinPaths){continue}
    
    $SusShimCacheBin = @{
      ComputerName  = $env:COMPUTERNAME
      SusExe        = $shBIN.FullName
      WinSysMatch   = ''
      WinSys64Match = ''
    }
    $SysInfoByName.($shBIN.Name).foreach{$SysBIN = $_
      switch($SysBIN.Local){
       'Sys32'{$SusShimCacheBin.WinSysMatch   = $SysBIN.FullName;break}
       'Sys64'{$SusShimCacheBin.WinSys64Match = $SysBIN.FullName;break}
      }
    }
    write-output $SusShimCacheBin
  } | Export-csv -NoTypeInformation $CollectionPath\SuspiciousShimCacheEntries.csv
}
#endregion Shimcache Functions

#region Start Suspicious Bin Audit
Function Get-SusExecsPS45{
<#
.DESCRIPTION
Get-SusExec & Get-SusDLLs 
  Profiles a system to locate System32 and SysWow64 executables and DLL files 
  that do not exist within their default location.
#>
  param(
    [string]
    #Specifies the path to the new report file
    $Destination = (join-path $CollectionPath 'SuspiciousBinsList.csv')
  )
  write-host "Analyzing binaries in userland"

  #Start Find possible sideloaded exes
  $UserLandBins.where{$_.Name.ToUpperInvariant() -in $SysBinNames}.foreach{
    $uBIN  = $_
    $MatchingSysBins = $SysInfoByName.($uBIN.Name) | sort-object -Unique -Property Path
    $MatchingSysBins.foreach{
      $SysBIN = $_
      write-output ([PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        SusExe       = $uBIN.FullName
        SusExeOGName = $uBIN.VersionInfo.OriginalFileName
        SusExeHash   = $uBIN.Hash.MD5
        WinSysMatch  = $SysBIN.FullName
        WinSysHash   = $SysBIN.Hash.MD5
        MatchedOnOGName = 'No'
      })
    }
  } | Export-csv -NoTypeInformation $Destination

  $UserLandBins.where{$_.OGName -ne $null -and $_.Name.ToUpperInvariant() -ne $_.OGName.ToUpperInvariant() -and $_.OGName.ToUpperInvariant() -in $SysBinNames}.foreach{
    $uBIN = $_
    $MatchingSysBins = $SysInfoByName.($uBIN.OGName) | sort-object -Unique -Property Path
    $MatchingSysBins.foreach{
      $SysBIN = $_
      write-output ([PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        SusExe       = $uBIN.FullName
        SusExeOGName = $uBIN.VersionInfo.OriginalFileName
        SusExeHash   = $uBIN.Hash.MD5
        WinSysMatch  = $SysBIN.FullName
        WinSysHash   = $SysBIN.Hash.MD5
        MatchedOnOGName = 'Yes'
      })
    }
  } | Export-csv -NoTypeInformation $Destination -Append
}
#endregion Suspicious Bin Audit

#region Start Suspicious DLL Audit
Function Get-SusDllsPS45{
<#
.DESCRIPTION
Get-SusExec & Get-SusDLLs 
  Profiles a system to locate System32 and SysWow64 executables and DLL files 
  that do not exist within their default location.
#>
  param(
    [string]
    #Specifies the path to the new report file
    $Destination = (join-path $CollectionPath 'SuspiciousDllsList.csv')
  )
  write-host "Analyzing DLLs in userland"

  #Start Find possible sideloaded DLLs
  $UserLandDLLs.where{$_.Name.ToUpperInvariant() -in $SysDLLNames -and !$_.SaysMS}.foreach{
    $uDLL = $_
    $MatchingSysDLLs = $SysInfoByName.($uDLL.Name) | sort-object -Unique -Property Path
    $MatchingSysDLLs.foreach{
      $SysDLL = $_
      write-output ([PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        SusDll       = $uDLL.FullName
        SusDllHash   = $uDLL.Hash.MD5
        WinSysMatch  = $SysDLL.FullName
        WinSysHash   = $SysDLL.Hash.MD5
      })
    }
  } | Export-csv -NoTypeInformation $Destination
}
#endregion suspicious DLL Audit

$ErrorActionPreference = "Continue"

#region Collect File Info
set-variable -Option ReadOnly -Name MSSubject -Value 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
set-variable -Option ReadOnly -Name System32  -Value "$env:SystemRoot\System32\"
set-variable -Option ReadOnly -Name SysWOW64  -Value "$env:SystemRoot\SysWOW64\"
$FullList     = new-object System.Collections.ArrayList
$MagicErrors  = new-object System.Collections.ArrayList

$Sys32BinList = new-object System.Collections.ArrayList
$Sys64BinList = new-object System.Collections.ArrayList
$UserLandBins = new-object System.Collections.ArrayList
$Sys32DLLList = new-object System.Collections.ArrayList
$Sys64DLLList = new-object System.Collections.ArrayList
$UserLandDLLs = new-object System.Collections.ArrayList
$InfoByPathByType = @{}
$SysInfoByName    = @{}

$FileCount = 0
filter ProcessFile{
  $file = $_
  try{$PE_Magic = get-content $file -TotalCount 2 -Encoding Byte -ErrorAction Ignore}catch {
    $PE_Magic = new-object byte[] 2
    if($file.FullName -match '[[\]]'){
      #get-content has a known bug with square brackets
      try{
        $r = $file.OpenRead()
        $null = $r.Read($PE_Magic,0,2)
      }catch {$_|fl * -force|out-string|write-host -Background Black -Foreground Red}finally {$r.Close()}
    }else{
      write-warning "Magic Error: $($file.FullName)"
      $null = $MagicErrors.Add(@{
        Name = $file.FullName
        Ref  = $file
      })
    }
  }
  $isMagic = $PE_Magic.Length -eq 2 -and $PE_Magic[0] -eq 0x4D -and $PE_Magic[1] -eq 0x5A
  if($isMagic -or $File.Extension -in '.exe','.dll','.sys','.com','.scr'){
    $info = @{
      Name     = $file.Name
      OGName   = $file.VersionInfo.OriginalFileName
      FullName = $file.FullName
      File     = $file
      Path     = $file.Directory.FullName
      Local    = switch($true){
        ({$file.FullName.StartsWith($System32)}){'Sys32';break}
        ({$file.FullName.StartsWith($SysWOW64)}){'Sys64';break}
        default{'UserLand';break}
      }
      fType    = $file.Extension.Substring(1).ToLowerInvariant()
      isMagic  = $isMagic
      Hash     = (HashThis ([System.IO.File]::ReadAllBytes($file.FullName)))
      Sig      = (Get-AuthenticodeSignature $file -ErrorAction Ignore)
    }
    $info.SaysMS = $info.Sig.SignerCertificate.Subject -eq $MSSubject
    if($info.OGName -ne $null)
      {$info.OGName = $info.OGName.Replace('.MUI','')}
    
    switch($info.Local){
      'Sys32'{
        if($info.fType -eq 'dll'){$null=$Sys32DLLList.Add($info)}else{$null=$Sys32BinList.Add($info)};
        OrganizeThis $SysInfoByName $info.Name.ToUpperInvariant() $info
        break;
      }
      'Sys64'{
        if($info.fType -eq 'dll'){$null=$Sys64DLLList.Add($info)}else{$null=$Sys64BinList.Add($info)};
        OrganizeThis $SysInfoByName $info.Name.ToUpperInvariant() $info
        break;
      }
      'UserLand'{
        if($info.fType -eq 'dll'){$null=$UserLandDLLs.Add($info)}else{$null=$UserLandBins.Add($info)};
        break;
      }
    }

    OrganizeThis $InfoByPathByType $iPath,$iType $info
    
    $null=$FullList.Add($info)
  }
  if(!(++$FileCount % 500))
    {write-automated ('Files Reviewed:{0,15:#,##0}; Identified:{1,15:#,##0} {2:0.0%}' -f $FileCount,$FullList.Count,($FullList.Count/$FileCount))}
}

@(
  $System32,
  $SysWOW64,
  "$env:HOMEDRIVE\Users",
  "$env:HOMEDRIVE\ProgramData",
  "$env:HOMEDRIVE\Intel",
  "$env:HOMEDRIVE\Recovery"
) | get-childitem -File -Force -Recurse -ErrorAction Ignore | ProcessFile

$32BinNames  = $Sys32BinList.Name.ToUpperInvariant() | sort-object -Unique
$64BinNames  = $Sys64BinList.Name.ToUpperInvariant() | sort-object -Unique
$SysBinNames = $32BinNames + $64BinNames | sort-object -Unique
$32DLLNames  = $Sys32DLLList.Name.ToUpperInvariant() | sort-object -Unique
$64DLLNames  = $Sys64DLLList.Name.ToUpperInvariant() | sort-object -Unique
$SysDLLNames = $32DLLNames + $64DLLNames | sort-object -Unique

$64BinsOnly = new-object System.Collections.ArrayList
$Sys64BinList.where{$_.Name.ToUpperInvariant() -NotIn $32BinNames}.foreach{$null = $64BinsOnly.Add($_)}

$64DllsOnly = new-object System.Collections.ArrayList
$Sys64DLLList.where{$_.Name.ToUpperInvariant() -NotIn $64DLLNames}.foreach{$null = $64DLLOnly.Add($_)}
#endregion

#region Run Audit Functions
Get-SideLoadDetectsPS45
Get-SusShimCachePS45
Get-SusExecsPS45
Get-SusDllsPS45
#endregion
