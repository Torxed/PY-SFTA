import win32security
import win32api
import win32con
import datetime
import os
import sys
import time
import json
import struct
import hashlib
import binascii
import base64
import winreg

def get_user_sid():
	"""
	function local:Get-UserSid {
        [OutputType([string])]
        $userSid = ((New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value).ToLower()
        Write-Output $userSid
    }
    """

	# Get the handle to the current process token
	token_handle = win32security.OpenProcessToken(
		win32api.GetCurrentProcess(),
		win32con.TOKEN_QUERY
	)
	
	# Get the user info from the token
	user_info = win32security.GetTokenInformation(
		token_handle,
		win32security.TokenUser
	)
	
	# Extract the SID from the user info
	user_sid = user_info[0]
	
	# Convert the SID to a string
	user_sid_str = win32security.ConvertSidToStringSid(user_sid)
	
	return user_sid_str

def get_hex_date_time():
	"""
	function local:Get-HexDateTime {
		[OutputType([string])]

		$now = [DateTime]::Now
		$dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
		$fileTime = $dateTime.ToFileTime()
		$hi = ($fileTime -shr 32)
		$low = ($fileTime -band 0xFFFFFFFFL)
		$dateTimeHex = ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
		Write-Output $dateTimeHex
	}
	"""
	now = datetime.datetime.now()

	WINDOWS_TICKS = int(1/10**-7)  # 10,000,000 (100 nanoseconds or .1 microseconds)
	WINDOWS_EPOCH = datetime.datetime.strptime('1601-01-01 00:00:00',
											   '%Y-%m-%d %H:%M:%S')
	POSIX_EPOCH = datetime.datetime.strptime('1970-01-01 00:00:00',
										 '%Y-%m-%d %H:%M:%S')
	EPOCH_DIFF = (POSIX_EPOCH - WINDOWS_EPOCH).total_seconds()

	posix_secs = int(time.mktime(now.timetuple())) - now.second # We zero out the seconds
	fileTime = (posix_secs + int(EPOCH_DIFF)) * WINDOWS_TICKS

	hi = fileTime >> 32
	low = fileTime & 0xFFFFFFFF

	# Convert the integer to a hexadecimal string
	hash_str = f"{hi:08X}{low:08X}"

	return hash_str

def get_user_experience():
	"""
	function local:Get-UserExperience {
		[OutputType([string])]
		$hardcodedExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
		$userExperienceSearch = "User Choice set via Windows User Experience"
		$userExperienceString = ""
		$user32Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86) + "\Shell32.dll"
		$fileStream = [System.IO.File]::Open($user32Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
		$binaryReader = New-Object System.IO.BinaryReader($fileStream)
		[Byte[]] $bytesData = $binaryReader.ReadBytes(5mb)
		$fileStream.Close()
		$dataString = [Text.Encoding]::Unicode.GetString($bytesData)
		$position1 = $dataString.IndexOf($userExperienceSearch)
		$position2 = $dataString.IndexOf("}", $position1)
		try {
			$userExperienceString = $dataString.Substring($position1, $position2 - $position1 + 1)
		}
		catch {
			$userExperienceString = $hardcodedExperience
		}
		Write-Output $userExperienceString
	}
	"""
	hardcoded_experience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
	user_experience_search = "User Choice set via Windows User Experience"
	user_experience_string = ""

	# Get the path to Shell32.dll
	system_folder = os.environ.get('SYSTEMROOT', 'C:\\Windows') + '\\SysWOW64\\Shell32.dll'
	
	with open(system_folder, 'rb') as file:
		bytes_data = file.read(5 * 1024 * 1024)  # Read 5 MB of data

	# Decode the bytes to a string using UTF-16LE encoding
	data_string = bytes_data.decode('utf-16le', errors='ignore')

	# Find the positions of the search strings
	position1 = data_string.find(user_experience_search)
	if position1 == -1:
		raise ValueError("Search string not found")

	position2 = data_string.find('}', position1)
	if position2 == -1:
		raise ValueError("Closing brace not found")

	# Extract the user experience string
	user_experience_string = data_string[position1:position2 + 1]

	return user_experience_string

def get_shift_right(iValue, iCount):
	"""
	function local:Get-ShiftRight {
		[CmdletBinding()]
		param (
			[Parameter( Position = 0, Mandatory = $true)]
			[long] $iValue, 
					
			[Parameter( Position = 1, Mandatory = $true)]
			[int] $iCount 
		)

		if ($iValue -band 0x80000000) {
			Write-Host "$($iValue) $($iCount) $(0xFFFF0000)"
			Write-Output (( $iValue -shr $iCount) -bxor 0xFFFF0000)
		}
		else {
			Write-Output  ($iValue -shr $iCount)
		}
	}
	"""
	if iValue & 0x80000000:
		return (iValue >> iCount) ^ (-0x100000000 + 0xFFFF0000)
	else:
		return iValue >> iCount

def get_long(data, index=0, byteorder='little'):
	"""
	The following powershell function does not appear to take into account
	the total value, but rather the first four bytes starting at index.

	function local:Get-Long {
		[CmdletBinding()]
		param (
			[Parameter( Position = 0, Mandatory = $true)]
			[byte[]] $Bytes,

			[Parameter( Position = 1)]
			[int] $Index = 0
		)

		Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
	}

	This means that these two values generate the same output:
	Get-Long $([byte]176,220,177,116)
	Get-Long $([byte]176,220,177,116,123,255,255,255)
	"""
	if byteorder == 'little':
		return int.from_bytes(bytes(list(reversed(data)))[index:index+4], byteorder='little', signed=True)
	else:
		return int.from_bytes(data[index:index+4], byteorder='little', signed=True)

def convert_to_int32(value):
	"""
	The following powershell function does not appear to take into account
	the total value, but rather first four bytes, all the time.
	function local:Convert-Int32 {
		param (
			[Parameter( Position = 0, Mandatory = $true)]
			[long] $Value
		)

		[byte[]] $bytes = [BitConverter]::GetBytes($Value)
		return [BitConverter]::ToInt32( $bytes, 0) 
	}
	"""

	return int.from_bytes(
		value.to_bytes(32, byteorder='little', signed=True)[:4],
		byteorder='little',
		signed=True
	)

def calculate_hash(file_extension, progid, user_sid, userDateTime, userExperience):
	"""
	function Get-Hash {
        [CmdletBinding()]
        param (
            [Parameter( Position = 0, Mandatory = $True )]
            [string]
            $BaseInfo
        )


        function local:Get-ShiftRight {
            [CmdletBinding()]
            param (
                [Parameter( Position = 0, Mandatory = $true)]
                [long] $iValue, 
                        
                [Parameter( Position = 1, Mandatory = $true)]
                [int] $iCount 
            )
        
            if ($iValue -band 0x80000000) {
                Write-Output (( $iValue -shr $iCount) -bxor 0xFFFF0000)
            }
            else {
                Write-Output  ($iValue -shr $iCount)
            }
        }
        

        function local:Get-Long {
            [CmdletBinding()]
            param (
                [Parameter( Position = 0, Mandatory = $true)]
                [byte[]] $Bytes,
        
                [Parameter( Position = 1)]
                [int] $Index = 0
            )
        
            Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
        }
        

        function local:Convert-Int32 {
            param (
                [Parameter( Position = 0, Mandatory = $true)]
                [long] $Value
            )
        
            [byte[]] $bytes = [BitConverter]::GetBytes($Value)
            return [BitConverter]::ToInt32( $bytes, 0) 
        }

        [Byte[]] $bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo) 
        $bytesBaseInfo += 0x00, 0x00  
        
        $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        [Byte[]] $bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)
        Write-Host "MD5: $bytesMD5"
        Set-Variable -Name TestMD5 -Value $bytesMD5 -Scope Global
        
        $lengthBase = ($baseInfo.Length * 2) + 2 
        $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase  2) - 1
        $base64Hash = ""

        if ($length -gt 1) {
        
            $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
                R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
            }
        
            $map.CACHE = 0
            $map.OUTHASH1 = 0
            $map.PDATA = 0
            $map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
            $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
            $map.INDEX = Get-ShiftRight ($length - 2) 1
            $map.COUNTER = $map.INDEX + 1

            # $map | Out-String | Write-Host
        
            while ($map.COUNTER) {
                $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
                $map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
                $map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
                $map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
                $map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16) ))
                $map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
                $map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
                $map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
                $map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
                $map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
                $map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
                $map.CACHE = ([long]$map.OUTHASH2)
                $map.COUNTER = $map.COUNTER - 1
            }

            [Byte[]] $outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            [byte[]] $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
            # Write-Host "OUTHASH1: $buffer"
            $buffer.CopyTo($outHash, 0)
            $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
            # Write-Host "OUTHASH2: $buffer"
            $buffer.CopyTo($outHash, 4)

            # Write-Host "Out: $outHash"
        
            $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
                R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
            }
        
            $map.CACHE = 0
            $map.OUTHASH1 = 0
            $map.PDATA = 0
            $map.MD51 = ((Get-Long $bytesMD5) -bor 1)
            $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
            $map.INDEX = Get-ShiftRight ($length - 2) 1
            $map.COUNTER = $map.INDEX + 1

            # $map | Out-String | Write-Host

            while ($map.COUNTER) {
                $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
                $map.PDATA = $map.PDATA + 8
                $map.R1[0] = Convert-Int32 ($map.R0 * [long]$map.MD51)
                $map.R1[1] = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
                $map.R2[0] = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
                $map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
                $map.R3 = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
                $map.R4[0] = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
                $map.R4[1] = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
                $map.R5[0] = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
                $map.R5[1] = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
                $map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
                $map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3) 
                $map.CACHE = ([long]$map.OUTHASH2)
                $map.COUNTER = $map.COUNTER - 1
            }

        
            $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
            # Write-Host "OUTHASH1: $buffer"
            $buffer.CopyTo($outHash, 8)
            $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
            # Write-Host "OUTHASH2: $buffer"
            $buffer.CopyTo($outHash, 12)

            Write-Host "outHash: $($outHash)"
        
            [Byte[]] $outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            $hashValue1 = ((Get-Long $outHash 8) -bxor (Get-Long $outHash))
            $hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))

            Write-Host "Debug: $((Get-Long $outHash 8)) -bxor $((Get-Long $outHash))"
        
            $buffer = [BitConverter]::GetBytes($hashValue1)
            Write-Host "hashValue1: $($buffer)"
            $buffer.CopyTo($outHashBase, 0)
            $buffer = [BitConverter]::GetBytes($hashValue2)
            Write-Host "hashValue2: $($buffer)"
            $buffer.CopyTo($outHashBase, 4)

            Write-Host "Out: $outHashBase"

            $base64Hash = [Convert]::ToBase64String($outHashBase) 
        }

        Write-Output $base64Hash
    }
	"""
	# Concatenate the file extension and progid with a fixed string
	baseInfo = f"{file_extension}{user_sid}{progid}{userDateTime}{userExperience}".lower()
	# print(f"baseInfo: {baseInfo}")
	
	# Convert the data to UTF-16LE encoding
	data_utf16 = baseInfo.encode('utf-16le') + b'\x00\x00'
	
	# Calculate the MD5 hash of the encoded data
	md5_hash = hashlib.md5(data_utf16).digest()
	print('MD5:', str(list(md5_hash))[1:-1].replace(',', ''))
	
	lengthBase = (len(baseInfo) * 2) + 2 
	length = (1 if (lengthBase & 4) < 1 else 0) + get_shift_right(lengthBase, 2) - 1

	if length > 1:
		map = {
			'PDATA': 0,
			'CACHE': 0,
			'INDEX': get_shift_right(length - 2, 1),
			'COUNTER': get_shift_right(length - 2, 1) + 1,
			'MD51': (get_long(md5_hash, 0, byteorder='big') | 1) + 0x69FB0000,
			'MD52': (get_long(md5_hash, 4, byteorder='big') | 1) + 0x13DB0000,
			'OUTHASH1': 0,
			'OUTHASH2': 0,
			'R0': 0,
			'R1': [0, 0],
			'R2': [0, 0],
			'R3': 0,
			'R4': [0, 0],
			'R5': [0, 0],
			'R6': [0, 0],
			'R7': [0, 0]
		}

		while map['COUNTER']:
			map['R0'] = convert_to_int32(get_long(data_utf16, map['PDATA'], byteorder='big') + map['OUTHASH1'])
			map['R1'] = [
				convert_to_int32(get_long(data_utf16, map['PDATA'] + 4, byteorder='big')),
				0
			]
			map['R2'] = [
				convert_to_int32(
					(map['R0'] * map['MD51']) - (0x10FA9605 * get_shift_right(map['R0'], 16))
				),
				0 # Placeholder, replaced next
			]
			map['R2'] = [
				map['R2'][0],
				convert_to_int32(
					(0x79F8A395 * map['R2'][0]) + (0x689B6B9F * get_shift_right(map['R2'][0], 16))
				)
			]
			map['R3'] = convert_to_int32((0xEA970001 * map['R2'][1]) - (0x3C101569 * get_shift_right(map['R2'][1], 16)))
			map['R4'] = [
				convert_to_int32(map['R3'] + map['R1'][0]),
				0
			]
			map['R5'] = [
				convert_to_int32(map['CACHE'] + map['R3']),
				0
			]
			map['R6'] = [
				convert_to_int32((map['R4'][0] * map['MD52']) - (0x3CE8EC25 * get_shift_right(map['R4'][0], 16))),
				0, # Placeholder
			]
			map['R6'] = [
				map['R6'][0],
				convert_to_int32((0x59C3AF2D * map['R6'][0]) - (0x2232E0F1 * get_shift_right(map['R6'][0], 16)))
			]
			map['OUTHASH1'] = convert_to_int32((0x1EC90001 * map['R6'][1]) + (0x35BD1EC9 * get_shift_right(map['R6'][1], 16)))
			map['OUTHASH2'] = convert_to_int32(map['R5'][0] + map['OUTHASH1'])
			map['CACHE'] = map['OUTHASH2']
			map['COUNTER'] -= 1


		outHash = map['OUTHASH1'].to_bytes(4, byteorder='little', signed=True) + map['OUTHASH2'].to_bytes(4, byteorder='little', signed=True)
		
		map = {
			'PDATA': 0,
			'CACHE': 0,
			'COUNTER': get_shift_right(length - 2, 1) + 1,
			'INDEX': get_shift_right(length - 2, 1),
			'MD51': (get_long(md5_hash, 0, byteorder='big') | 1),
			'MD52': (get_long(md5_hash, 4, byteorder='big') | 1),
			'OUTHASH1': 0,
			'OUTHASH2': 0,
			'R0': 0,
			'R1': [0, 0],
			'R2': [0, 0],
			'R3': 0,
			'R4': [0, 0],
			'R5': [0, 0],
			'R6': [0, 0],
			'R7': [0, 0]
		}
		while map['COUNTER']:
			map['R0'] = convert_to_int32(get_long(data_utf16, map['PDATA'], byteorder='big') + map['OUTHASH1'])
			map['PDATA'] += 8
			map['R1'] = [
				convert_to_int32(map['R0'] * map['MD51']),
				0
			]
			map['R1'] = [
				map['R1'][0],
				convert_to_int32((0xB1110000 * map['R1'][0]) - (0x30674EEF * get_shift_right(map['R1'][0], 16)))
			]

			map['R2'] = [
				convert_to_int32((0x5B9F0000 * map['R1'][1]) - (0x78F7A461 * get_shift_right(map['R1'][1], 16))),
				0
			]
			map['R2'] = [
				map['R2'][0],
				convert_to_int32((0x12CEB96D * get_shift_right(map['R2'][0], 16)) - (0x46930000 * map['R2'][0]))
			]

			map['R3'] = convert_to_int32((0x1D830000 * map['R2'][1]) + (0x257E1D83 * get_shift_right(map['R2'][1], 16)))

			map['R4'] = [
				convert_to_int32(map['MD52'] * (map['R3'] + get_long(data_utf16, map['PDATA'] - 4, byteorder='big'))),
				0
			]
			map['R4'] = [
				map['R4'][0],
				convert_to_int32((0x16F50000 * map['R4'][0]) - (0x5D8BE90B * get_shift_right(map['R4'][0], 16)))
			]

			map['R5'] = [
				convert_to_int32((0x96FF0000 * map['R4'][1]) - (0x2C7C6901 * get_shift_right(map['R4'][1], 16))),
				0
			]
			map['R5'] = [
				map['R5'][0],
				convert_to_int32((0x2B890000 * map['R5'][0]) + (0x7C932B89 * get_shift_right(map['R5'][0], 16)))
			]

			map['OUTHASH1'] = convert_to_int32((0x9F690000 * map['R5'][1]) - (0x405B6097 * get_shift_right(map['R5'][1], 16)))
			map['OUTHASH2'] = convert_to_int32(map['OUTHASH1'] + map['CACHE'] + map['R3'])
			map['CACHE'] = map['OUTHASH2']
			map['COUNTER'] -= 1

		outHash += map['OUTHASH1'].to_bytes(4, byteorder='little', signed=True) + map['OUTHASH2'].to_bytes(4, byteorder='little', signed=True)

		hashValue1 = get_long(outHash, 8, byteorder='big') ^ get_long(outHash, byteorder='big')
		hashValue2 = get_long(outHash, 12, byteorder='big') ^ get_long(outHash, 4, byteorder='big')

		outHashBase = hashValue1.to_bytes(4, byteorder='little', signed=True) + hashValue2.to_bytes(4, byteorder='little', signed=True)

		return base64.b64encode(outHashBase).decode()
	else:
		return ""
	

app_context = sys.argv[1]
extension = sys.argv[2]
app_entry_hash = calculate_hash(extension, app_context, get_user_sid(), get_hex_date_time(), get_user_experience())

# Delete existing UserChoice key
try:
	with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\{extension}\\UserChoice", 0, winreg.KEY_WRITE) as user_choice:
		winreg.DeleteKey(user_choice, "")
except FileNotFoundError:
	pass


with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\{extension}", 0, winreg.KEY_WRITE) as extension_key:
	with winreg.CreateKey(extension_key, f"UserChoice") as user_choice:
		winreg.SetValueEx(user_choice, "Hash", 0, winreg.REG_SZ, app_entry_hash)
		winreg.SetValueEx(user_choice, "ProgId", 0, winreg.REG_SZ, app_context)