$ModuleManifestName = 'CustomPKI.psd1'
$ModuleManifestPath = "$PSScriptRoot\..\$ModuleManifestName"
Import-Module -Name $PSScriptRoot\..
function Compare-String {
	param (
		$ExpectedValue,
		$ActualValue
	)
	Should @args -ExpectedValue ($ExpectedValue | Out-String) -ActualValue ($ActualValue | Out-String)
}
Describe 'Module Manifest Tests' {
	It 'Passes Test-ModuleManifest' {
		Test-ModuleManifest -Path $ModuleManifestPath | Should Not BeNullOrEmpty
		$? | Should Be $true
	}
}
Describe 'New-SelfSignedCertificate' {
	BeforeAll {
		$pm = (Get-Command -Name New-SelfSignedCertificate).Parameters
	}
	(-split @'
UPN
Email
DNS
DirectoryName
URL
IPAddress
RegisteredID
GUID
'@) | % {
		$token = $_
		It ('Accepts parameter SAN{0}' -f $_) {
			$pm.ContainsKey('SAN{0}' -f $token) | Should -Be $true
		}
	}
	It 'Accepts parameter EKU' {
		$pm.ContainsKey('EKU') | Should -Be $true
	}
	It 'Merges SAN* & TextExtension' {
		Write-Information -MessageData 'Using TextExtension 2.5.29.37={text}1.3.6.1.5.5.7.3.8,2.5.29.17={text}DNS=domain' -InformationVariable expected
		New-SelfSignedCertificate -WhatIf -Subject Subject -SANDNS domain -TextExtension '2.5.29.37={text}1.3.6.1.5.5.7.3.8' -InformationVariable actual
		Compare-String -Be -ExpectedValue $expected -ActualValue $actual
	}
	It 'Merges EKU & Extension' {
		$ku = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DataEncipherment, $false)
		Write-Information -MessageData ('Using Extension{0}' -f ($ku,('Any Purpose' | New-EKU) | Out-String) -join ',') -InformationVariable expected
		New-SelfSignedCertificate -WhatIf -Subject Subject -EKU 'Any Purpose' -Extension $ku -InformationVariable actual
		Compare-String -Be -ExpectedValue $expected -ActualValue $actual
	}
	AfterAll {
		Remove-Variable -Name pm
	}
}