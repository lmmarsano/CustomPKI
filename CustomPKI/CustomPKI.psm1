Set-StrictMode -Version latest
# Implement your module commands in this script.
function New-EKU {
<#
.SYNOPSIS
	Create an X.509 Enhanced Key Usage extension.
.DESCRIPTION
	Create an X.509 Enhanced Key Usage extension from friendly names for OIDs in the pipeline.
.EXAMPLE
	PS C:\> (@'
	Any Purpose
	Client Authentication
	Server Authentication
	Secure Email
	Code Signing
	Time Stamping
	Document Encryption
	IP Security End System
	IP security tunnel termination
	IP Security User
	IP Security IKE Intermediate
	All application policies
	Microsoft Trust List Signing
	Qualified Subordination
	Key Recovery
	'@ -split "`n") | New-EKU -Critical
	Creates a critical EKU extension containing all the named OIDs.
#>
	[OutputType([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension])]
	[CmdletBinding()]
	param (
		# OID Friendly Names
		[Parameter(ValueFromPipeline=$true)]
		[string[]]
		$FriendlyName,

		# Critical Extension Flag
		[switch]
		$Critical
	)

	begin {
		$oidCollection = [System.Security.Cryptography.OidCollection]::new()
	}

	process {
		$FriendlyName | % {
			($oid = [System.Security.Cryptography.Oid]::new()).FriendlyName = $_
			[void]$oidCollection.Add($oid)
			Write-Verbose -Message ('Added OID {0} ({1})' -f $oid.Value,$oid.FriendlyName)
		}
	}

	end {
		[System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oidCollection, $Critical)
	}
}
function New-SelfSignedCertificate {
	[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium', HelpUri='https://go.microsoft.com/fwlink/?LinkId=386828')]
	param(
		[System.Security.AccessControl.FileSecurity]
		${SecurityDescriptor},

		[string[]]
		${TextExtension},

		[System.Security.Cryptography.X509Certificates.X509Extension[]]
		${Extension},

		[Microsoft.CertificateServices.Commands.HardwareKeyUsage[]]
		${HardwareKeyUsage},

		[Microsoft.CertificateServices.Commands.KeyUsageProperty[]]
		${KeyUsageProperty},

		[Microsoft.CertificateServices.Commands.KeyUsage[]]
		${KeyUsage},

		[Microsoft.CertificateServices.Commands.KeyProtection[]]
		${KeyProtection},

		[Microsoft.CertificateServices.Commands.KeyExportPolicy[]]
		${KeyExportPolicy},

		[int]
		${KeyLength},

		[string]
		${KeyAlgorithm},

		[switch]
		${SmimeCapabilities},

		[switch]
		${ExistingKey},

		[string]
		${KeyLocation},

		[string]
		${SignerReader},

		[string]
		${Reader},

		[securestring]
		${SignerPin},

		[securestring]
		${Pin},

		[string]
		${KeyDescription},

		[string]
		${KeyFriendlyName},

		[string]
		${Container},

		[string]
		${Provider},

		[Microsoft.CertificateServices.Commands.CurveParametersExportType]
		${CurveExport},

		[Microsoft.CertificateServices.Commands.KeySpec]
		${KeySpec},

		[Microsoft.CertificateServices.Commands.CertificateType]
		${Type},

		[string]
		${FriendlyName},

		[datetime]
		${NotAfter},

		[datetime]
		${NotBefore},

		[string]
		${SerialNumber},

		[string]
		${Subject},

		[string[]]
		${DnsName},

		[string[]]
		${SANDirectoryName},

		[string[]]
		${SANDNS},

		[string[]]
		${SANEmail},

		[string[]]
		${SANIPAddress},

		[string[]]
		${SANRegisteredID},

		[string[]]
		${SANUPN},

		[string[]]
		${SANURL},

		[string[]]
		${SANGUID},

		[ValidateSet('Any Purpose', 'Client Authentication', 'Server Authentication', 'Secure Email', 'Code Signing', 'Time Stamping', 'Document Encryption', 'IP Security End System', 'IP security tunnel termination', 'IP Security User', 'IP Security IKE Intermediate', 'All application policies', 'Microsoft Trust List Signing', 'Qualified Subordination', 'Key Recovery')]
		[string[]]
		${EKU},

		[string[]]
		${SuppressOid},

		[string]
		${HashAlgorithm},

		[switch]
		${AlternateSignatureAlgorithm},

		[switch]
		${TestRoot},

		[Microsoft.CertificateServices.Commands.Certificate]
		${Signer},

		[Parameter(ValueFromPipeline=$true)]
		[Microsoft.CertificateServices.Commands.Certificate]
		${CloneCert},

		[string]
		${CertStoreLocation})

	begin
	{
		try {
			# transfer DnsName to SANDNS
			if ($PSBoundParameters.ContainsKey('DnsName')) {
				if (!$PSBoundParameters.ContainsKey('SANDNS')) {
					$PSBoundParameters.SANDNS = [string[]]@()
				}
				$PSBoundParameters.SANDNS += $DnsName
				$PSBoundParameters.Remove('DnsName')
			}
			# convert SAN* parameters into TextExtension
			# sync matches into array for subsequent removal
			# expand $_.value
			$SAN = @($PSBoundParameters.GetEnumerator() `
			         | ? { $_.key.StartsWith('SAN') }) `
			     | % { [void]($PSBoundParameters.Remove($_.key))
			           $token = $_.key.Substring(3) # 3 = 'SAN'.length
			           $_.value } `
			     | % { '{0}={1}' -f $token,$_ }
			if ($null -ne $SAN) {
				if (!$PSBoundParameters.ContainsKey('TextExtension')) {
					$PSBoundParameters.TextExtension = [string[]]@()
				}
				if ($PSBoundParameters.ContainsKey('Subject')) {
					$CriticalSAN = ''
				} else {
					$CriticalSAN = '{critical}'
				}
				$PSBoundParameters.TextExtension += ,('2.5.29.17={0}{{text}}{1}' -f $CriticalSAN,($SAN -join '&'))
				Write-Information -MessageData ('Using TextExtension {0}' -f ($PSBoundParameters.TextExtension -join ','))
			}
			# convert EKU into Extension
			if ($PSBoundParameters.ContainsKey('EKU')) {
				if (!$PSBoundParameters.ContainsKey('Extension')) {
					$PSBoundParameters.Extension = [System.Security.Cryptography.X509Certificates.X509Extension[]]@()
				}
				$PSBoundParameters.Extension += ,(New-EKU -FriendlyName $EKU)
				[void]$PSBoundParameters.Remove('EKU')
				Write-Information -MessageData ('Using Extension{0}' -f ($PSBoundParameters.Extension | Out-String))
			}
			$outBuffer = $null
			if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
			{
				$PSBoundParameters['OutBuffer'] = 1
			}
			$wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('pki\New-SelfSignedCertificate', [System.Management.Automation.CommandTypes]::Cmdlet)
			$scriptCmd = {& $wrappedCmd @PSBoundParameters }
			$steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
			$steppablePipeline.Begin($PSCmdlet)
		} catch {
			throw
		}
	}

	process
	{
		try {
			$steppablePipeline.Process($_)
		} catch {
			throw
		}
	}

	end
	{
		try {
			$steppablePipeline.End()
		} catch {
			throw
		}
	}
	<#
	.ExternalHelp CustomPKI-help.xml
	.ForwardHelpTargetName pki\New-SelfSignedCertificate
	.ForwardHelpCategory Cmdlet
	#>
}
# Export only the functions using PowerShell standard verb-noun naming.
# Be sure to list each exported functions in the FunctionsToExport field of the module manifest file.
# This improves performance of command discovery in PowerShell.
Export-ModuleMember -Function New-EKU,New-SelfSignedCertificate