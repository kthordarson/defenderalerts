MAX_RECORDS = 500
RESOURCEAPPIDURI = 'https://api-eu.securitycenter.microsoft.com'
DEVICE_SCHEMAS = ['DeviceInfo', 'DeviceNetworkInfo', 'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents',
				  'DeviceRegistryEvents', 'DeviceLogonEvents', 'DeviceImageLoadEvents', 'DeviceEvents', 'DeviceFileCertificateInfo']
EMAIL_SCHEMAS = ['EmailEvents', 'EmailAttachmentInfo',
				 'EmailUrlInfo', 'EmailPostDeliveryEvents', 'UrlClickEvents']
IDENTITY_SCHEMAS = ['IdentityInfo', 'IdentityLogonEvents', 'IdentityQueryEvents',
					'IdentityDirectoryEvents', 'CloudAppEvents', 'AADSpnSignInEventsBeta', 'AADSignInEventsBeta']
ALERT_SCHEMAS = ['AlertInfo', 'AlertEvidence',
				 'BehaviorInfo', 'BehaviorEntities']
API_URLS = [
			'LibraryFiles',
			'Machines',
			'Investigations',
			'Recommendations',
			'Vulnerabilities',
			'Software',
			'Alerts',
			'Firmware',
			'Indicators',
			'ExposureScore',
			'ConfigurationScore',
			'BaselineConfigurations',
			'BaselineProfiles',
			'RemediationTasks',
			'DeviceAuthenticatedScanDefinitions',
			'DeviceAuthenticatedScanAgents',
			'CustomDetections',
			'DeviceAvInfo',
			]
			# 404
			# 'BrowserExtensions',
			# 'AlertEntitySetName',
			# 'Users',
			# 'MachineActions',
			# 'Files',
			# 'Domains',
			# 'Ips',
			# 'PublicProductDto',
			# 'PublicVulnerabilityDto',
			# 403   Forbidden Tenant feature is not enabled base
			#'DeviceGroups',
			# 403 Forbidden Application context is not allowed to access this API
			#'DataExportSettings'
			# 'Incidents',
