# DefenderEndpointAPI
# View and manage alerts from 365 defender

import os
import json
from json import JSONDecodeError
import urllib.request
import urllib.parse
from urllib.error import HTTPError
import requests
from io import BytesIO, StringIO
from datetime import datetime, timedelta
from loguru import logger
from html.parser import HTMLParser


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


class SchemaException(Exception):
	pass

class TokenException(Exception):
	pass

class WrongReasonException(Exception):
	pass

class MissingResource(Exception):
	pass

class MLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.reset()
        self.strict = False
        self.convert_charrefs= True
        self.text = StringIO()
    def handle_data(self, d):
        self.text.write(d)
    def get_data(self):
        return self.text.getvalue()

def strip_tags(html):
    """
    Strip html tags from text
    Params:
    html: text with html tags
    returns stripped text
	"""
    s = MLStripper()
    s.feed(html)
    stripped = s.get_data()
    return stripped.replace('\n','')

def get_aad_token():
	"""
	returns aadtoken
	Must set enviorment variables with valid credentials for the registered azure enterprise application
	"""
	AppID = os.environ.get('defenderappid')
	TenantID = os.environ.get('defenderTenantID')
	Value = os.environ.get('defenderValue')
	SecretID = os.environ.get('defenderSecretID')
	if not AppID or not TenantID or not Value or not SecretID:
		raise TokenException(f'Missing authinfo....')
	url = f"https://login.microsoftonline.com/{TenantID}/oauth2/token"
	resourceAppIdUri = 'https://api-eu.securitycenter.microsoft.com'
	body = {'resource': resourceAppIdUri, 'client_id': AppID,
			'client_secret': Value, 'grant_type': 'client_credentials'}
	data = urllib.parse.urlencode(body).encode("utf-8")
	req = urllib.request.Request(url, data)
	try:
		response = urllib.request.urlopen(req)
	except HTTPError as e:
		logger.error(e)
		raise TokenException(f'Error getting token {e} appid:{AppID} tid:{TenantID} v:{Value} s:{SecretID}')
	jsonResponse = json.loads(response.read())
	aadToken = jsonResponse["access_token"]
	logger.debug(f'got aadtoken: {len(aadToken)}')
	return aadToken


def get_indicators(aadtoken, severity='High'):
	"""
	Get list of indicators from Office365 defender
	Params:
	aadToken: auth token
	severity: Filter by severity level. 'Informational' 'Low', 'Medium', 'High', Default 'High'
	Returns: json object of alerts
	"""
	session = requests.Session()
	session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + aadtoken
		})
	#build get-alerts API
	filterTime = datetime.utcnow() - timedelta(hours = 8)          #If you want to include alerts from longer then an hour, change here (days, weeks)
	filterTime = filterTime.strftime("%Y-%m-%dT%H:%M:%SZ")
	# url = "https://api.securitycenter.microsoft.com/api/alerts?$filter=alertCreationTime+ge+{}".format(filterTime)
	# url = "https://api.securitycenter.microsoft.com/api/machines?$filter=riskScore+eq+'High'
	baseurl = "https://api-eu.securitycenter.microsoft.com/api/"
	# apiurl = f"{baseurl}Alerts?$filter=severity+eq+'{severity}' # &$filter=alertCreationTime+ge+{filterTime}"
	apiurl = f"{baseurl}Indicators"
	try:
		response = session.get(apiurl)
	except HTTPError as e:
		logger.error(f'{type(e)} {e} url = {apiurl}')
	if response.status_code == 200:
		json_response = json.loads(response.content)
		try:
			json_values = json_response['value']
		except KeyError as e:
			logger.warning(f'{type(e)} {e} {apiurl} {json_response}')
			json_values = json_response
		logger.info(f'{apiurl} json_values = {len(json_values)} {type(json_values)}')
		return json_values
	elif response.status_code == 403:
		json_err = json.loads(response.content)
		logger.warning(f"responsecode={response.status_code} {json_err.get('error').get('code')} {json_err.get('error').get('message')} base = {baseurl} apiurl={apiurl}")
	elif response.status_code == 404:
		#json_err = json.loads(response.content)
		logger.error(f'notfound responsecode={response.status_code} response.content={response.content} base = {baseurl} apiurl={apiurl}')
	elif response.status_code == 400:
		#json_err = json.loads(response.content)
		logger.error(f'responsecode={response.status_code} response.content={response.content} base = {baseurl} apiurl={apiurl}')
	else:
		logger.error(f'unknown status responsecode={response.status_code} base = {baseurl} apiurl={apiurl}')

def get_Vulnerabilities(aadtoken):
	"""
	Get list of Vulnerabilities from Office365 defender
	Params:
	aadToken: auth token
	severity: Filter by severity level. 'Informational' 'Low', 'Medium', 'High', Default 'High'
	Returns: json object of alerts
	"""
	session = requests.Session()
	session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + aadtoken
		})
	#build get-alerts API
	filterTime = datetime.utcnow() - timedelta(hours = 8)          #If you want to include alerts from longer then an hour, change here (days, weeks)
	filterTime = filterTime.strftime("%Y-%m-%dT%H:%M:%SZ")
	# url = "https://api.securitycenter.microsoft.com/api/alerts?$filter=alertCreationTime+ge+{}".format(filterTime)
	# url = "https://api.securitycenter.microsoft.com/api/machines?$filter=riskScore+eq+'High'
	baseurl = "https://api-eu.securitycenter.microsoft.com/api/"
	# apiurl = f"{baseurl}Alerts?$filter=severity+eq+'{severity}' # &$filter=alertCreationTime+ge+{filterTime}"
	apiurl = f"{baseurl}Vulnerabilities"
	try:
		response = session.get(apiurl)
	except HTTPError as e:
		logger.error(f'{type(e)} {e} url = {apiurl}')
	if response.status_code == 200:
		json_response = json.loads(response.content)
		try:
			json_values = json_response['value']
		except KeyError as e:
			logger.warning(f'{type(e)} {e} {apiurl} {json_response}')
			json_values = json_response
		logger.info(f'{apiurl} json_values = {len(json_values)} {type(json_values)}')
		return json_values
	elif response.status_code == 403:
		json_err = json.loads(response.content)
		logger.warning(f"responsecode={response.status_code} {json_err.get('error').get('code')} {json_err.get('error').get('message')} base = {baseurl} apiurl={apiurl}")
	elif response.status_code == 404:
		#json_err = json.loads(response.content)
		logger.error(f'notfound responsecode={response.status_code} response.content={response.content} base = {baseurl} apiurl={apiurl}')
	else:
		logger.error(f'unknown status responsecode={response.status_code} base = {baseurl} apiurl={apiurl}')


def get_defender_data(aadtoken, api_item):
	"""
	Get list of Vulnerabilities from Office365 defender
	Params:
	aadToken: auth token
	severity: Filter by severity level. 'Informational' 'Low', 'Medium', 'High', Default 'High'
	Returns: json object with data
	"""
	session = requests.Session()
	session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + aadtoken
		})
	# filterTime = datetime.utcnow() - timedelta(hours = 8)
	# filterTime = filterTime.strftime("%Y-%m-%dT%H:%M:%SZ")
	# url = "https://api.securitycenter.microsoft.com/api/alerts?$filter=alertCreationTime+ge+{}".format(filterTime)
	# url = "https://api.securitycenter.microsoft.com/api/machines?$filter=riskScore+eq+'High'
	baseurl = "https://api-eu.securitycenter.microsoft.com/api/"
	# apiurl = f"{baseurl}Alerts?$filter=severity+eq+'{severity}' # &$filter=alertCreationTime+ge+{filterTime}"
	apiurl = f"{baseurl}{api_item}"
	try:
		response = session.get(apiurl)
	except HTTPError as e:
		logger.error(f'{type(e)} {e} url = {apiurl}')
	if response.status_code == 200:
		json_response = json.loads(response.content)
		try:
			json_values = json_response['value']
		except KeyError as e:
			logger.warning(f'{type(e)} {e} apiurl: {apiurl} json: {json_response}')
			json_values = json_response
		logger.info(f'{apiurl} json_values = {len(json_values)} {type(json_values)}')
		return json_values
	elif response.status_code == 403:
		json_err = json.loads(response.content)
		logger.warning(f"responsecode={response.status_code} {json_err.get('error').get('code')} {json_err.get('error').get('message')} base = {baseurl} apiurl={apiurl}")
	elif response.status_code == 404:
		#json_err = json.loads(response.content)
		logger.error(f'notfound responsecode={response.status_code} response.content={response.content} base = {baseurl} apiurl={apiurl}')
	else:
		logger.error(f'unknown status responsecode={response.status_code} base = {baseurl} apiurl={apiurl}')
	return None


def get_defender_alerts(aadtoken):
	"""
	Get list of Alerts from Office365 defender
	Params:
	aadToken: auth token
	severity: Filter by severity level. 'Informational' 'Low', 'Medium', 'High', Default 'High'
	Returns: json object of alerts
	"""
	session = requests.Session()
	session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + aadtoken
		})
	baseurl = "https://api-eu.securitycenter.microsoft.com/api/alerts/"
	# apiurl = f"{baseurl}{api_item}?top=10&$expand=evidence"
	#apiurl = f"{baseurl}?$filter=status+eq+'New'&$expand=evidence&top=100"
	apiurl = f"{baseurl}?$filter=status+eq+'New'&$expand=evidence&top=100"
	try:
		response = session.get(apiurl)
	except HTTPError as e:
		logger.error(f'{type(e)} {e} url = {apiurl}')
	if response.status_code == 200:
		json_response = json.loads(response.content)
		logger.debug(f'respcontent = {len(response.content)} json_response={len(json_response)}')
		try:
			json_values = json_response['value']
		except KeyError as e:
			logger.warning(f'{type(e)} {e} apiurl: {apiurl} json: {json_response}')
			json_values = json_response
		if len(json_values) == 0:
			logger.warning(f'No alerts from defender securitycenter! jsonresp: {json_response}')
		return json_values
	elif response.status_code == 403:
		json_err = json.loads(response.content)
		logger.warning(f"responsecode={response.status_code} {json_err.get('error').get('code')} {json_err.get('error').get('message')} base = {baseurl} apiurl={apiurl}")
	elif response.status_code == 404:
		#json_err = json.loads(response.content)
		logger.error(f'notfound responsecode={response.status_code} response.content={response.content} base = {baseurl} apiurl={apiurl}')
	else:
		logger.error(f'unknown status responsecode={response.status_code} base = {baseurl} apiurl={apiurl}')
	return None

def get_defender_alert(aadtoken, alert_id):
	"""
	Get single Alert from Office365 defender
	Params:
	aadToken: auth token
	alert_id: id of alert
	Returns: json object of alerts
	"""
	session = requests.Session()
	session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + aadtoken
		})
	baseurl = "https://api-eu.securitycenter.microsoft.com/api/alerts/"
	apiurl = f"{baseurl}{alert_id}"
	try:
		response = session.get(apiurl)
	except HTTPError as e:
		logger.error(f'{type(e)} {e} url = {apiurl}')
	if response.status_code == 200:
		json_response = json.loads(response.content)
		logger.debug(f'alerts = {len(response.content)} json_response={len(json_response)}')
		return json_response
	elif response.status_code == 403:
		json_err = json.loads(response.content)
		logger.warning(f"responsecode={response.status_code} {json_err.get('error').get('code')} {json_err.get('error').get('message')} base = {baseurl} apiurl={apiurl}")
	elif response.status_code == 404:
		#json_err = json.loads(response.content)
		logger.error(f'notfound responsecode={response.status_code} response.content={response.content} base = {baseurl} apiurl={apiurl}')
	else:
		logger.error(f'unknown status responsecode={response.status_code} base = {baseurl} apiurl={apiurl}')
	return None

def update_alert(aadtoken, alert_id):
	"""
	Update a single alert
	Params:
	aadToken: auth token
	alert_id: id of the alert to update

	Property Description
	Status: Specifies the current status of the alert. The property values are: 'New', 'InProgress' and 'Resolved'.
	assignedTo: Owner of the alert
	Classification: Specifies the specification of the alert. The property values are: TruePositive, Informational, expected activity, and FalsePositive.
	Determination:  Specifies the determination of the alert.
		Possible determination values for each classification are:
		True positive:
			Multistage attack (MultiStagedAttack),
			Malicious user activity (MaliciousUserActivity),
			Compromised account (CompromisedUser) consider changing the enum name in public api accordingly,
			Malware (Malware),
			Phishing (Phishing),
			Unwanted software (UnwantedSoftware),
			and Other (Other).
		Informational,
			expected activity: Security test (SecurityTesting),
			Line-of-business application (LineOfBusinessApplication),
			Confirmed activity (ConfirmedUserActivity) - consider changing the enum name in public api accordingly,
			and Other (Other).
		False positive:
			Not malicious (Clean) - consider changing the enum name in public api accordingly,
			Not enough data to validate (InsufficientData),
			and Other (Other).
	Comment: Comment to be added to the alert.
	returns status of update
	"""
	session = requests.Session()
	session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + aadtoken
		})
	baseurl = "https://api-eu.securitycenter.microsoft.com/api/alerts"
	# apiurl = f"{baseurl}{api_item}?top=10&$expand=evidence"
	apiurl = f"{baseurl}/{alert_id}"
	jsondata = {
		'status': 'Resolved',
		#'assignedTo': '',
		#'Classification' : 'Informational',
		#'Determination' : 'Malware',
		'Comment' : 'update via defenderapitool'
	}
	response = None
	logger.debug(f'update {alert_id} apiurl: {apiurl}')
	try:
		response = session.patch(url=apiurl, json=jsondata)
	except HTTPError as e:
		logger.error(e)
		return None
	if response.status_code == 200:
		print(response)
		return response
	elif response.status_code == 403:
		errmsg = json.loads(response.content).get('error')
		logger.warning(f'403 {errmsg}')
		return None
	elif response.status_code == 400:
		errmsg = json.loads(response.content).get('error')
		logger.warning(f'errmsg {errmsg} {response.status_code} {response.content}')
		return None
	else:
		logger.warning(f'{response.status_code} {response.content}')
		return None


def get_cloudapp_resource(resource, skip=0, limit=100, alertopen=True, resolutionStatus=0, resolution_status='open'):
	"""
	Get list of alerts from Cloud app security portal
	Params:
	skip: skip n items. Default 0.
	limit: max items to fectch in each request. Default 100.
	alertopen: True = fetch only open alerts, False = fetch both open and closed alerts. Default True.
	resolutionStatus: 0 = open, 1 = dismissied, 2 = resolved, 3 falsepositive, 4 = benign, 5 = truepositive. default = 0
	resolution_status: 0 = open, 1 = dismissed, 2 = resolved. default = open
	"""
	# filters https://learn.microsoft.com/en-us/defender-cloud-apps/api-alerts#filters
	token = os.environ.get('CLOUDAPPAPIKEY')
	cloudappurl = os.environ.get('CLOUDAPPURL')
	if resource == 'alerts':
		baseurl = f'https://{cloudappurl}/api/v1/alerts/'
	elif resource == 'activities':
		baseurl = f'https://{cloudappurl}/api/v1/activities/'
	elif resource == 'discovery':
		# todo fix
		baseurl = f'https://{cloudappurl}/api/v1/discovery/'
		# POST /api/v1/discovery/discovered_apps/categories/
		# GET /api/discovery/streams/
	elif resource == 'entities':
		baseurl = f'https://{cloudappurl}/api/v1/entities/'
	elif resource == 'files':
		baseurl = f'https://{cloudappurl}/api/v1/files/'
	elif resource == 'subnet':
		baseurl = f'https://{cloudappurl}/api/v1/subnet/'
	else:
		raise MissingResource(f'Missing api resource item')
	session = requests.Session()
	session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "token " + token
		})

	data = {'filters': {'resolutionStatus': {'eq': resolutionStatus}}, 'skip': skip, 'limit': limit}
	records = []
	hasnext = True
	MAX_RECORDS = 500
	while hasnext:
		try:
			response = session.post(url=baseurl, json=data)
		except HTTPError as e:
			logger.error(f'{type(e)} {e} url = {baseurl}')
		if response.status_code == 200:
			json_response = json.loads(response.content)
			logger.debug(f'hasnext: {hasnext} respcontent = {len(response.content)} json_response={len(json_response)} records = {len(records)}')
			try:
				json_values = json_response.get('data', [])
			except KeyError as e:
				logger.warning(f'{type(e)} {e} baseurl: {baseurl} json: {json_response}')
			if len(json_values) == 0:
				logger.warning(f'No alerts! jsonresp: {json_response}')
			else:
				records += json_values
			hasnext = json_response.get('hasNext', False)
			if len(records) >= MAX_RECORDS:
				logger.warning(f'Reached MAX_RECORDS={MAX_RECORDS} records = {len(records)}')
				hasnext = False
	return records

def get_cloudapp_alert(alert_id:str):
	"""
	Get single cloudapp security alert
	Params:
	id: alert id
	"""
	token = os.environ.get('CLOUDAPPAPIKEY')
	cloudappurl = os.environ.get('CLOUDAPPURL')
	baseurl = f'https://{cloudappurl}/api/v1/alerts/{alert_id}'
	session = requests.Session()
	session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "token " + token
		})
	try:
		response = session.get(url=baseurl)
	except HTTPError as e:
		logger.error(f'{type(e)} {e} url = {baseurl}')
	if response.status_code == 200:
		json_values = json.loads(response.content)
		logger.debug(f'respcontent = {len(response.content)} json={len(json_values)}')
		if len(json_values) == 0:
			logger.warning(f'No alerts! jsonresp: {json_values}')
		return json_values
	elif response.status_code == 403:
		json_err = json.loads(response.content)
		logger.warning(f"responsecode={response.status_code} {json_err} base = {baseurl} apiurl={baseurl}")
	elif response.status_code == 404:
		#json_err = json.loads(response.content)
		logger.error(f'notfound responsecode={response.status_code} response.content={response.content} base = {baseurl} apiurl={baseurl}')
	else:
		logger.error(f'unknown status responsecode={response.status_code} base = {baseurl} apiurl={baseurl}')
	return None

def update_cloudapp_alert(alert_id, close_reason, reasonid, comment='defendercloudapireasoncomment',):
	"""
	Update cloud app security alert
	Params:
	id: alert id
	close_reason: benign, falsepositive, truepositive
	reasonid: see below description...
	comment: comment text
	"""
	token = os.environ.get('CLOUDAPPAPIKEY')
	cloudappurl = os.environ.get('CLOUDAPPURL')

	session = requests.Session()
	session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "token " + token
		})
	if close_reason == 'benign':
		# POST /api/v1/alerts/close_benign/ # reasonid 2: actual severity is lower, 4: other, 5:confirmed with user, 6:triggered by test
		baseurl = f'https://{cloudappurl}/api/v1/alerts/close_benign/'
		if reasonid not in (2,4,5,6):
			raise WrongReasonException(f'invalid reasonid {reasonid} {close_reason}')
	elif close_reason == 'falsepositive':
		# POST /api/v1/alerts/close_false_positive/ # reasonid: 0 : not of interest, 1 : too many similar alerts,3 : Alert not accurate, 4 : other
		baseurl = f'https://{cloudappurl}/api/v1/alerts/close_false_positive/'
		if reasonid not in (0,1,3,4):
			raise WrongReasonException(f'invalid reasonid {reasonid} {close_reason}')
	elif close_reason == 'truepositive':
		# POST /api/v1/alerts/close_true_positive/
		baseurl = f'https://{cloudappurl}/api/v1/alerts/close_true_positive/'
		reasonid = ''
	else:
		raise WrongReasonException(f'invalid close reason {close_reason}')
	data = {
		'filters' :{
			'id': {
				'eq': [alert_id]
			}
		},
		'comment':comment,
		'reasonID':reasonid,
		'sendFeedback': False,
		'feetbackText': 'feedbacktext',
		'allowContact': False,
		'contactEmail': 'user@contoso.com'
	}
	try:
		response = session.post(url=baseurl, json=data)
	except HTTPError as e:
		logger.error(f'{type(e)} {e} url = {baseurl}')
		return None
	jsonresp = json.loads(response.content)
	logger.debug(f'[resp] {jsonresp}')
	return jsonresp


if __name__ == '__main__':
	aadtoken = None
	try:
		aadtoken = get_aad_token()
	except TokenException as e:
		logger.error(e)
	if aadtoken:
		defenderalerts = get_defender_alerts(aadtoken)
		cloudapp_alerts = get_cloudapp_resource(resource='alerts', limit=100)
		print(f'defenderalerts = {len(defenderalerts)} cloudappalerts = {len(cloudapp_alerts)}')
		if len(defenderalerts) > 0:
			[print(f"defender - date:{k.get('lastUpdateTime'):<30} id:{k.get('incidentId')} {k.get('id')} evidence:{len(k.get('evidence'))} title:{k.get('title')} ") for k in defenderalerts]
		if len(cloudapp_alerts) > 0:
			for alert in cloudapp_alerts:
				# strip html tags from description text
				alert['description'] = strip_tags(alert['description'])
			[print(f'cloudapp - ts:{k.get("timestamp")} id:{k.get("_id")}\n\tt:{k.get("title")}\n\td:{k.get("description")}\n\tsv:{k.get("statusValue")} {k.get("resolutionStatusValue")} c:{k.get("comment")}') for k in cloudapp_alerts if k.get("title")]
