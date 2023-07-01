import json
from urllib.error import HTTPError
import requests
from datetime import datetime, timedelta
from loguru import logger

from .constants import RESOURCEAPPIDURI

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
	baseurl = f"{RESOURCEAPPIDURI}/api/"
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
	baseurl = f"{RESOURCEAPPIDURI}/api/"
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
	baseurl = f"{RESOURCEAPPIDURI}/api/"
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
	baseurl = f"{RESOURCEAPPIDURI}/api/alerts/"
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
	baseurl = f"{RESOURCEAPPIDURI}/api/alerts/"
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
	baseurl = f"{RESOURCEAPPIDURI}/api/alerts"
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
