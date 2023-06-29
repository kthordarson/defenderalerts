import os
import requests
import json
from urllib.error import HTTPError
from loguru import logger
from msticpy.data.data_providers import QueryProvider

from .utils import get_aad_token
from .exceptions import DefenderSessionException, CloudAppException, TokenException, SchemaException, WrongReasonException, MissingResource, MDATPException
resourceAppIdUri = 'https://api-eu.securitycenter.microsoft.com'

class CustomSession():
	def __repr__(self):
		return f'CustomSession( data={len(self.data)} )'
	def __init__(self):
		self.session = self.get_session()
		self.data = []

	def get_session(self):
		try:
			token = get_aad_token()
		except TokenException as e:
			raise e
		session = requests.Session()
		session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + token,
			'authorization_uri': resourceAppIdUri
		})
		return session

	def get_data(self, query='DeviceProcessEvents | limit 10'):
		"""
		:param query: query to run, default DeviceProcessEvents
			DeviceFileEvents, DeviceProcessEvents, AlertInfo, AlertEvidence, DeviceNetworkEvents, DeviceLogonEvents, DeviceRegistryEvents
			DeviceEvents, DeviceImageLoadEvents, IdentityLogonEvents, IdentityQueryEvents
		:return: json data
		"""
		data = {
			'Query': query,
		}
		url = 'https://api-eu.securitycenter.microsoft.com/api/advancedqueries/run'
		jdata = json.dumps({ 'Query' : query }).encode("utf-8")
		response = self.session.post(url, data=jdata)

class MDATPSession():
	def __repr__(self):
		return f'MDATPSession( data={len(self.mdatp_data)} )'

	def __init__(self):
		self.mdatp = QueryProvider("MDATP")
		self.mdatp_data = []

	def get_data(self):
		rawmdatp_data = None
		logger.debug(f'[MDATP] getdata connected: {self.mdatp.connected}')
		if not self.mdatp.connected:
			try:
				self.mdatp.connect()
			except Exception as e:
				raise MDATPException(e)
		else:
			try:
				rawmdatp_data = self.mdatp.MDATP.list_alerts()
				logger.debug(f'[MDATP] rawmdatp_data {type(rawmdatp_data)}')
			except Exception as e:
				raise MDATPException(e)
			alertlist = json.loads(rawmdatp_data.to_json(orient="records"))
			self.mdatp_data = alertlist
			logger.debug(f'[MDATP] alertlist {len(self.mdatp_data)}')
			return self.mdatp_data

class DefenderSesssion():
	def __repr__(self):
		return f'DefenderSesssion( defender={len(self.defender_data)} )'

	def __init__(self):
		self.defender_session = self.get_session()
		self.defender_data = []

	def get_session(self):
		try:
			token = get_aad_token()
		except TokenException as e:
			raise DefenderSessionException(e)
		session = requests.Session()

		session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + token,
			'authorization_uri': resourceAppIdUri
		})
		return session

	def get_data(self, api_item:str='alerts', status:str='new'):
		"""
		Get list of Alerts from Office365 defender
		Params:
		api_item: name of api to use, default 'alerts'
		status: alert status, default 'new'
		severity: Filter by severity level. 'Informational' 'Low', 'Medium', 'High', Default 'High'
		Returns: json object of alerts
		"""
		apiurl = f"https://api-eu.securitycenter.microsoft.com/api/{api_item}/?$filter=status+eq+'{status}'&$expand=evidence&top=100"
		hasnext = True
		records = []
		self.defender_data = []
		while hasnext:
			try:
				response = self.defender_session.get(apiurl)
			except HTTPError as e:
				errmsg = f'{type(e)} {e} url = {apiurl}'
				raise DefenderSessionException(errmsg)
			if response.status_code != 200:
				logger.warning(f'Error: {response.status_code} text: {response.text}')
				hasnext = False
			if response.status_code == 200:
				json_response = json.loads(response.content)
				records += json_response['value']
				self.defender_data += records
				logger.debug(f'Getting defenderdata hn: {hasnext} r: {len(response.content)} jr: {len(json_response)} r: {len(records)} defender_data: {len(self.defender_data)}')
				if not '@odata.nextLink' in json_response:
					hasnext = False
				else:
					apiurl = json_response['@odata.nextLink']
		return self.defender_data

class CloudappsecuritySession():
	def __repr__(self):
		return f'CloudappsecuritySession( data={len(self.cloudapp_data)} )'

	def __init__(self):
		self.cloudappurl = os.environ.get('CLOUDAPPURL')
		self.cloudapp_session = self.get_session()
		self.cloudapp_data = []

	def get_session(self):
		token = os.environ.get('CLOUDAPPAPIKEY')
		if not token or not self.cloudappurl:
			raise CloudAppException(f'Missing cloudappapikey or cloudappurl')
		session = requests.Session()
		session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "token " + token,
			'authorization_uri': resourceAppIdUri
		})
		return session

	def get_data(self, api_item:str='alerts', skip=0, limit=100, alertopen=True, resolutionStatus=0, resolution_status='open'):
		"""
		Get list of alerts from Cloud app security portal
		Params:
		api_item: alerts, activities, discovery, entities, files, subnet. default = 'alerts'
		skip: skip n items. Default 0.
		limit: max items to fectch in each request. Default 100.
		alertopen: True = fetch only open alerts, False = fetch both open and closed alerts. Default True.
		resolutionStatus: 0 = open, 1 = dismissied, 2 = resolved, 3 falsepositive, 4 = benign, 5 = truepositive. default = 0
		resolution_status: 0 = open, 1 = dismissed, 2 = resolved. default = open
		"""
		# filters https://learn.microsoft.com/en-us/defender-cloud-apps/api-alerts#filters
		if api_item == 'alerts':
			baseurl = f'https://{self.cloudappurl}/api/v1/alerts/'
		elif api_item == 'activities':
			baseurl = f'https://{self.cloudappurl}/api/v1/activities/'
		elif api_item == 'discovery':
			# todo fix
			baseurl = f'https://{self.cloudappurl}/api/v1/discovery/'
			# POST /api/v1/discovery/discovered_apps/categories/
			# GET /api/discovery/streams/
		elif api_item == 'entities':
			baseurl = f'https://{self.cloudappurl}/api/v1/entities/'
		elif api_item == 'files':
			baseurl = f'https://{self.cloudappurl}/api/v1/files/'
		elif api_item == 'subnet':
			baseurl = f'https://{self.cloudappurl}/api/v1/subnet/'
		else:
			raise MissingResource(f'Missing api resource item')

		data = {'filters': {'resolutionStatus': {'eq': resolutionStatus}}, 'skip': skip, 'limit': limit}
		records = []
		self.cloudapp_data = []
		hasnext = True
		MAX_RECORDS = 500
		while hasnext:
			try:
				response = self.cloudapp_session.post(url=baseurl, json=data)
			except HTTPError as e:
				logger.error(f'{type(e)} {e} url = {baseurl}')
			if response.status_code == 401 and 'Invalid token' in response.text:
				raise TokenException(f'Token invalid: baseurl: {baseurl} headers: {self.cloudapp_session.headers}')
			if response.status_code != 200:
				hasnext = False
				logger.warning(f'[!] RespError {response.status_code} {response.text}')
			if response.status_code == 200:
				json_response = json.loads(response.content)
				logger.debug(f'Getting cloudappdata hn: {hasnext} r: {len(response.content)} jr: {len(json_response)} r: {len(records)}')
				try:
					json_values = json_response.get('data', [])
				except KeyError as e:
					logger.warning(f'{type(e)} {e} baseurl: {baseurl} json: {json_response}')
				if len(json_values) == 0:
					logger.warning(f'No alerts! jsonresp: {json_response}')
				else:
					records += json_values
					self.cloudapp_data += records
				hasnext = json_response.get('hasNext', False)
				if len(records) >= MAX_RECORDS:
					logger.warning(f'Reached MAX_RECORDS={MAX_RECORDS} records = {len(records)}')
					hasnext = False
		return self.cloudapp_data
