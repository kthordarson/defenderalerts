import os
import requests
from requests import TooManyRedirects
import json
from urllib.error import HTTPError
from loguru import logger
import urllib3

from msticpy.data.data_providers import QueryProvider

from .utils import get_aad_token, get_aad_session
from .exceptions import DefenderSessionException, CloudAppException, TokenException, SchemaException, WrongReasonException, MissingResource, MDATPException
from .constants import RESOURCEAPPIDURI, MAX_RECORDS

urllib3.disable_warnings()

class BaseSesssion():
	data = []
	session = requests.Session()
	authenticated = False
	result = -1

	def __init__(self, name):
		self.name = name

	def __repr__(self):
		return f'{self.name}( data={len(self.data)} auth:{self.authenticated} r:{self.result})'


class CustomSession(BaseSesssion):
	def __init__(self, name):
		super().__init__(self)
		self.name = name		

	def update_session_token(self, uri=RESOURCEAPPIDURI):
		try:
			token = get_aad_token()
		except TokenException as e:
			raise e
		self.session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + token,
			'authorization_uri': uri
		})

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

class GraphSession():
	# apps = json.loads(session.get('https://graph.microsoft.com/v1.0/applications').content)
	# https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0&tabs=http
	def __repr__(self):
		return f'GraphSession( data={len(self.data)} )'
	def __init__(self):
		self.baseurl = 'https://graph.microsoft.com'
		self.session = self.get_session()
		self.data = []

	def get_session(self):
		try:
			token = get_aad_token(AppIdUri=self.baseurl)
		except TokenException as e:
			raise e
		session = requests.Session()
		session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + token
		})
		return session
	
	def runhunt(self, query):
		# POST /security/runHuntingQuery
		testq = {"Query": "DeviceProcessEvents | limit 2"}
		url  = f"{self.baseurl}/security/runHuntingQuery"
		response = self.session.post(url, json=testq)
		return json.loads(response.content)['value']
	
	def get_data(self, item='alerts', status='newAlert', top=10, skip=0, limit=10):
		"""
		item: alerts, alerts_v2, incidents
		"""
		# data = {'filters': {'status': {'eq': status}}, 'skip': skip, 'limit': limit}
		# url  = f"{self.baseurl}/v1.0/security/{item}?&$top={top}"
		url  = f"{self.baseurl}/v1.0/security/{item}?$filter=status+eq+'{status}'"
		response = self.session.get(url)
		logger.debug(f'{self} {url} resp: {response.status_code}')
		try:
			value = json.loads(response.content)['value']
		except KeyError as e:
			logger.error(f'{self} {e} resp: {response.status_code} {response.text}')
			value = {}
		return value

class FortiSession():
	def __repr__(self):
		return f'FortiSession({self.hostname}:{self.port} data={len(self.data)} )'

	def __init__(self, hostname:str='', port:str='443'):
		self.hostname = hostname or os.environ.get('fortiapiurl')
		self.port = port or '443'
		self.api_url = f'https://{self.hostname}:{self.port}/api/v1'
		session = self.get_session()
		self.data = []

	def get_session(self):
		session = requests.Session()
		return session

	def get_forti_sid(self):
		sid = 'None'
		# POST https://<ip address>:<port>/fpc/api/login
		fortiapiuser = os.environ.get('fortiapiuser', None)
		fortiapipass = os.environ.get('fortiapipass', None)
		# payload = {'user' : fortiapiuser,'password' : fortiapipass			}
		self.session.headers.update(
		{
			'Content-Type': 'application/x-www-form-urlencoded',
			'Accept': '*/*'
		})
		execparams = [ { 'url': 'sys/login/user', 'data': [ { 'passwd': fortiapipass, 'user': fortiapiuser } ] } ]  
		payloadx = {'id':0, 'jsonrpc':'2.0','session' : None,'method': 'exec','params': [{'url': '/sys/login/user', 'data': {'passwd': fortiapiuser, 'user': fortiapipass} } ]}
		payloadxx =  {'id':0, 'jsonrpc':'2.0','session' : None,'method': 'exec','params': {'url':  '/sys/login/user', 'data': {'passwd': fortiapiuser, 'user': fortiapipass} } }
		payload =  {'id':0, 'jsonrpc':'2.0','session' : None,'method': 'exec','params': execparams}
		response = self.session.post(f'{self.hostname}/jsonrpc', json=payload)
		return sid

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

class QuerySession(BaseSesssion):

	def __init__(self, name="MDATP"):
		"""
		params: 
		name: "MDE", "M365D", "MDATP"
		"""
		super().__init__(self)
		self.name = name	

	def get_data(self):
		rawmdatp_data = None
		mdatp = QueryProvider(self.name)
		logger.debug(f'{self} getdata connected: {mdatp.connected}')
		if not mdatp.connected:
			try:
				mdatp.connect()
			except Exception as e:
				raise MDATPException(e)
		try:
			# rawmdatp_data = mdatp.MDATP.list_alerts()
			rawmdatp_data = mdatp.MDATP.list_alertsinfo()
			logger.debug(f'{self} rawmdatp_data {type(rawmdatp_data)}')
		except Exception as e:
			raise MDATPException(e)
		alertlist = json.loads(rawmdatp_data.to_json(orient="records"))
		self.data = alertlist
		logger.debug(f'{self} alertlist {len(self.data)}')

class DefenderSesssion(BaseSesssion):

	def __init__(self, name='DefenderSession'):
		super().__init__(self)
		self.name = name

	def update_session(self, uri=RESOURCEAPPIDURI):
		try:
			token = get_aad_token()
		except TokenException as e:
			self.authenticated = False
			raise DefenderSessionException(e)

		self.session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + token,
			'authorization_uri': uri
		})
		self.authenticated = True

	def get_incidents(self, pageSize=50, alertStatus=['New','InProgress'], severity=[256,128,64], pageIndex=1, lookBackInDays=3):
		tenant_id = os.environ.get('defenderTenantID')
		referer = 'https://security.microsoft.com/incidents'
		session, token = get_aad_session(AppIdUri='https://security.microsoft.com')
		session.headers.update(
			{
				'Host' : 'security.microsoft.com',
				'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
				'tenant-id' : tenant_id,
				'X-tid' : tenant_id,
				'X-ClientPage' : 'incidents@wicd-ine',
				'Referer' : referer,
				'Origin' : referer,
				'Accept' : 'application/json, text/plain, */*',
				'Content-Type' : 'application/json',
				'Authorization': "Bearer " + token,
				'authority': 'security.microsoft.com',
				'request-context': 'appId=cid-v1:9f356be6-73bf-45f7-9a98-a86fc98ec84f', # appid ?
				# 'cookie' : session.cookies()
			})
		# get
		# geturl = 'https://security.microsoft.com/apiproxy/mtp/incidentDashboard/Dashboard/ActiveIncidentsSummary'
		# post
		posturl = 'https://security.microsoft.com/apiproxy/mtp/incidentQueue/incidents/alerts'
		# https://security.microsoft.com/apiproxy/mtp/incidentQueue/incidents/filters?name=systemTag%2CcustomTag%2CalertPolicyIds
		# https://security.microsoft.com/apiproxy/mtp/incidentQueue/incidents/alerts
		# data-raw '{"isDexLicense":false,"isStatusFilterEnable":false,"pageSize":40,"isMultipleIncidents":true,"alertStatus":["New","InProgress"],"severity":[256,128,64],"lookBackInDays":"7","pageIndex":1}'
		json_data = {
				'isStatusFilterEnable': 'false',
				'isDexLicense': 'false',
				'pageSize': pageSize,
				'lookBackInDays': f'"{lookBackInDays}"',
				'isMultipleIncidents': True,
				'alertStatus': alertStatus,
				'severity': severity,
				'pageIndex': pageIndex,
				}
		try:
			response = session.post(posturl, json=json_data, allow_redirects=False)
		except TooManyRedirects as e:
			logger.warning(f'{e} {type(e)} url: {posturl} data: {json_data} headers: {self.session.headers}')
			response = {}
		except Exception as e:
			logger.error(f'{e} {type(e)} url: {posturl} data: {json_data} headers: {self.session.headers}')
			response = {}
		return response

	def get_data(self, api_item:str='alerts', status:str='new', severity:str='High'):
		"""
		Get list of Alerts from Office365 defender
		Params:
		api_item: name of api to use, default 'alerts'
		status: alert status, default 'new'
		severity: Filter by severity level. 'Informational' 'Low', 'Medium', 'High', Default 'High'
		Returns: json object of alerts
		"""
		# apiurl = f"{baseurl}Alerts?$filter=severity+eq+'{severity}' # &$filter=alertCreationTime+ge+{filterTime}"
		if not self.authenticated:
			self.update_session()
		filterq = f'{api_item}?$filter=Status eq {status} and Severity eq {severity}'
		apiurl = f"https://api-eu.securitycenter.microsoft.com/api/{api_item}/?$filter=status+eq+'{status}'&$expand=evidence&top=100"
		hasnext = True
		records = []
		while hasnext:
			try:
				response = self.session.get(apiurl)
				self.result = response.status_code
			except HTTPError as e:
				errmsg = f'{type(e)} {e} url = {apiurl}'
				self.authenticated = False
				raise DefenderSessionException(errmsg)
			if response.status_code != 200:
				logger.warning(f'{self} Error: {response.status_code} text: {response.text}')
				self.authenticated = False
				hasnext = False
				return response.status_code				
			if response.status_code == 200:
				json_response = json.loads(response.content)
				records += json_response['value']
				logger.debug(f'{self} hn: {hasnext} r: {len(response.content)} jr: {len(json_response)} r: {len(records)}')
				if not '@odata.nextLink' in json_response:
					hasnext = False
				else:
					apiurl = json_response['@odata.nextLink']
				if len(records) >= MAX_RECORDS:
					logger.warning(f'{self} Reached MAX_RECORDS={MAX_RECORDS} records = {len(records)}')
					hasnext = False
		# self.data = records
		logger.info(f'{self} records={len(records)}')
		return records

class CloudappsecuritySession(BaseSesssion):

	def __init__(self, name='CloudAppSecurity'):
		super().__init__(self)
		self.name = name
		self.cloudappurl = os.environ.get('CLOUDAPPURL')

	def update_session(self):
		token = os.environ.get('CLOUDAPPAPIKEY')
		if not token or not self.cloudappurl:
			self.authenticated = False
			raise CloudAppException(f'Missing cloudappapikey or cloudappurl')
		self.session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "token " + token,
			'authorization_uri': RESOURCEAPPIDURI
		})
		self.authenticated = True

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
		if not self.authenticated:
			self.update_session()
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
		hasnext = True
		while hasnext:
			try:
				response = self.session.post(url=baseurl, json=data)
				self.result = response.status_code
			except HTTPError as e:
				errmsg = f'{self}  {type(e)} {e} url = {baseurl}'
				self.authenticated = False
				raise CloudAppException(errmsg)
			if response.status_code == 401 and 'Invalid token' in response.text:
				self.authenticated = False
				raise TokenException(f'{self}  Token invalid: baseurl: {baseurl} headers: {self.session.headers}')
			if response.status_code != 200:
				hasnext = False
				self.authenticated = False
				errmsg = f'{self}  RespError {response.status_code} {response.text}'
				raise CloudAppException(errmsg)
			if response.status_code == 200:
				json_response = json.loads(response.content)
				logger.debug(f'{self} hn: {hasnext} r: {len(response.content)} jr: {len(json_response)} r: {len(records)}')
				try:
					json_values = json_response.get('data', [])
				except KeyError as e:
					errmsg = f'{self}  {type(e)} {e} baseurl: {baseurl} json: {json_response}'
					raise CloudAppException(errmsg)
				hasnext = json_response.get('hasNext', False)
				if len(json_values) == 0:
					logger.warning(f'{self} hasnext:{hasnext} No alerts! jsonresp: {json_response}')
				else:
					records += json_values					
				if len(records) >= MAX_RECORDS:
					logger.warning(f'{self} Reached MAX_RECORDS={MAX_RECORDS} records = {len(records)} hasnext:{hasnext}')
					hasnext = False
		self.data = records
		return self.result
