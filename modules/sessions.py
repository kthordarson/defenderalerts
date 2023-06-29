import os
import requests
import json
from urllib.error import HTTPError
from loguru import logger

from .utils import get_aad_token
from .exceptions import * 


class DefenderSesssion():
	def __repr__(self):
		return f'DefenderSesssion()'

	def __init__(self):
		self.cloudappurl = os.environ.get('CLOUDAPPURL')
		self.defender_session = self.get_defender_session()
		self.cloudapp_session = self.get_clapp_session()

	def get_clapp_session(self):
		token = os.environ.get('CLOUDAPPAPIKEY')
		if not token or not self.cloudappurl:
			raise CloudAppException(f'Missing cloudappapikey or cloudappurl')
		session = requests.Session()
		session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "token " + token
		})
		return session

	def get_defender_session(self):
		try:
			token = get_aad_token()
		except TokenException as e:
			raise DefenderSessionException(e)
		session = requests.Session()
		session.headers.update(
		{
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'Authorization': "Bearer " + token
		})
		return session

	def get_defender_data(self, api_item:str='alerts', status:str='new'):
		"""
		Get list of Alerts from Office365 defender
		Params:
		api_item: name of api to use, default 'alerts'
		status: alert status, default 'new'
		severity: Filter by severity level. 'Informational' 'Low', 'Medium', 'High', Default 'High'
		Returns: json object of alerts
		"""
		apiurl = f"https://api-eu.securitycenter.microsoft.com/api/{api_item}/?$filter=status+eq+'New'&$expand=evidence&top=100"
		try:
			response = self.defender_session.get(apiurl)
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
			logger.warning(f"responsecode={response.status_code} {json_err.get('error').get('code')} {json_err.get('error').get('message')} apiurl={apiurl}")
		elif response.status_code == 404:
			#json_err = json.loads(response.content)
			logger.error(f'notfound responsecode={response.status_code} response.content={response.content} apiurl={apiurl}')
		else:
			logger.error(f'unknown status responsecode={response.status_code} apiurl={apiurl}')
		return None

	def get_cloudapp_data(self, api_item:str='alerts', skip=0, limit=100, alertopen=True, resolutionStatus=0, resolution_status='open'):
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
