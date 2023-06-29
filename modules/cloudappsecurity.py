import os
import json
from urllib.error import HTTPError
import requests
from loguru import logger

from .exceptions import *

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
