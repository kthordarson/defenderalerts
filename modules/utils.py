import requests
from html.parser import HTMLParser
import os
import urllib
from loguru import logger
from io import BytesIO, StringIO
from urllib.error import HTTPError
import json

from .exceptions import TokenException
from .constants import RESOURCEAPPIDURI
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


def get_aad_token(AppIdUri:str=RESOURCEAPPIDURI):
	"""
	returns aadtoken
	Must set enviorment variables with valid credentials for the registered azure enterprise application
	"""
	AppID = os.environ.get('defenderappid')
	TenantID = os.environ.get('defenderTenantID')
	Value = os.environ.get('defenderSecretValue')
	SecretID = os.environ.get('defenderSecretID')
	if not AppID or not TenantID or not Value or not SecretID:
		raise TokenException(f'Missing authinfo....')
	url = f"https://login.microsoftonline.com/{TenantID}/oauth2/token"

	body = {'resource': AppIdUri, 'authorization_uri': AppIdUri, 'client_id': AppID, 'client_secret': Value, 'grant_type': 'client_credentials'}
	data = urllib.parse.urlencode(body).encode("utf-8")
	req = urllib.request.Request(url, data)
	try:
		response = urllib.request.urlopen(req)
	except HTTPError as e:
		logger.error(e)
		raise TokenException(f'Error getting token {e} appid:{AppID} tid:{TenantID} v:{Value} s:{SecretID}')
	except Exception as e:
		logger.error(e)
		raise TokenException(f'Unhandled Exception {e} appid:{AppID} tid:{TenantID} v:{Value} s:{SecretID}')
	jsonResponse = json.loads(response.read())
	aadToken = jsonResponse["access_token"]
	logger.info(f'got aadtoken: {len(aadToken)} AppIdUri:{AppIdUri}')
	return aadToken

def get_aad_session(AppIdUri:str=RESOURCEAPPIDURI):
	"""
	returns aadtoken
	Must set enviorment variables with valid credentials for the registered azure enterprise application
	"""
	session = requests.Session()
	AppID = os.environ.get('defenderappid')
	TenantID = os.environ.get('defenderTenantID')
	Value = os.environ.get('defenderSecretValue')
	SecretID = os.environ.get('defenderSecretID')
	if not AppID or not TenantID or not Value or not SecretID:
		raise TokenException(f'Missing authinfo....')
	url = f"https://login.microsoftonline.com/{TenantID}/oauth2/token"

	body = {'resource': AppIdUri, 'authorization_uri': AppIdUri, 'client_id': AppID, 'client_secret': Value, 'grant_type': 'client_credentials'}
	# data = urllib.parse.urlencode(body).encode("utf-8")
	# req = urllib.request.Request(url, data)
	try:
		response = session.post(url, data=body)
	except HTTPError as e:
		logger.error(e)
		raise TokenException(f'Error getting token {e} appid:{AppID} tid:{TenantID} v:{Value} s:{SecretID}')
	except Exception as e:
		logger.error(e)
		raise TokenException(f'Unhandled Exception {e} appid:{AppID} tid:{TenantID} v:{Value} s:{SecretID}')
	jsonResponse = json.loads(response.content)
	aadToken = jsonResponse["access_token"]
	logger.info(f'got aadtoken: {len(aadToken)} AppIdUri:{AppIdUri}')
	return session, aadToken

