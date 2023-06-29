# DefenderEndpointAPI
# View and manage alerts from 365 defender

import os
import json
import urllib.parse
from urllib.error import HTTPError
import requests
from datetime import datetime, timedelta
from loguru import logger
import argparse

from modules.utils import get_aad_token, strip_tags
from modules.exceptions import *
from modules.sessions import DefenderSesssion
from modules.securitycenter import get_defender_alert, get_defender_alerts
from modules.cloudappsecurity import get_cloudapp_alert, get_cloudapp_resource


def main():
	argsp = argparse.ArgumentParser(description='defenderapitool')
	argsp.add_argument('--defenderalerts','-da', default=False, action='store_true', help='get defender alerts')
	argsp.add_argument('--cloudappalerts','-ca', default=False, action='store_true', help='get cloudappalerts alerts')
	args = argsp.parse_args()
	try:
		def_session = DefenderSesssion()
	except DefenderSessionException as e:
		logger.error(e)
		os._exit(-1)
	all_alerts = []
	dal = []
	cal = []
	if args.defenderalerts:
		all_alerts += def_session.get_defender_data(api_item='alerts')
	if args.cloudappalerts:
		try:
			all_alerts += def_session.get_cloudapp_data(api_item='alerts')
		except TokenException as e:
			logger.error(f'TokenException {e}')
	print(f'all: {len(all_alerts)}')
	for alert in all_alerts:
		print(f'[A] {alert}')

if __name__ == '__main__':
	main()