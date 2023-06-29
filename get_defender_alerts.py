#!/usr/bin/python
# DefenderEndpointAPI
# View and manage alerts from 365 defender

import os
from loguru import logger
import argparse

from modules.exceptions import DefenderSessionException, CloudAppException, TokenException, SchemaException, WrongReasonException, MissingResource, MDATPException
from modules.sessions import DefenderSesssion, CloudappsecuritySession, MDATPSession

def main():
	argsp = argparse.ArgumentParser(description='defenderapitool')
	argsp.add_argument('--defenderalerts','-da', default=False, action='store_true', help='get defender alerts')
	argsp.add_argument('--cloudappalerts','-ca', default=False, action='store_true', help='get cloudappalerts alerts')
	argsp.add_argument('--mdatpalerts','-md', default=False, action='store_true', help='get mdatp alerts')
	args = argsp.parse_args()
	defender = None

	all_alerts = []
	dal = []
	cal = []

	if args.defenderalerts:
		try:
			defender = DefenderSesssion()
			all_alerts += defender.get_data(api_item='alerts')
		except DefenderSessionException as e:
			logger.error(f'DefenderSessionException {e}')

	if args.cloudappalerts:
		try:
			cloudapp = CloudappsecuritySession()
			all_alerts += cloudapp.get_data(api_item='alerts')
		except CloudAppException as e:
			logger.error(f'CloudAppException {e}')

	if args.mdatpalerts:
		try:
			mdatp = MDATPSession()
			all_alerts += mdatp.get_data(api_item='alerts')
		except MD as e:
			logger.error(e)
		except MDATPException as e:
			logger.error(f'MDATPException {e}')

	print(f'all: {len(all_alerts)}')
	for alert in all_alerts:
		print(f'[A] {alert}')

if __name__ == '__main__':
	main()