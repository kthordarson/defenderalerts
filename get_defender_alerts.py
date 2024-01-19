#!/usr/bin/python
# DefenderEndpointAPI
# View and manage alerts from 365 defender

import os
from loguru import logger
import argparse

from modules.exceptions import DefenderSessionException, CloudAppException, TokenException, SchemaException, WrongReasonException, MissingResource, MDATPException
from modules.sessions import DefenderSesssion, CloudappsecuritySession, GraphSession, QuerySession

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
	defender = None
	cloudapp = None
	mdatp = None
	if args.defenderalerts:
		defender = DefenderSesssion()
		try:			
			dres = defender.get_incidents()
		except DefenderSessionException as e:
			logger.error(f'{e} {defender}')

	if args.cloudappalerts:
		cloudapp = CloudappsecuritySession()
		try:			
			clres = cloudapp.get_data(api_item='alerts')
		except CloudAppException as e:
			logger.error(f'{e} {cloudapp}')

	if args.mdatpalerts:
		mdatp = QuerySession(name='MDATP')
		try:			
			mdres = mdatp.get_data(api_item='alerts')
		except MDATPException as e:
			logger.error(f'{e} {mdatp}')
		except MDATPException as e:
			logger.error(f'MDATPException {e}')

	print(f'defender: {defender} cloudapp: {cloudapp} mdatp: {mdatp}')
	for alert in all_alerts:
		print(f'[A] {alert}')

if __name__ == '__main__':
	main()