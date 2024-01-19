import os
import asyncio
import pandas as pd
import numpy as np
from azure.identity.aio import ClientSecretCredential
from msgraph_beta import GraphServiceClient
from msgraph_beta.generated.security.alerts.alerts_request_builder import AlertsRequestBuilder
from loguru import logger
import csv
from datetime import datetime, timedelta
from msgraph_beta.generated.models.o_data_errors.o_data_error import ODataError
from kiota_abstractions.api_error import APIError
from kiota_abstractions.store.in_memory_backing_store import InMemoryBackingStore

DATEFIELDS = [ 'event_date_time', 'last_modified_date_time','closed_date_time', 'created_date_time','event_date_time','last_modified_date_time', ] # 'last_event_date_time',
EXPANDFIELDS = ['user_states', 'vendor_information',  'additional_data' ]

def create_client():
	credential = ClientSecretCredential(
		os.environ.get('AZURE_TENANT_ID'),
		os.environ.get('AZURE_CLIENT_ID') ,
		os.environ.get('AZURE_CLIENT_SECRET'),
	)
	scopes = ['https://graph.microsoft.com/.default']
	client = GraphServiceClient(credentials=credential, scopes=scopes)
	return client
 
def save_crashed_buffer(buffer):
	cnt = 0

	for b in buffer:
		outfilename = f'getalertscrashed-{datetime.now().day}-{datetime.now().month}-{datetime.now().year}-{datetime.now().hour}-{datetime.now().minute}-{datetime.now().second}-buf{cnt}.csv'
		logger.warning(f'saving buffer to: {outfilename}')
		# outb = pd.DataFrame(b)
		for df in DATEFIELDS:
			try:
				b[df] = b[df].dt.tz_localize(None)
			except Exception as e:
				logger.error(f'{e} {type(e)} df: {df}')
		b.to_csv(outfilename)
		cnt += 1

async def testget_alerts(client):
	buffer = []
	selection = []
	bufcount = 0
	qp = AlertsRequestBuilder.AlertsRequestBuilderGetQueryParameters(top=300)
	rc = AlertsRequestBuilder.AlertsRequestBuilderGetRequestConfiguration(query_parameters=qp)
	rc.headers.add("ConsistencyLevel", "eventual")
	result = await client.security.alerts.get(request_configuration = rc)
	r1 = pd.DataFrame(result.value, index=None)
	logger.debug(f'r1: {r1.columns}')
	for df in DATEFIELDS:
		try:
			r1[df] = r1[df].dt.tz_localize(None)
		except Exception as e:
			logger.error(f'{e} {type(e)} df: {df} r0cols: {r1.columns}')
	return r1
	# r0.to_csv(f'{basename}{bufcount}.csv')
	# data = pd.concat([pd.DataFrame(k.value) for k in results])
	# buffer = buffer.sort_values(by='approximate_last_sign_in_date_time')

def get_columns(result):
	data = pd.DataFrame(result)
	dataisnull = data.isnull().sum().to_dict()
	dataisna = data.isna().sum().to_dict()
	valid_cols = []
	invalid_cols = []
	# check nulls
	for col in dataisnull:
		# print(f'checknull Col: {col} count: {dataisnull[col]}')
		if dataisnull[col] > 0:
			valid_cols.append(col)
		else:
			invalid_cols.append(col)
	# check na
	for col in dataisna:
		# print(f'checkisna Col: {col} count: {dataisna[col]}')
		if dataisna[col] > 0:
			valid_cols.append(col)
		else:
			invalid_cols.append(col)
	
	# check empty cells
	for idx,col in enumerate(data.columns): # InMemoryBackingStore
		if isinstance(type(data[col].values[0]), InMemoryBackingStore):
			logger.warning(f'{idx}/{len(data.columns)} InMemoryBackingStore {col}')
			valid_cols.append(col)
		if isinstance(type(data[col].values[0]), np.datetime64):
			logger.warning(f'{idx}/{len(data.columns)} np.datetime64 {col}')
			valid_cols.append(col)
		if not data[col].values[0]:
			logger.warning(f'{idx}/{len(data.columns)}  valids:{len(valid_cols)} inv:{len(invalid_cols)} nonetype in {col}')
		else:
			try:
				dcount = sum([len(k) for k in data[col].values])
				logger.debug(f'{idx}/{len(data.columns)} valids:{len(valid_cols)} inv:{len(invalid_cols)} checking {col} dcount:{dcount} type: {type(data[col].values[0])}')
			except (TypeError, KeyError) as e:
				if 'NoneType' in str(e):
					dcount = 0
					invalid_cols.append(col)
					logger.error(f'{idx}/{len(data.columns)}  {e} {type(e)} valids:{len(valid_cols)} inv:{len(invalid_cols)}  column {col} datachk:{data[col].values[0]} typedatachk:{type(data[col].values[0])}') 
				else:
					logger.warning(f'{idx}/{len(data.columns)}  {e} {type(e)} valids:{len(valid_cols)} inv:{len(invalid_cols)} column {col} datachk:{data[col].values[0]} typedatachk:{type(data[col].values[0])}') 
					dcount = 1
			# print(f'checkempty Col: {col} count: {dataisna[col]}')
			if dcount > 0:
				valid_cols.append(col)
			else:
				invalid_cols.append(col)
	selection = [k for k in set(valid_cols)]
	[selection.append(k) for k in DATEFIELDS if k not in selection] # add datefields
	invalidselection = [k for k in set(invalid_cols)]
	logger.info(f'validcolumns: {len(valid_cols)} {valid_cols}')
	logger.info(f'invalidselection: {len(invalidselection)} {invalidselection}')
	return selection

async def get_alerts(maxcount=100, maxbuf=300):
	buffer = []
	bufcount = 0
	client = create_client()
	qp = AlertsRequestBuilder.AlertsRequestBuilderGetQueryParameters(top=300)
	rc = AlertsRequestBuilder.AlertsRequestBuilderGetRequestConfiguration(query_parameters=qp)
	rc.headers.add("ConsistencyLevel", "eventual")
	result = await client.security.alerts.get(request_configuration = rc)
	# r1 = pd.DataFrame(result.value)
	# col_selection = get_columns(result.value)
	# logger.debug(f'valid columns {col_selection}')
	r1 = pd.DataFrame(result.value, index=None) #, columns=col_selection)
	buffer.append(r1)
	logger.info(f'res: {len(result.value)} {len(buffer)}')
	# r1.to_csv(f'{basename}{bufcount}.csv')
	while result.odata_next_link:
		client = create_client()
		bufcount +=1
		# result = await client.devices.get(request_configuration = request_configuration)
		try:
			result = await client.security.alerts.with_url(result.odata_next_link).get()
		except (ODataError, APIError) as e:
			logger.error(f'bufcount: {bufcount} ODataError {e} {type(e)} buffer:{len(buffer)}')
			# save_crashed_buffer(buffer)
			break
		except Exception as e:
			logger.error(f'bufcount: {bufcount}  {e} {type(e)} buffer:{len(buffer)}')
			# save_crashed_buffer(buffer)
			break
			# r0.to_csv(f'{basename}{bufcount}.csv')
		# col_selection = get_columns(result.value)
		r0 = pd.DataFrame(result.value, index=None) # , columns=col_selection)
		buffer.append(r0)
		if bufcount >= maxbuf:
			logger.warning(f'bufcount: {bufcount} buffer: {len(buffer)} breaking res: {len(result.value)}  onext: {result.odata_next_link}')
			break
		logger.info(f'res: {len(result.value)} buf: {len(buffer)} bc:{bufcount} onext: {result.odata_next_link}')
	return buffer
	# data = pd.concat([pd.DataFrame(k.value) for k in results])
	# buffer = buffer.sort_values(by='approximate_last_sign_in_date_time')

# $filter : assignedTo, classification, determination, createdDateTime, lastUpdateDateTime, severity, serviceSource and status.
# filterTime = datetime.utcnow() - timedelta(hours = 8)          #If you want to include alerts from longer then an hour, change here (days, weeks)
# filterTime = filterTime.strftime("%Y-%m-%dT%H:%M:%SZ")
# # url = "https://api.securitycenter.microsoft.com/api/alerts?$filter=alertCreationTime+ge+{}".format(filterTime)
# # url = "https://api.securitycenter.microsoft.com/api/machines?$filter=riskScore+eq+'High'
# # apiurl = f"{baseurl}Alerts?$filter=severity+eq+'{severity}' # &$filter=alertCreationTime+ge+{filterTime}"
# datetime.utcnow() - timedelta(weeks=4)
# for k in range(52):
# 	enddate = startdate + timedelta(weeks=1)
# 	print(f'{startdate} {enddate}')
# 	startdate += timedelta(weeks=1)
# filter: createdDateTime ge 2023-01-01T00:00:00Z and createdDateTime lt 2023-01-29T00:00:00Z
# filter: createdDateTime ge 2023-01-01T00:00:00Z and createdDateTime lt 2023-01-29T00:00:00Z 0
# filter: createdDateTime ge 2023-02-01T00:00:00Z and createdDateTime lt 2023-03-01T00:00:00Z
# filter: createdDateTime ge 2023-02-01T00:00:00Z and createdDateTime lt 2023-03-01T00:00:00Z 0
# filter: createdDateTime ge 2023-03-01T00:00:00Z and createdDateTime lt 2023-03-29T00:00:00Z
# filter: createdDateTime ge 2023-03-01T00:00:00Z and createdDateTime lt 2023-03-29T00:00:00Z 0
# filter: createdDateTime ge 2023-04-01T00:00:00Z and createdDateTime lt 2023-04-29T00:00:00Z
# filter: createdDateTime ge 2023-04-01T00:00:00Z and createdDateTime lt 2023-04-29T00:00:00Z 0
# filter: createdDateTime ge 2023-05-01T00:00:00Z and createdDateTime lt 2023-05-29T00:00:00Z
# filter: createdDateTime ge 2023-05-01T00:00:00Z and createdDateTime lt 2023-05-29T00:00:00Z 0
# filter: createdDateTime ge 2023-06-01T00:00:00Z and createdDateTime lt 2023-06-29T00:00:00Z
# filter: createdDateTime ge 2023-06-01T00:00:00Z and createdDateTime lt 2023-06-29T00:00:00Z 0
# filter: createdDateTime ge 2023-07-01T00:00:00Z and createdDateTime lt 2023-07-29T00:00:00Z
# filter: createdDateTime ge 2023-07-01T00:00:00Z and createdDateTime lt 2023-07-29T00:00:00Z 300
# filter: createdDateTime ge 2023-08-01T00:00:00Z and createdDateTime lt 2023-08-29T00:00:00Z
# filter: createdDateTime ge 2023-08-01T00:00:00Z and createdDateTime lt 2023-08-29T00:00:00Z 300
# filter: createdDateTime ge 2023-09-01T00:00:00Z and createdDateTime lt 2023-09-29T00:00:00Z
# filter: createdDateTime ge 2023-09-01T00:00:00Z and createdDateTime lt 2023-09-29T00:00:00Z 300
# filter: createdDateTime ge 2023-10-01T00:00:00Z and createdDateTime lt 2023-10-29T00:00:00Z
# filter: createdDateTime ge 2023-10-01T00:00:00Z and createdDateTime lt 2023-10-29T00:00:00Z 300
# filter: createdDateTime ge 2023-11-01T00:00:00Z and createdDateTime lt 2023-11-29T00:00:00Z
# filter: createdDateTime ge 2023-11-01T00:00:00Z and createdDateTime lt 2023-11-29T00:00:00Z 300
# filter: createdDateTime ge 2023-12-01T00:00:00Z and createdDateTime lt 2023-12-29T00:00:00Z
# filter: createdDateTime ge 2023-12-01T00:00:00Z and createdDateTime lt 2023-12-29T00:00:00Z 381

async def get_alertstestdate():
	buffer = []
	bufcount = 0
	client = create_client()
	# filterTime = datetime.now() - timedelta(hours = 8)
	for k in range(1,13):
		filterTime = datetime(2023,k,1)
		starttime = filterTime.strftime("%Y-%m-%dT%H:%M:%SZ")

		endtime = filterTime + timedelta(weeks=4)
		endtime = datetime.strftime(endtime, format="%Y-%m-%dT%H:%M:%SZ")
		filter = f'createdDateTime ge {starttime} and createdDateTime lt {endtime}'

		qp = AlertsRequestBuilder.AlertsRequestBuilderGetQueryParameters(top=300, filter=filter)
		rc = AlertsRequestBuilder.AlertsRequestBuilderGetRequestConfiguration(query_parameters=qp)
		rc.headers.add("ConsistencyLevel", "eventual")
		print(f'filter: {filter}')
		result = await client.security.alerts.get(request_configuration = rc)
		print(f'filter: {filter} {len(result.value)}')


async def get_alerts_datebatch(maxcount=100, maxbuf=300):
	buffer = []
	bufcount = 0
	client = create_client()
	qp = AlertsRequestBuilder.AlertsRequestBuilderGetQueryParameters(top=300)
	rc = AlertsRequestBuilder.AlertsRequestBuilderGetRequestConfiguration(query_parameters=qp)
	rc.headers.add("ConsistencyLevel", "eventual")
	result = await client.security.alerts.get(request_configuration = rc)
	# r1 = pd.DataFrame(result.value)
	# col_selection = get_columns(result.value)
	# logger.debug(f'valid columns {col_selection}')
	r1 = pd.DataFrame(result.value, index=None) #, columns=col_selection)
	buffer.append(r1)
	logger.info(f'res: {len(result.value)} {len(buffer)}')
	# r1.to_csv(f'{basename}{bufcount}.csv')
	while result.odata_next_link:
		client = create_client()
		bufcount +=1
		# result = await client.devices.get(request_configuration = request_configuration)
		try:
			result = await client.security.alerts.with_url(result.odata_next_link).get()
		except (ODataError, APIError) as e:
			logger.error(f'bufcount: {bufcount} ODataError {e} {type(e)} buffer:{len(buffer)}')
			# save_crashed_buffer(buffer)
			break
		except Exception as e:
			logger.error(f'bufcount: {bufcount}  {e} {type(e)} buffer:{len(buffer)}')
			# save_crashed_buffer(buffer)
			break
			# r0.to_csv(f'{basename}{bufcount}.csv')
		# col_selection = get_columns(result.value)
		r0 = pd.DataFrame(result.value, index=None) # , columns=col_selection)
		buffer.append(r0)
		if bufcount >= maxbuf:
			logger.warning(f'bufcount: {bufcount} buffer: {len(buffer)} breaking res: {len(result.value)}  onext: {result.odata_next_link}')
			break
		logger.info(f'res: {len(result.value)} buf: {len(buffer)} bc:{bufcount} onext: {result.odata_next_link}')
	return buffer
	# data = pd.concat([pd.DataFrame(k.value) for k in results])
	# buffer = buffer.sort_values(by='approximate_last_sign_in_date_time')


async def result_buffer_pd(buffer):
	results = pd.DataFrame()
	for idx,r in enumerate(buffer):
		try:
			results = pd.concat([results, r])
		except AttributeError as e:
			logger.error(f'{idx}/{len(buffer)} {e} {type(r)} rlen: {len(r.values)} cols: {r.columns}')
		logger.debug(f'{idx}/{len(buffer)} bufferconcat {type(r)} {len(r.values)} {len(results)}')
	return results

async def fixdates(results):
	#results = pd.concat([results_input])
	for datefield in DATEFIELDS:
		try:
			results[datefield] = results[datefield].dt.tz_localize(None)
		except Exception as e:
			logger.error(f'{e} {type(e)} datefield: {datefield} ')
	return results


async def mainloop():
	alertbuffer = await get_alerts()
	logger.debug(f'alertbuffer: {len(alertbuffer)}')
	alertdata = await result_buffer_pd(alertbuffer)
	defenderalerts = await fixdates(alertdata)
	baseoutname = 'defenderalerts'
	outfilename = f'{baseoutname}-{datetime.now().day}-{datetime.now().month}-{datetime.now().year}-{datetime.now().hour}-{datetime.now().minute}-{datetime.now().second}.csv'
	outfilenamex = f'{baseoutname}-{datetime.now().day}-{datetime.now().month}-{datetime.now().year}-{datetime.now().hour}-{datetime.now().minute}-{datetime.now().second}.xlsx'
	defenderalerts.to_csv(outfilename)
	defenderalerts.to_excel(outfilenamex)

if __name__ == '__main__':
	
	logger.debug(f'')
	asyncio.run(mainloop())
	#asyncio.run(get_applications())
