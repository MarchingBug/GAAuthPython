
import json
import logging
import os

import azure.functions as func
from oauth2client.service_account import ServiceAccountCredentials

from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    
    try:
       logging.info("Python HTTP trigger function processed a request.")
       logging.info("about to get keyvault")
       keyvaultName = os.environ['KEY_VAULT_URL']      
       logging.info(keyvaultName)
       kvClient = SecretClient(vault_url=keyvaultName, credential=DefaultAzureCredential())
       logging.info("got key vault client")

       keyJson = kvClient.get_secret("GAAuthToken").value
       logging.info("got keyjson")
       
       SCOPES = ['https://www.googleapis.com/auth/analytics.readonly']
       
       keyfile_dict = json.loads(keyJson)
       token = ServiceAccountCredentials.from_json_keyfile_dict(keyfile_dict, SCOPES).get_access_token().access_token       
           
       logging.info("token is " + token)
 
       return func.HttpResponse("{\"token\":\"" + token + "\"}", status_code=200)
      
    except Exception as ex:
        logging.info(ex.__cause__)
        return func.HttpResponse(ex.__cause__, status_code=400)


