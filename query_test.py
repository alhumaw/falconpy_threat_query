from falconpy import Hosts, APIHarnessV2
import os
import json
import pyfiglet
from tabulate import tabulate

CLIENT_ID = os.environ["FALCON_CLIENT_ID"]
CLIENT_SECRET = os.environ["FALCON_CLIENT_SECRET"]

""" Return API Handler Object """
def api_init():
    falcon = APIHarnessV2(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    return falcon

def query_actors(resources):
    actors = []
    for parent in resources:
        for key in parent:
            if key == 'name':
                actors.append(parent[key])
    return actors

def query_intel_actor_entities(query, falcon):
    query = query.replace(" ","-").lower()
    try:
        intel = falcon.command(action="QueryIntelActorEntities",q=query)['body']['resources']
        actors=query_actors(intel)
        return actors
    except IndexError:
        print("Filter Error")

def find_relevance(filter,falcon):
    actors = query_intel_actor_entities(filter,falcon)
    print(f"\nFound {len(actors)} values related to {filter}\n")
    if len(actors) > 1:
        print(actors)
        exact_actor = input("Please choose from the follow actors\n")
        return exact_actor
    return filter









class Actor:
    
    def __init__(self, handler, queried_value):
        self.name = ''
        self.handler = handler
        self.threat_id = 0
        self.threats = ''
        self.url = ''
        self.queried_value = queried_value
        
    '''Returns a dictionary of actor info'''
    def get_basic_info(self):
        name = self.queried_value.replace(" ","-").lower()
        intel = self.handler.command(action="QueryIntelActorEntities",q=name)['body']['resources']
        return intel

    def get_threat_info(self, threat):
        intel = self.handler.command(action="QueryIntelIndicatorEntities", q=threat)
        return intel

    def set_threat_id(self, threat_id):
        self.threat_id = threat_id
    
    def set_threats(self, threats):
        self.threats = threats
    
    def set_name(self, name):
        self.name = name
    
    def set_url(self, url):
        self.url = url


'''
    1) Which actor do we want to query
        - find_results of actor
    2) Found # results for actor
        - if results > 1
            - please choose from these options
    3) Use API & ThreadPoolExecutor to return values relevant to result
    

'''

def print_actor_info(actor):
    name = pyfiglet.figlet_format(actor.name,justify="center")

    seperator = "="*90

    table = [["THREATS RELATED", actor.threats], ["IDENTIFIER", actor.threat_id],["URL",actor.url]]
    print(f"{seperator}")
    print(f"{name}")
    print(tabulate(table, tablefmt="heavy_grid"))
    print(f"{seperator}")
   

def generate_actor_profile(query):
    actor = Actor(falcon,query)
    intel = actor.get_basic_info()
    character_list = intel[0]
    actor.set_name(character_list['name'])
    actor.set_threat_id(character_list['id'])
    actor.set_url(character_list['url'])
    try:
        threat_dict = character_list['develops_threats'][0]
        actor.set_threats(threat_dict['family_name'])
    except KeyError:
        threat_dict = character_list["uses_threats"][0]
        actor.set_threats(threat_dict['family_name'])
    return actor


def begin_search(falcon):
    query= input("Which threat actor would you like to query? ")
    query = find_relevance(query,falcon)
    #Generate new Actor
    actor = generate_actor_profile(query)
    #generate threat info
    #send to print method
    print_actor_info(actor)

if __name__ == "__main__":
    falcon = api_init()
    begin_search(falcon)
    

    #print_actor_info(intel)





