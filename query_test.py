from falconpy import APIHarnessV2
import os
import json
import pyfiglet
from tabulate import tabulate


def api_init():
    """Return API Handler Object"""
    CLIENT_ID = os.environ["FALCON_CLIENT_ID"]
    CLIENT_SECRET = os.environ["FALCON_CLIENT_SECRET"]
    falcon = APIHarnessV2(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    return falcon

class Actor:
    """Actor generation class"""
    def __init__(self, handler, queried_value):
        self.queried_value = queried_value
        self.handler = handler
        self.mitre = ()
        self.threat_id = 0
        self.threats = ''
        self.name = ''
        self.url = ''
        self.desc = ''

            
    def get_basic_info(self):
        '''Returns a dictionary of actor info'''
        name = self.queried_value.replace(" ","-").lower()
        intel = self.handler.command(action="QueryIntelActorEntities",q=name)['body']['resources']
        return intel
    
    
    def get_threat_info(self, threat):
        '''Returns a dictionary of threat info'''
        intel = self.handler.command(action="GetMitreReport",actor_id=self.threat_id, format="json")
        return intel
    
    def set_threat_id(self, threat_id):
        self.threat_id = threat_id
    
    def set_threats(self, threats):
        self.threats = threats
    
    def set_name(self, name):
        self.name = name
    
    def set_url(self, url):
        self.url = url
    
    def set_mitre(self, mitre):
        self.mitre = mitre

    def set_desc(self, desc):
        self.desc = desc


def print_actor_info(actor):
    """Depending on keys found, formats data onto console"""
    seperator = "="*90
    name = pyfiglet.figlet_format(actor.name,justify="center")
    if len(actor.mitre) > 1:
        profile = [["THREATS RELATED", actor.threats], ["IDENTIFIER", actor.threat_id],["URL",actor.url]]
        print(f"{seperator}\n{name}\n{tabulate(profile, tablefmt="heavy_grid")}")
        mitre_connections = '\n'.join(actor.mitre)
        mitre = [["MITRE CONNECTIONS"],[mitre_connections]]
        print(f"{tabulate(mitre, tablefmt='heavy_grid', headers="firstrow")}\n{seperator}")
    else:
        profile = [["IDENTIFIER", actor.threat_id],["URL",actor.url]]
        print(f"{seperator}\n{name}\n{tabulate(profile, tablefmt="heavy_grid")}")
        print(actor.desc.center(65))
        print(f"\n{seperator}")

def chunk_long_description(desc: str, col_width: int = 80) -> str:
    """Chunk a long string by delimiting with CR based upon column length."""
    desc_chunks = []
    chunk = ""
    for word in desc.split():
        new_chunk = f"{chunk}{word.strip()} "
        if len(new_chunk) >= col_width:
            desc_chunks.append(new_chunk)
            chunk = ""
        else:
            chunk = new_chunk

    delim = "\n"
    desc_chunks.append(chunk)

    return delim.join(desc_chunks)

def generate_actor_profile(query):
    """Parses dictionary of intel, setting Actor class values"""
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
        if  "uses_threats" not in character_list:
            actor.set_threats(" ")
            short_desc = character_list["short_description"]
            short_desc = chunk_long_description(short_desc)
            actor.set_desc(short_desc.split(".")[0] + ".")
        else:
            threat_dict = character_list["uses_threats"][0]  
            actor.set_threats(threat_dict['family_name'])
    return actor

def iterate_lod(resources, key_search):
    """Finds keys in nested dictionaries"""
    found_values = []
    for parent in resources:
        for key in parent:
            if key == key_search:
                found_values.append(parent[key])
    return found_values

def query_intel_actor_entities(query, falcon):
    """Returns list of actor names"""
    query = query.replace(" ","-").lower()
    try:
        intel = falcon.command(action="QueryIntelActorEntities",q=query)['body']['resources']
        actors=iterate_lod(intel,key_search="name")
        return actors
    except IndexError:
        print("Filter Error")

def generate_threat_info(actor):
    """Setting MITRE connections to Actor, if there are any"""
    intel = actor.get_threat_info(actor.threats)
    intel=intel.decode('utf-8')
    intel_list = json.loads(intel)
    if intel_list == None:
        print('Loading...')
    else:
        mitre = iterate_lod(intel_list,key_search="tactic_name")
        actor.set_mitre(set(mitre))

def generate_recon_info(actor):
    intel = actor.recon_actor_info()
    print(intel)

def find_relevance(filter,falcon):
    """Finds the actor specified in user input, returns a single actor"""
    actors = query_intel_actor_entities(filter,falcon)
    while len(actors) < 1:
        filter = input("Value not found in query, please try again: ")
        actors = query_intel_actor_entities(filter,falcon)
        print(len(actors))    
    
    print(f"\nFound {len(actors)} values related to {filter}\n")
    
    while len(actors) > 1:
        print(actors)
        try:
            exact_actor = input("Please choose from the follow actors\n")
            if exact_actor.upper() not in actors:
                raise ValueError("Invalid Actor Selected")
            actors = query_intel_actor_entities(exact_actor, falcon)
        except ValueError:
            print("Error")
        else:
            return exact_actor
    if len(actors) == 1:
        return actors[0]
    else:
        return filter

def begin_query(falcon):
    query= input("Which threat would you like to query? ")
    query = find_relevance(query,falcon)
    actor = generate_actor_profile(query)
    generate_threat_info(actor)
    print_actor_info(actor)


if __name__ == "__main__":
    falcon = api_init()
    begin_query(falcon)
    





