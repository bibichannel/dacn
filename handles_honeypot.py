import docker
import subprocess
import pickle
import os

client = docker.from_env()

def create_honeypots(number=1):
  list_honeypot_container = {}

  # Load object manager info honeypot 
  if os.path.exists('honeypots.pkl'):
    with open('honeypots.pkl', 'rb') as f:
          list_honeypot_container = pickle.load(f)
    
  for i in range(number):
    name_container = f"honeypot-{len(list_honeypot_container) + 1}"
    ipaddress = f"10.0.0.{len(list_honeypot_container) + 15}"

    client.containers.run(
      image="bibichannel/honeypot:v3",
      command = "cowrie start -n",
      detach=True,
      auto_remove = True,
      name = name_container,
      tty = True
    )

    list_honeypot_container[name_container] = ipaddress

    # Link docker container to OVS s3
    subprocess.call(['ovs-docker', 'add-port', 's3', 'eth1', f'{name_container}', f'--ipaddress={ipaddress}/24'])
  
  with open('honeypots.pkl', 'wb') as f:
    pickle.dump(list_honeypot_container, f)

  return list_honeypot_container

# Stop running containers
def stop_honeypots(number=1):
  list_honeypot_container = {}

  if os.path.exists('honeypots.pkl'):
    with open('honeypots.pkl', 'rb') as f:
          list_honeypot_container = pickle.load(f)

  if list_honeypot_container is None:
    print("List honeypot Container is None")
    return True
  
  if len(list_honeypot_container) <= number:
    number = len(list_honeypot_container)

  for i in range(number):
    pop_item = list_honeypot_container.popitem()
    container = client.containers.get(pop_item[0])

    #  Deletes INTERFACE inside CONTAINER and removes its connection to Open vSwitch BRIDGE 
    subprocess.call(['ovs-docker', 'del-port', 's3', 'eth1', f'{pop_item[0]}'])
    
    # Stop container
    container.stop()

  with open('honeypots.pkl', 'wb') as f:
    pickle.dump(list_honeypot_container, f)

  return list_honeypot_container

def info_honeypots():
  if os.path.exists('honeypots.pkl'):
    with open('honeypots.pkl', 'rb') as f:
          list_honeypot_container = pickle.load(f)

  message = ''
  for key, value in list_honeypot_container.items():
    message += f"{key} - ip: {value} | "

  return message

