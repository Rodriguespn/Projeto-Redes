import os
import requests
import time

as_ip = "193.136.128.109"
as_port = "58038"
fs_ip = "193.136.128.109"
fs_port = "59038"

test_host = "tejo.tecnico.ulisboa.pt"
test_port = "58000"
test_url = "http://{}:{}/index.html?ASIP={}&ASPORT={}&FSIP={}&FSPORT={}&SCRIPT={}"
  
# Directory 
parent_dir = "./"
directory = "Script-Tests"

sleep = 1
timeout = 30
  
path = os.path.join(parent_dir, directory) 

try:
    os.mkdir(path) 
    print("Directory '% s' created" % path) 
except FileExistsError:
    print("Directory '{}' already exists".format(path))

number_of_tests = int(input("Insira o numero total de scripts\n"))
for script in range(1, number_of_tests+1):
    url = test_url.format(test_host, test_port, as_ip, as_port, fs_ip, fs_port, script)
    init_time = time.time()
    print("GET {}".format(url))
    while True:
        curr_time = time.time() - init_time
        try:
            response = requests.get(url)
            print("Status code: {}".format(response.status_code))

        except Exception as e:
            #print("Exception {}".format(e))
            #print("Something went wrong... skipping script {}".format(script))
            time.sleep(sleep)
            continue
            
        if curr_time > timeout:
            print("Timeout... skipping script {}".format(script))
            break

        if response.status_code == 200: # ok
            content = response.content

            with open('{}/RC-script_{}.html'.format(path, script), 'wb') as f:
                f.write(content)

        else: 
            print("Got status code {}... skipping script {}".format(response.status_code, script))
        break
