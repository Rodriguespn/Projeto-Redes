import os
import requests
import time

as_ip = "193.136.128.109"
as_port = "58039"
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

begin_script = int(input("Insira o numero do script onde quer comecar\n"))
end_script = int(input("Insira o numero do script onde quer acabar\n"))
count = 0
for script in range(begin_script, end_script+1):
    url = test_url.format(test_host, test_port, as_ip, as_port, fs_ip, fs_port, script)
    init_time = time.time()
    print("GET {}".format(url))
    while True:
        try:
            response = requests.get(url)
            print("Status code: {}".format(response.status_code))
            
            if response.status_code == 200: # ok
                content = response.content

                with open('{}/RC-script_{}.html'.format(path, script), 'wb') as f:
                    f.write(content)
                count += 1

            else: 
                print("Got status code {}... skipping script {}".format(response.status_code, script))
            break

        except Exception as e:
            print("Exception {}".format(e))
            #print("Something went wrong... skipping script {}".format(script))
            time.sleep(sleep)

        finally:
            curr_time = time.time() - init_time
            print(curr_time)
            if curr_time > timeout:
                print("Timeout... skipping script {}".format(script))
                break

print("{} tests completed".format(count))
