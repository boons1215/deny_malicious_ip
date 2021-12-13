# boon.siew@illumio.com
# Resource Ref: https://github.com/stamparm/ipsum

import requests
import time

# update here
api_user = "<api_user>"
api_secret = "<api_key>"
pce = "https://" + "<pce_fqdn>/api/v2/orgs/1/sec_policy/"
iplist_name = "malicious_ip" # precreate the iplist
iplist_id = "281474976711028"  # precreate the iplist

def retrieve_update():
    url_get = requests.get("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt")
    timestr = time.strftime("%Y%m%d")
    filename = "malicious_ip_" + timestr + ".txt"

    with open(filename, "w") as ip_file:
        ip_file.write(url_get.text)

    return filename

def content_check(filename: str):
    ip_appear_3_time = []

    with open(filename) as ip_file:
        for ip in ip_file:
            if "#" in ip:
                continue
            else:
                parts = ip.strip().split("\t")
                if int(parts[1]) >= 3: # only append the ip which appears on 3 lists and above
                    bad_ip = parts[0]
                    ip_appear_3_time.append({"from_ip": bad_ip})

    return ip_appear_3_time

def iplist_update(ip_appear_3_time: list, iplist_name: str):
    pce_headers = {'content-type': 'application/json', 'Accept': 'application/json'}
    payload = {"name": iplist_name, "description":"malicious IPs", "ip_ranges": ip_appear_3_time, "fqdns":[]}

    puts = requests.put(pce + "draft/ip_lists/" + iplist_id, auth=(api_user, api_secret), headers=pce_headers, json=payload)

    if puts.status_code == 204:
        payload = {"update_description":"","change_subset":{"ip_lists":[{"href":"/orgs/8/sec_policy/draft/ip_lists/281474976711028"}]}}
        posts = requests.post(pce, auth=(api_user, api_secret), headers=pce_headers, json=payload)
    else:
        return "Unable to update the iplist"

    if posts.status_code == 201:
        return f"Provisioned. {len(ip_appear_3_time)} bad IPs."
    else:
        return "Unable to provision the change"


if __name__ == '__main__':
    ip_appear_3_time = content_check(retrieve_update())
    print(iplist_update(ip_appear_3_time, iplist_name))
