#!/usr/bin/env python3
import requests
import json
import configparser
from datetime import datetime

def fetch_hosts(base_url, headers):
    hosts_list = []
    hosts_response = requests.get(f'{base_url}/fleet/hosts', headers=headers)
    hosts_data = hosts_response.json()
    for host in hosts_data.get('hosts', []):
        hosts_list.append(host['id'])
    return hosts_list

def log_vulnerabilities(pkgs, log_file):
    with open(log_file, 'a') as log:
        log.write(json.dumps(pkgs, sort_keys=True) + '\n')

def main():
    config = configparser.ConfigParser()
    config.read('config')
    api_token = config['fleet']['api_token']
    base_url = config['fleet']['base_url']
    headers = {'Authorization': f'Bearer {api_token}'}
    hosts_list = fetch_hosts(base_url, headers)

    for host_id in hosts_list:
        host_response = requests.get(f'{base_url}/fleet/hosts/{host_id}', headers=headers)
        host_data = host_response.json()
        for software_item in host_data.get('host', {}).get('software', []):
            if software_item.get('vulnerabilities'):
                for vulnerability in software_item['vulnerabilities']:
                    my_date = datetime.now().isoformat()
                    pkgs = {
                        'timestamp': my_date,
                        'cve_id': vulnerability['cve'],
                        'host_name': host_data['host']['hostname'],
                        'pkg_name': software_item['name'],
                        'source': software_item['source'],
                        'version': software_item['version'],
                        'os_version': host_data['host']['os_version'],
                        'platform': host_data['host']['platform'],
                        'public_ip': host_data['host']['public_ip'],
                        'primary_ip': host_data['host']['primary_ip'],
                        'primary_mac': host_data['host']['primary_mac']
                    }
                    log_vulnerabilities(pkgs, '/tmp/vulners.log')

if __name__ == "__main__":
    main()
