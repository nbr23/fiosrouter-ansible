# Copyright: nbr23
# License: MIT

import urllib3
import requests
from json import JSONDecodeError
from hashlib import sha512

urllib3.disable_warnings()

def hash_password(password, salt):
    return sha512(str(password + salt).encode()).hexdigest()

class RouterSession:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.session = requests.Session()

    def create_url(self, path):
        return 'https://{ip}:{port}/api/{path}'.format(ip=self.ip, port=self.port, path=path)

    def post(self, path, data):
        try:
            return self.session.post(self.create_url(path), verify=False, json=data,
                headers={'X-XSRF-TOKEN': self.session.cookies.get('XSRF-TOKEN')}).json()
        except JSONDecodeError:
            pass

    def put(self, path, data):
        try:
            return self.session.put(self.create_url(path), verify=False, json=data,
                headers={'X-XSRF-TOKEN': self.session.cookies.get('XSRF-TOKEN')}).json()
        except JSONDecodeError:
            pass

    def get(self, path):
        try:
            return self.session.get(self.create_url(path), verify=False,
                headers={'X-XSRF-TOKEN': self.session.cookies.get('XSRF-TOKEN')}).json()
        except JSONDecodeError:
            pass

    def delete(self, path):
        try:
            return self.session.delete(self.create_url(path), verify=False,
                headers={'X-XSRF-TOKEN': self.session.cookies.get('XSRF-TOKEN')}).json()
        except JSONDecodeError:
            pass

    def get_password_salt(self):
        r = self.post('login', None)
        return r['passwordSalt']

    def login(self, password):
        r = self.post('login', {'password': hash_password(password, self.get_password_salt())})
        self.session.cookies = requests.utils.add_dict_to_cookiejar(self.session.cookies, {'bhr4HasEnteredAdvanced': 'true'})
        return r

    def logout(self):
        return self.get('logout')

    def get_settings_dns_entries(self):
        return self.get('settings/dnsserver')

    def post_settings_dns_entry(self, hostname, ipAddress):
        return self.post('settings/dnsserver',
                {
                    'hostname': hostname,
                    'ipAddress': ipAddress,
                    'type': 1,
                    })

    def del_settings_dns(self, entry_id):
        return self.delete('settings/dnsserver/{}'.format(entry_id))

    def put_settings_dns(self, entry_id, hostname, ipAddress):
        return self.put('settings/dnsserver/{}'.format(entry_id),
                {
                    'hostname': hostname,
                    'ipAddress': ipAddress,
                    'type': 1,
                    })

    def get_settings_dns_hostname(self, hostname):
        for entry in self.get_settings_dns_entries():
            if entry['hostname'] == hostname:
                return entry

    def get_dhcp_clients(self):
        return self.get('dhcp/clients')

    def get_dhcp_client(self, hostname, ipAddress, mac):
        return [client for client in self.get_dhcp_clients()
                if client['ipAddress'] == ipAddress or
                    client['mac'] == mac or
                    client['name'] == hostname]

    def post_dhcp_client(self, hostname, ipAddress, mac, staticAddress):
        return self.post('dhcp/clients',
                {
                    'name': hostname,
                    'ipAddress': ipAddress,
                    'mac': mac,
                    'staticAddress': staticAddress,
                    })

    def del_dhcp_client(self, entry_id):
        return self.delete('dhcp/clients/{}'.format(entry_id))
