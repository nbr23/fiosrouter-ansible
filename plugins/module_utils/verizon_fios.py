# Copyright: nbr23
# License: MIT

import urllib3
import requests
from json import JSONDecodeError
from hashlib import sha512

urllib3.disable_warnings()

def hash_password(password, salt):
    return sha512(str(password + salt).encode()).hexdigest()


def protocol_match(pname, pid):
    return pname == 'both' or (pname == 'tcp' and pid == 1) or \
            (pname == 'udp' and pid == 2)

def get_rule_protocols(rule):
    return [p['protocol'] for p in rule['protocols']]

def port_in_forward_rule(rule, port):
    for p in rule['protocols']:
        if p['outgoingPortStart'] != port:
            return False
    return True

def protocol_ids(protocol_name):
    if protocol_name == 'both':
        return [1, 2]
    elif protocol_name == 'tcp':
        return [1]
    return [2]

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

    def get_port_forwardings(self):
        return self.get('firewall/portforward')

    def get_matching_port_forwarding(self, name, ip, port_ext, port_int, protocol):
        return [pf for pf in self.get_port_forwardings()
            if pf['name'] == name \
                or (pf['deviceIp'] == ip and pf['servicePort'] == port_int) \
                or len([prot for prot in pf['protocols']
                    if protocol_match(protocol, prot['protocol']) \
                            and port_ext == prot['outgoingPortStart']]) > 0
                ]

    def is_equal_port_forwarding(self, rule, name, ip, port_ext, port_int, protocol):
        return rule['name'] == name and \
                rule['deviceIp'] == ip and \
                rule['servicePort'] == port_ext and \
                port_in_forward_rule(rule, port_ext) and \
                sum(get_rule_protocols(rule)) == sum(protocol_ids(protocol))

    def post_port_forwarding(self, name, ip, port_ext, port_int, protocol, enabled, port_src=None):
        return self.post('firewall/portforward',
                {
                    "enabled": enabled,
                    "deviceIp": ip,
                    "name": name,
                    "protocols": [
                        {
                            "protocol": proto,
                            "incomingPorts": 0 if port_src is None else 1,
                            "incomingPortStart": 0 if port_src is None else port_src,
                            "incomingPortEnd": 65535 if port_src is None else port_src,
                            "incomingExclude": False,
                            "outgoingPorts": 1,
                            "outgoingPortStart": port_ext,
                            "outgoingPortEnd": port_ext,
                            "outgoingExclude": False
                            } for proto in protocol_ids(protocol)
                        ],
                    "schedule": "Always",
                    "servicePort": port_int
                    })

    def put_port_forwarding(self, rule_id, enabled):
        return self.put('firewall/portforward/{}'.format(rule_id),
                { "enabled": enabled, })

    def del_port_forwarding(self, entry_id):
        return self.delete('firewall/portforward/{}'.format(entry_id))
