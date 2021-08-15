#!/usr/bin/python

# Copyright: nbr23
# License: MIT

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: fios_dhcp_static_lease
short_description: Manage Fios Verizon Router DHCP static leases
description:
    - Manage Fios Verizon Router DHCP static leases
author: "nbr23 <max@23.tf>"
requirements:
options:
    name:
        required: true
        description:
            - hostname of the DHCP static lease target
    ip:
        required: true
        description:
            - IP Address of the DHCP static lease target
    mac:
        required: true
        description:
            - MAC Address of the DHCP static lease target
    router_password:
        required: true
        description:
            - Fios router admin password
    router_ip:
        required: false
        default: '192.168.1.1'
        description:
            - Fios router ip
    router_port:
        required: false
        default: 443
        description:
            - Fios router https listening port
    state:
        required: true
        default: present
        choices:
            - present
            - absent
        description:
            - Whether the static DHCP lease should exist in the Fios router
'''

EXAMPLES = '''
- name: Delete static lease
  nbr23.fiosrouter.fios_dhcp_static_lease:
    name: myhost
    ip: 192.168.1.5
    mac: 00:00:00:00:00:00
    router_ip: 192.168.1.1
    router_password: '{{ fios_password }}'
    state: absent

- name: Set / Update static lease
  nbr23.fiosrouter.fios_dhcp_static_lease:
    name: myhost
    ip: 192.168.1.5
    mac: 00:00:00:00:00:00
    router_ip: 192.168.1.1
    router_password: '{{ fios_password }}'
    state: present
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.nbr23.fiosrouter.plugins.module_utils.verizon_fios import RouterSession

def module_fail(module, session, msg):
    session.logout()
    module.fail_json(msg=msg)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            router_password=dict(required=True, type='str', no_log=True),
            router_ip=dict(required=False, default='192.168.1.1', type='str'),
            router_port=dict(type='int', default=443),
            state=dict(default='present', choices=['present', 'absent']),
            name=dict(required=True, type='str'),
            mac=dict(required=True, type='str'),
            ip=dict(required=True, type='str')
        ),
        supports_check_mode=True
    )

    result = dict(
        changed=False
    )

    present = module.params['state'] == 'present'
    session = RouterSession(module.params['router_ip'], module.params['router_port'])

    log_res = session.login(module.params['router_password'])
    if log_res is not None and 'error' in log_res:
        if log_res.get('error') == 2:
            module.fail_json(msg='API Login error: too many sessions open')
        else:
            module.fail_json(msg='API Login error: Incorrect fios credentials')

    current = session.get_dhcp_client(module.params['name'], module.params['ip'], module.params['mac'])
    if len(current) > 1:
         module_fail(module, session, 'Conflicting entries found for specified ip, mac, name')

    current = None if len(current) < 1 else current[0]

    if current is not None:
        if not present and current['staticIp']:
            if not module.check_mode:
                result['result'] = session.del_dhcp_client(current['id'])
            result['changed'] = True
        elif present and not current['staticIp'] \
                and current['name'] == module.params['name'] \
                and current['ipAddress'] == module.params['ip'] \
                and current['mac'] == module.params['mac']:
            if not module.check_mode:
                result['result'] = session.post_dhcp_client(current['name'], current['ipAddress'], current['mac'], True)
            result['changed'] = True
        elif present and (current['name'] != module.params['name']
                or current['ipAddress'] != module.params['ip']
                or current['mac'] != module.params['mac']):
            if not module.check_mode:
                session.del_dhcp_client(current['id'])
                result['result'] = session.post_dhcp_client(module.params['name'], module.params['ip'], module.params['mac'], True)
            result['changed'] = True
    elif present:
        if not module.check_mode:
            result['result'] = session.post_dhcp_client(module.params['name'], module.params['ip'], module.params['mac'], True)
        result['changed'] = True

    session.logout()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
