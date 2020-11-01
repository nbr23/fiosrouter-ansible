#!/usr/bin/python

# Copyright: nbr23
# License: MIT

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: fios_dns
short_description: Manage Fios Verizon Router local DNS entries
description:
    - Manage Fios Verizon Router local DNS entries
author: "nbr23 <max@23.tf>"
requirements:
options:
    name:
        required: true
        description:
            - DNS entry name to update
    ip:
        required: true
        description:
            - IP Address for the the DNS entry
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
            - Whether the DNS entry should exist in the Fios router
'''

EXAMPLES = '''
- name: Delete DNS entry
  nbr23.fiosrouter.fios_dns:
    name: myhost
    ip: 192.168.1.5
    router_ip: 192.168.1.1
    router_password: '{{ fios_password }}'
    state: absent

- name: Create/Update DNS entry
  nbr23.fiosrouter.fios_dns:
    name: myhost
    ip: 192.168.1.5
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
            ip=dict(required=True, type='str')
        ),
        supports_check_mode=True
    )

    result = dict(
        changed=False
    )

    present = module.params['state'] == 'present'
    session = RouterSession(module.params['router_ip'], module.params['router_port'])
    session.login(module.params['router_password'])

    current = session.get_settings_dns_hostname(module.params['name'])

    if current is not None:
        if present and module.params['ip'] != current['ipAddress']:
            session.put_settings_dns(current['id'], module.params['name'], module.params['ip'])
            result['changed'] = True
        elif not present:
            session.del_settings_dns(current['id'])
            result['changed'] = True
    else:
        if present:
            session.post_settings_dns_entry(module.params['name'], module.params['ip'])
            result['changed'] = True

    session.logout()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
