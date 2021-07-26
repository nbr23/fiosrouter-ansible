#!/usr/bin/python

# Copyright: nbr23
# License: MIT

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: fios_system_info
short_description: Retrieve FIOS Router system information
description:
    - Retrieve FIOS Router system information
author: "nbr23 <max@23.tf>"
requirements:
options:
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
'''

EXAMPLES = '''
- name: Retrieve router system information
  nbr23.fiosrouter.fios_system_info:
    router_ip: 192.168.1.1
    router_password: '{{ fios_password }}'
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
        ),
        supports_check_mode=True
    )

    result = dict(
        changed=False
    )

    session = RouterSession(module.params['router_ip'], module.params['router_port'])

    log_res = session.login(module.params['router_password'])
    if log_res is not None and 'error' in log_res:
        if log_res.get('error') == 2:
            module.fail_json(msg='API Login error: too many sessions open')
        else:
            module.fail_json(msg='API Login error: Incorrect fios credentials')

    result['firmware_info'] = session.get('firmware')
    result['system_info'] = session.get('settings/system')

    session.logout()
    module.exit_json(**result)

if __name__ == '__main__':
    main()
