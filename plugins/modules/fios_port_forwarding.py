#!/usr/bin/python

# Copyright: nbr23
# License: MIT

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: fios_port_forwarding
short_description: Manage Fios Verizon Router Port Forwarding / PAT
description:
    - Manage Fios Verizon Router Port Forwarding / PAT
author: "nbr23 <max@23.tf>"
requirements:
options:
    name:
        required: true
        description:
            - Name of the forwarding rule
    ip:
        required: true
        description:
            - IP Address of the local device to map
    protocol:
        choices:
            - tcp
            - udp
            - both
        required: true
        description:
            - Protocol(s) to forward to the local device
    port_ext:
        required: true
        description:
            - External (Internet facing) port to forward to the local device
    port_int:
        required: true
        description:
            - Internal (Local device) port to forward to
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
            - Whether the NAT rule should exist in the Fios router
    enabled:
        default: true
        description:
            - Enable/Disable the forwarding rule
'''

EXAMPLES = '''
- name: Map port 80 to 192.168.1.5:8080 on tcp
  nbr23.fiosrouter.fios_port_forwarding:
    name: Test_rule_1
    ip: 192.168.1.5
    port_ext: 80
    port_int: 8080
    protocol: tcp
    router_ip: 192.168.1.1
    router_password: '{{ fios_password }}'
    state: present

- name: Delete port forwarding rule
  nbr23.fiosrouter.fios_port_forwarding:
    name: Test_rule_1
    ip: 192.168.1.5
    port_ext: 80
    port_int: 8080
    protocol: tcp
    router_ip: 192.168.1.1
    router_password: '{{ fios_password }}'
    state: absent
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
            enabled=dict(default=True, type='bool'),
            name=dict(required=True, type='str'),
            protocol=dict(default='tcp', choices=['tcp', 'udp', 'both']),
            port_ext=dict(required=True, type='int'),
            port_int=dict(required=True, type='int'),
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

    current = session.get_matching_port_forwarding(module.params['name'], module.params['ip'], module.params['port_ext'], module.params['port_int'], module.params['protocol'])

    if len(current) > 0:
        if not present:
            for rule in current:
                if session.is_equal_port_forwarding(rule,
                        module.params['name'],
                        module.params['ip'],
                        module.params['port_ext'],
                        module.params['port_int'],
                        module.params['protocol']
                        ):
                    session.del_port_forwarding(rule['id'])
                    result['changed'] = True
        else:
            if len(current) == 1:
                if session.is_equal_port_forwarding(current[0],
                        module.params['name'],
                        module.params['ip'],
                        module.params['port_ext'],
                        module.params['port_int'],
                        module.params['protocol']
                        ):
                    if current[0]['enabled'] != module.params['enabled']:
                        session.put_port_forwarding(current[0]['id'],
                                module.params['enabled'])
                        result['changed'] = True
                else:
                    session.del_port_forwarding(current[0]['id'])
                    session.post_port_forwarding(module.params['name'],
                            module.params['ip'],
                            module.params['port_ext'],
                            module.params['port_int'],
                            module.params['protocol'],
                            module.params['enabled']
                            )
                    result['changed'] = True
            else:
                module_fail(module, session, msg='Ambiguous situation: several existing rules match the description.\n{}'.format(current))
    elif present:
        session.post_port_forwarding(module.params['name'],
                module.params['ip'],
                module.params['port_ext'],
                module.params['port_int'],
                module.params['protocol'],
                module.params['enabled']
                )
        result['changed'] = True

    session.logout()
    module.exit_json(**result)

if __name__ == '__main__':
    main()
