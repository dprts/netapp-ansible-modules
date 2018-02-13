#!/usr/bin/python

# (c) 2017, Piotr Olczak <piotr.olczak@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: na_gather_facts
author: Piotr Olczak
short_description: NetApp information gatherer
description:
    - This module allows you to gather various information about NetApp storage configuration
version_added: "2.2"
requirements:
    - netapp_lib
options:
    state:
        description:
            - Returns "info"
        default: "info"
        required: false
        choices: ['info']
    hostname:
        description:
            - API Hostname, it can be one of https://host:port or http://host:port or ip (this defaults to https)
        required: true
    username:
        description:
            - API Username
        required: false
    password:
        description:
            - API User's password
        required: false
    style:
        description:
            - Authentication style.
            - When C(basic_auth) is specified C(username) and C(password) are required parameters.
            - When C(basic_auth) is specified C(cert_file) and C(key_file) are required parameters.
        required: false
        default: basic_auth
        choices: ['basic_auth', 'certificate_auth']
    cert_file:
        description:
            - Path to certificate
        required: false
    key_file:
        description:
            - Path to key file
        required: false
    verify_ssl:
        description:
            - Set to false if SSL certificate validation should be skipped
        required: false
        default: true
'''

EXAMPLES = '''
- name: Get NetApp info (Password Authentication)
  na_gather_facts:
    state: info
    hostname: "https://10.34.254.201:10443"
    username: "admin"
    password: "admins_password"
    verify_ssl: false

- name: Get NetApp info (Certificate Authentication)
  na_gather_facts:
    state: info
    hostname: "https://10.34.254.201:10443"
    cert_file: "../certificates/certificate.pem"
    key_file: "../certificates/key.pem"
    verify_ssl: false
'''

RETURN = '''
netapp_info:
    description: Returns various information about NetApp cluster configuration
    returned: always
    type: dict
    sample: '{
        "netapp_info": {
            "aggregate_info": {...},
            "net_ifgrp_info": {...},
            "net_interface_info": {...},
            "net_port_info": {...},
            "security_login_account_info": {...},
            "volume_info": {...},
            "storage_failover_info": {...}
    }'
'''

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible.module_utils.netapp as netapp_utils

import xmltodict
import json

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppGatherFacts(object):

    def __init__(self, module):
        self.module = module
        self.netapp_info = dict()

        if HAS_NETAPP_LIB is False:
            self.module.fail_json(msg="the python NetApp-Lib module is required")
        else:
            self.server = netapp_utils.setup_ontap_zapi(module=self.module)

    def call_api(self, call, query=None):
        api_call = netapp_utils.zapi.NaElement(call)
        result = None

        if query:
            for k, v in query.items():
                # Can v be nested?
                api_call.add_new_child(k, v)
        try:
            result = self.server.invoke_successfully(api_call, enable_tunneling=False)
            return result
        except netapp_utils.zapi.NaApiError as e:
            self.module.fail_json(msg="Error calling API %s: %s" %
                                  (call, to_native(e)), exception=traceback.format_exc())

    def get_ifgrp_info(self):
        net_port_info = self.netapp_info['net_port_info']
        interfaces = net_port_info.keys()

        ifgrps = []
        for ifn in interfaces:
            if net_port_info[ifn]['port_type'] == 'if_group':
                ifgrps.append(ifn)

        net_ifgrp_info = dict()
        for ifgrp in ifgrps:
            query = dict()
            query['node'], query['ifgrp-name'] = ifgrp.split(':')

            tmp = self.get_generic_get_iter('net-port-ifgrp-get', field=('node', 'ifgrp-name'), attribute='net-ifgrp-info', query=query, children='attributes')
            net_ifgrp_info = net_ifgrp_info.copy()
            net_ifgrp_info.update(tmp)
        return net_ifgrp_info

    def get_generic_get_iter(self, call, attribute=None, field=None, query={}, children='attributes-list'):
        generic_call = self.call_api(call, query)

        if field is None:
            out = []
        else:
            out = {}

        attributes_list = generic_call.get_child_by_name(children)

        for child in attributes_list.get_children():
            d = xmltodict.parse(child.to_string(), xml_attribs=False)

            if attribute is not None:
                d = d[attribute]

            if isinstance(field, str):
                unique_key = _finditem(d, field)
                out = out.copy()
                out.update({unique_key: convert_keys(json.loads(json.dumps(d)))})
            elif isinstance(field, tuple):
                unique_key = ':'.join([_finditem(d, el) for el in field])
                out = out.copy()
                out.update({unique_key: convert_keys(json.loads(json.dumps(d)))})
            else:
                out.append(convert_keys(json.loads(json.dumps(d))))

        return out

    def get_all(self):
        self.netapp_info['net_interface_info'] = self.get_generic_get_iter(
            'net-interface-get-iter',
            attribute='net-interface-info',
            field='interface-name',
            query={'max-records': '1024'}
        )
        self.netapp_info['net_port_info'] = self.get_generic_get_iter(
            'net-port-get-iter',
            attribute='net-port-info',
            field=('node', 'port'),
            query={'max-records': '1024'}
        )
        self.netapp_info['cluster_node_info'] = self.get_generic_get_iter(
            'cluster-node-get-iter',
            attribute='cluster-node-info',
            field='node-name',
            query={'max-records': '1024'}
        )
        self.netapp_info['security_login_account_info'] = self.get_generic_get_iter(
            'security-login-get-iter',
            attribute='security-login-account-info',
            field=('user-name', 'application', 'authentication-method'),
            query={'max-records': '1024'}
        )
        self.netapp_info['aggregate_info'] = self.get_generic_get_iter(
            'aggr-get-iter',
            attribute='aggr-attributes',
            field='aggregate-name',
            query={'max-records': '1024'}
        )
        self.netapp_info['volume_info'] = self.get_generic_get_iter(
            'volume-get-iter',
            attribute='volume-attributes',
            field='name',
            query={'max-records': '1024'}
        )
        self.netapp_info['storage_failover_info'] = self.get_generic_get_iter(
            'cf-get-iter',
            attribute='storage-failover-info',
            field='node',
            query={'max-records': '1024'}
        )

        self.netapp_info['net_ifgrp_info'] = self.get_ifgrp_info()

        return self.netapp_info


# https://stackoverflow.com/questions/14962485/finding-a-key-recursively-in-a-dictionary
def _finditem(obj, key):

    if key in obj:
        return obj[key]
    for k, v in obj.items():
        if isinstance(v, dict):
            item = _finditem(v, key)
            if item is not None:
                return item


def convert_keys(d):
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            v = convert_keys(v)
            out[k.replace('-', '_')] = v
    else:
        return d
    return out


def main():
    argument_spec = netapp_utils.ontap_sf_host_argument_spec()
    required_if = netapp_utils.ontap_sf_host_argument_required_if()
    argument_spec.update(dict(
        state=dict(default='info', choices=['info']),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=True
    )

    state = module.params['state']
    v = NetAppGatherFacts(module)
    g = v.get_all()
    result = {'state': state, 'changed': False, 'netapp_info': g}
    module.exit_json(**result)


if __name__ == '__main__':
    main()
