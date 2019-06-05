#!/usr/bin/env python
# -*- coding: utf8 -*-


from xml.etree import ElementTree
import subprocess
import requests
import logging
import base64
import time
import sys
import os


class LetsHook:
    def __init__(self):
        self.certbot_domain = os.environ["CERTBOT_DOMAIN"]
        self.certbot_validation = os.environ["CERTBOT_VALIDATION"]
        self.nicru_service = os.environ['service']
        self.nicru_api_id = os.environ['api_id']
        self.nicru_api_password = os.environ['api_password']
        self.nicru_username = os.environ['username']
        self.nicru_password = os.environ['password']
        self.tokens_path = '/tmp/' + self.certbot_domain

        # Define logger
        self.logger = logging.getLogger('certbot')
        self.logger.setLevel(logging.DEBUG)

        self.formater = logging.Formatter('%(asctime)s %(name)s %(levelname)s : %(message)s')

        self.streamhamdler = logging.StreamHandler()
        self.streamhamdler.setLevel(logging.WARNING)
        self.streamhamdler.setFormatter(self.formater)

        self.filehandler = logging.FileHandler('/tmp/letsencrypt.log')
        self.filehandler.setLevel(logging.DEBUG)
        self.filehandler.setFormatter(self.formater)

        self.logger.addHandler(self.streamhamdler)
        self.logger.addHandler(self.filehandler)


    def get_environments(self):
        environments = {}
        for var_name, var_val in os.environ.items():
            environments[var_name] = var_val
        self.logger.info('All environments:')
        self.logger.info(environments)
        self.logger.info('Certbot docker container session environments:')
        self.logger.info('CERTBOT_DOMAIN: ' + environments['CERTBOT_DOMAIN'])
        self.logger.info('CERTBOT_VALIDATION: ' + environments['CERTBOT_VALIDATION'])
        return environments


    def tmp_certbot_validation_file(self):
        """
        Function will create storage directory which one will be temporary storage for CERTBOT_VALIDATION tokens
        Create file with name like the new token - /tmp/mydomain.com/ZluqcTC5zia6Zgdo4wSbIu-m6xyTloazJBz37iPkQ5M
        It will help to determine which tokens are obsolete and then remove them

        :return: True or False
        """
        access_rights = 0o755
        if not os.path.exists(self.tokens_path):
            try:
                os.mkdir(self.tokens_path, access_rights)
                self.logger.info("Monitoring directory for tokens was created: " + self.tokens_path)
            except OSError:
                self.logger.warning("Cant create directory: " + self.tokens_path)
                return False

        file_name = os.path.join(self.tokens_path, self.certbot_validation)
        with open(file_name, 'a'):
            self.logger.info("Monitoring token file was created: " + file_name)
            return True


    def nic_auth_token(self):
        """
        # HTTP API example:
        POST https://api.nic.ru/oauth/token HTTP/1.1
        Authorization: Basic MzNmM3VvaXVramphc2RmaTg3YXNsZGtqZmxhanNkbGY6U0RqbGtqbDhqbGFzbWNsYXNpb2lhc29pamxhSkxLU0pER0ZIT0kK
        Content-Type: application/x-www-form-urlencoded

        grant_type=password&username=898443/NIC-D&password=MyTechnoNicRuAccountPass!&scope=(GET|PUT|POST|DELETE)%3A%2Fdns-master%2F.%2B


        :return: <str> "ASEZ2WtEDa48mFbOr9jrk9PgX2W2fyS7U7Lh5kRiOX"
        """

        url = 'https://api.nic.ru/oauth/token'

        nicru_api_build_base = self.nicru_api_id + ':' + self.nicru_api_password
        nicru_api_auth_base64 = base64.b64encode(nicru_api_build_base.encode('utf-8')).decode('utf-8')
        self.logger.info('Base64 format auth token for nic.ru api - "api_id:api_password" : ' + nicru_api_auth_base64)

        headers = {
            'Authorization': 'Basic ' + nicru_api_auth_base64,
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        data = {
            'grant_type': 'password',
            'username': self.nicru_username,
            'password': self.nicru_password,
            'scope': '(GET|PUT|POST|DELETE):/dns-master/.+'
        }

        request = requests.post(url, headers=headers, data=data)
        if request.status_code != 200:
            self.logger.critical('Nic.ru api auth token was not gotten!')
            self.logger.critical(request.text)
            return False
        else:
            access_token = request.json()['access_token']
            self.logger.info('Nic.ru api auth token:')
            self.logger.info(access_token)
            return access_token


    def nic_get_records(self, auth_token, service, zone):
        """
        # HTTP API example:
        GET https://api.nic.ru/dns-master/services/SERVICENAME/zones/mydomain.com/records
        Authorization: Bearer ASEZ2WtEDa48mFbOr9jrk9PgX2W2fyS7U7Lh5kRiOX

        :param auth_token: temporary token for API nic.ru "ASEZ2WtEDa48mFbOr9jrk9PgX2W2fyS7U7Lh5kRiOX"
        :param service: name of DNS-hosting service (for example "SERVICENAME" which contain domain - mydomain.com)
        :param zone: DNS name <str> mydomain.com
        :return: <str> xml response with DNS entiries from nic.ru API DNS
        """

        url = 'https://api.nic.ru/dns-master/services/{service}/zones/{zone}/records'.format(service=service, zone=zone)

        headers = {
            'Authorization': 'Bearer {auth_token}'.format(auth_token=auth_token)
        }

        request = requests.get(url, headers=headers)
        self.logger.info('All nic.ru DNS records:')
        self.logger.info(request.content.decode('utf-8'))
        response = ElementTree.fromstring(request.text)
        return response


    def nic_get_acme_records_ids(self, xml_content):
        """
        Parser for XML which one tries to find all DNS entries containing `_acme-challenge` name

        :param xml_content:
        :return: <dict> {'38007627': '1234', '38008827': 'kPyWMN5TW3vK5tHxOVXvy3V7Q78AfCXclEr6t0gtwDY'}
        """

        acme_ids = {}

        for find_zone in xml_content.findall('./data/zone'):
            for all_rr in find_zone.iter('rr'):
                for inside_rr_acme in all_rr.findall("[name='_acme-challenge']"):
                    if inside_rr_acme is not None:
                        acme_challenge_id = inside_rr_acme.attrib['id']
                        for acme in inside_rr_acme.iter('string'):
                            acme_ids[acme_challenge_id] = acme.text
                    else:
                        return acme_ids

        self.logger.info('The next `_acme-challenge` entries are present on the DNS NS server now')
        self.logger.info(acme_ids)
        return acme_ids


    def nic_del_record(self, auth_token, service, zone, **rr_ids):
        """
        The function will delete entries with specific ids from DNS server

        # HTTP API example:
        #DELETE https://api.nic.ru/dns-master/services/SERVICENAME/zones/mydomain.com/records/<rr_id>
        DELETE https://api.nic.ru/dns-master/services/SERVICENAME/zones/mydomain.com/records/37987883
        Authorization: Bearer ASEZ2WtEDa48mFbOr9jrk9PgX2W2fyS7U7Lh5kRiOX

        :param auth_token: temporary token for API nic.ru "ASEZ2WtEDa48mFbOr9jrk9PgX2W2fyS7U7Lh5kRiOX"
        :param service: name of DNS-hosting service (for example "SERVICENAME" which contain domain - mydomain.com)
        :param zone: DNS name <str> mydomain.com
        :param rr_ids: <dict> with id numbers of the DNS entry with value
            example:
            {'38007627': '1234', '38008827': 'y3V7Q78AfCXclEr6t0gtwDY', '38008713': 'm6xyTloazJBz37iPkQ5M'}
        :return: True or False
        """

        list_of_current_tokens = os.listdir(self.tokens_path)
        self.logger.info('Current certbot tokens used for this session:')
        self.logger.info(list_of_current_tokens)

        for rr_id, txt_entry in rr_ids['rr_ids'].items():
            self.logger.info('Current working id:')
            self.logger.info(rr_id)

            if txt_entry in list_of_current_tokens:
                self.logger.info('The next token is used for current session and should not be removed: ' + txt_entry)
                pass

            else:
                url = 'https://api.nic.ru/dns-master/services/{service}/zones/{zone}/records/{rr_id}'.format(
                    service=service, zone=zone, rr_id=rr_id)

                headers = {
                    'Authorization': 'Bearer {auth_token}'.format(auth_token=auth_token)
                }

                request = requests.delete(url, headers=headers)
                request_content = request.content.decode('utf-8')

                if request.status_code != 200:
                    self.logger.critical('Nic.ru api can not delete obsolete token:')
                    self.logger.critical(request.text)
                    return False
                else:
                    self.logger.info('The next obsolete rr_id entry will be removed: ' + rr_id)
                    return request_content


    def nic_put_txt(self, service, zone, auth_token, acme_token, **rr_ids):
        """
        The function will deploy TXT `_acme-challenge` entry on the DNS server

        # HTTP API example:
        PUT https://api.nic.ru/dns-master/services/SERVICENAME/zones/mydomain.com/records
        Authorization: Bearer ASEZ2WtEDa48mFbOr9jrk9PgX2W2fyS7U7Lh5kRiOX

        <?xml version="1.0" encoding="UTF-8" ?>
        <request>
         <rr-list>
           <rr>
               <name>_acme-challenge</name>
               <ttl>300</ttl>
               <type>TXT</type>
               <txt>
                   <string>1234</string>
               </txt>
           </rr>
         </rr-list>
        </request>

        :param service: name of DNS-hosting service (for example "SERVICENAME" which contain domain - mydomain.com)
        :param zone: DNS name <str> mydomain.com
        :param auth_token: temporary token for API nic.ru "ASEZ2WtEDa48mFbOr9jrk9PgX2W2fyS7U7Lh5kRiOX"
        :param acme_token: token that you got from certbot for DNS TXT verification <str> 123
        :param rr_ids: <dict> with id numbers of the DNS entry with value
            example:
            {'38007627': '1234', '38008827': 'y3V7Q78AfCXclEr6t0gtwDY', '38008713': 'm6xyTloazJBz37iPkQ5M'}
        :return: True of False
        """

        if acme_token in [acme_txt for acme_id, acme_txt in rr_ids['rr_ids'].items()]:
            self.logger.info('acme_token: ' + acme_token + ' already exist on the DNS server! Skip!')
        else:
            url = 'https://api.nic.ru/dns-master/services/{service}/zones/{zone}/records'.format(service=service,
                                                                                                 zone=zone)

            headers = {
                'Authorization': 'Bearer {auth_token}'.format(auth_token=auth_token)
            }

            data = """
            <?xml version="1.0" encoding="UTF-8" ?>
            <request>
             <rr-list>
               <rr>
                   <name>_acme-challenge</name>
                   <ttl>300</ttl>
                   <type>TXT</type>
                   <txt>
                       <string>{acme_token}</string>
                   </txt>
               </rr>
             </rr-list>
            </request>
            """.format(acme_token=acme_token)

            request = requests.put(url, data=data, headers=headers)

            request_content = request.content.decode('utf-8')

            if request.status_code != 200:
                self.logger.critical('Nic.ru api can not PUT new TXT token:')
                self.logger.critical(request.text)
                return False
            else:
                self.logger.info('Nic.ru api TXT entry was successful deployed:')
                self.logger.info(request_content)
                return request


    def nic_commit(self, service, zone, auth_token):
        """
        The function will commit all changes on the remote nic.ru DNS server

        # HTTP API example:
        POST https://api.nic.ru/dns-master/services/SERVICENAME/zones/mydomain.com/commit
        Authorization: Bearer ASEZ2WtEDa48mFbOr9jrk9PgX2W2fyS7U7Lh5kRiOX

        :param service: name of DNS-hosting service (for example "SERVICENAME" which contain domain - mydomain.com)
        :param zone: DNS name <str> mydomain.com
        :param auth_token: temporary token for API nic.ru "ASEZ2WtEDa48mFbOr9jrk9PgX2W2fyS7U7Lh5kRiOX"
        :return: True or False
        """

        url = 'https://api.nic.ru/dns-master/services/{service}/zones/{zone}/commit'.format(service=service, zone=zone)

        headers = {
            'Authorization': 'Bearer {auth_token}'.format(auth_token=auth_token)
        }

        request = requests.post(url, headers=headers)

        if request.status_code != 200:
            self.logger.critical('Nic.ru api can not apply commit:')
            self.logger.critical(request.text)
            return False
        else:
            self.logger.info('Commit was successfully applied')
            return request


    def dns_get_ns(self, zone):
        """
        The function will return all ns servers for specified domain

        :param zone: DNS name <str> mydomain.com
        :return: <list> ['ns4-l2.nic.ru.', 'ns8-cloud.nic.ru.', 'ns3-l2.nic.ru.', 'ns8-l2.nic.ru.', 'ns4-cloud.nic.ru.']
        """

        # I used `dig` command because it is more flexible and worked in more cases (instead python dns.resolver module)
        # Install `dig` package (by default `certbot` docker container has 'Alipine' distributive
        apk_install = 'apk add bind-tools'
        pkg_install = subprocess.Popen(apk_install.split())
        pkg_install.wait()
        self.logger.info('dig package was installed. Command: ' + apk_install)

        command = 'dig ns +short @8.8.8.8 {zone}'.format(zone=zone).split()
        ns_servers = subprocess.check_output(command).decode("utf-8")
        # create a list of ns servers without gaps
        trim_ns_servers = [x for x in ns_servers.split('\n') if x]
        self.logger.info('All used NS server for zone - ' + zone)
        self.logger.info(trim_ns_servers)
        return trim_ns_servers


    def dns_get_txt(self, zone, name_servers=('8.8.8.8', '77.88.8.8')):
        """
        The function will return all TXT entries for specified domain on the specified NS servers

        :param zone: DNS name <str> mydomain.com
        :param name_servers: DNS NS servers where you will search your deployed TXT entries. (for example 8.8.8.8)
        :return: <dict> {'ns4-cloud.nic.ru.': ['123'], 'ns3-l2.nic.ru.': ['123'], 'ns8-l2.nic.ru.': ['123'], 'ns8-cloud.nic.ru.': ['123']}
        """

        # Empty list with NS. For example:
        # {'ns4-cloud.nic.ru.': [], 'ns3-l2.nic.ru.': [], 'ns8-l2.nic.ru.': [], 'ns8-cloud.nic.ru.': []}
        entries_in_name_servers = {ns: [] for ns in name_servers}

        # _acme-challenge.mydomain.com
        acme_dns_entry = '_acme-challenge.' + zone

        for ns_server in name_servers:
            # `dig` command is used.
            command = 'dig txt +short @{ns_server} {acme_dns_entry}'.format(acme_dns_entry=acme_dns_entry,
                                                                            ns_server=ns_server).split()
            txt = subprocess.check_output(command)
            trim_txt_entry = [x.replace('"', '') for x in txt.decode('utf-8').split('\n') if x]

            entries_in_name_servers[ns_server] = trim_txt_entry

        self.logger.info('Now NS servers are containing the next TXT entries:')
        self.logger.info(entries_in_name_servers)
        return entries_in_name_servers


    def dns_check_txt_in_ns(self, zone, acme_token, counter=60, check_period=10):
        """
        The function is trying to check the existence of specified entry on all ns servers

        :param zone: DNS name <str> mydomain.com
        :param acme_token: token that you got from certbot for DNS TXT verification <str> "123"
        :param counter: how many times try again
        :param check_period: how long in seconds we should wait between
        :return: True of False
        """

        try_max_counter = counter

        servers_ns = self.dns_get_ns(zone)

        while try_max_counter > 0:
            try_max_counter -= 1
            time.sleep(check_period)
            self.logger.info('Waiting for deploying TXT entries on the NS servers. Counter attempt number:')
            self.logger.info(try_max_counter)

            pool_of_txt_entries = self.dns_get_txt(zone=zone, name_servers=servers_ns)
            ns_success_statuses = {ns: 'False' for ns in servers_ns}

            for ns_server, txts in pool_of_txt_entries.items():
                if acme_token in txts:
                    self.logger.info('On the NS server ' + ns_server + ' TXT token is present. Waiting for the next one.')
                    ns_success_statuses[ns_server] = 'True'

            self.logger.info('Status of deploy:')
            self.logger.info(ns_success_statuses)

            if 'False' not in [status for ns, status in ns_success_statuses.items()]:
                self.logger.info('Finish! Deploy of TXT entries on the NS servers was successfully finished!')
                return True

        self.logger.critical('One of the TXT entries was not deployed on one of NS servers!')
        self.logger.critical('Count of attempts: ' + str(counter))
        return False


    def __call__(self):
        self.get_environments()
        self.tmp_certbot_validation_file()

        # If we don't get nic.ru auth API token then exit
        nicru_token = self.nic_auth_token()

        if nicru_token:
            records = self.nic_get_records(auth_token=nicru_token, service=self.nicru_service, zone=self.certbot_domain)

            # Check `_acme-challenge` if exist and delete if entry is obsoleted
            txt_records_ids = self.nic_get_acme_records_ids(xml_content=records)
            if txt_records_ids:
                self.nic_del_record(auth_token=nicru_token, service=self.nicru_service, zone=self.certbot_domain, rr_ids=txt_records_ids)
                self.nic_commit(auth_token=nicru_token, service=self.nicru_service, zone=self.certbot_domain)

            self.nic_put_txt(auth_token=nicru_token, service=self.nicru_service, zone=self.certbot_domain, acme_token=self.certbot_validation, rr_ids=txt_records_ids)

            self.nic_commit(auth_token=nicru_token, service=self.nicru_service, zone=self.certbot_domain)

            self.dns_check_txt_in_ns(zone=self.certbot_domain, acme_token=self.certbot_validation)
        else:
            sys.exit(1)


start = LetsHook()
start()
