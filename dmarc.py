# A simple milter that filters outgoing mail
# If the connecting SMTP client is an internal host the
# the From domain has to be one of a list of hosted
# domains for which a proper DMARC compliant setup exists

import configargparse
import logging
import logging.handlers
import os
import re
import time
import string
import random

import Milter
from peewee import *

db_proxy = Proxy()


class AddrMapping(Model):

    encoded_addr = CharField(null=False, max_length=255, index=True, primary_key=True)
    addr         = CharField(null=False, max_length=255, index=True, unique=True)
    created      = IntegerField(null=False)
    name         = CharField(null=True, max_length=255)

    class Meta:
        database = db_proxy
        db_table = 'email_address_mapping'


class DMARCMilter(Milter.Base):

    def log(self, *msg):
        for message in msg:
            self.config.logger.info(message)

    def encodeAddress(self, address, address_orig):
        encoded_address = ''
        name            = None

        match = self.config.name_regex.search(address_orig)
        if match:
            name = match.group(1).strip().replace('"', '')

        # if we have a name of the person from the comment of the mail address,
        # use it to extract first name + last name and try to build the encoded
        # address as "firstname.lastname.randomstring@mail-domain.tld"
        #  "firstname.lastname.randomstring" must not be longer than 64 characters
        if name and len(name) > 0:
            name_split = name.split(' ')
            if len(name_split) > 0:
                if len(name_split[0]) > 0 and len(name_split[0]) <= 52:
                    # we got a first name, start building the encoded address
                    encoded_address = name_split[0].lower() + "."
                    last_name  = "_".join(name_split[1:]).lower()
                    if len(last_name) > 1 and len(encoded_address + last_name) <= 51:
                        # we got a last name, add it to the encoded address
                        encoded_address += last_name + "."

        # build the rest of the encoded address with random string of 11 characters and the mail domain
        encoded_address += ''.join(random.choice(string.ascii_lowercase) for i in range(11)) + "@" + self.x_mail_domain

        self.config.logger.debug("Inserting new encoded address in DB: original address \"{0}\", encoded address \"{1}\".".format(address, encoded_address))
        try:
            mapping = AddrMapping.create(
                encoded_addr=encoded_address,
                addr=address,
                created=int(time.time()),
                name=name)
        except Exception as excpt:
            self.config.logger.error("Inserting new encoded address in DB failed: original address \"{0}\", encoded address \"{1}\".".format(address, encoded_address))
            self.config.logger.exception("Peewee Error: ", excpt)

        return (encoded_address, name)

    def getDecodedAddress(self, address):
        mapping = None
        try:
            mapping = AddrMapping.get(AddrMapping.encoded_addr == address)
            if mapping:
                self.config.logger.debug("Looked up address \"{0}\", found \"{1}\".".format(address, dec_addr))
        except AddrMapping.DoesNotExist as excpt:
            self.config.logger.debug("Encoded address \"{0}\" wasn't found in lookup table.".format(address))
        except Exception as excpt:
            self.config.logger.error("Error while looking up encoded address \"{0}\"".format(address))
            self.config.logger.exception("Exception: ", excpt)

        return mapping

    def getEncodedAddressAndName(self, address):
        enc_addr_and_name = None
        try:
            mapping = AddrMapping.get(AddrMapping.addr == address)
            if mapping:
                enc_addr_and_name = (mapping.encoded_addr, mapping.name)
                self.config.logger.debug("Looked up address \"{0}\", found address \"{1}\" and name \"{2}\".".format(address, enc_addr_and_name[0], enc_addr_and_name[1]))

        except AddrMapping.DoesNotExist as excpt:
            self.config.logger.debug("Address \"{0}\" wasn't found in lookup table.".format(address))
        except Exception as excpt:
            self.config.logger.error("Error while looking up decoded address \"{0}\"".format(address))
            self.config.logger.exception("Exception: ", excpt)

        return enc_addr_and_name

    # change header and envelope "To" fields
    def changeMailToAddress(self, address, address_with_name):
        self.chgheader('To', 1, address_with_name)
        self.addrcpt(address)
        self.delrcpt(self.envlp_to_address)

    # take the existing header "From" field and encode it
    def encodeMailFromAddress(self, return_path=None):
        enc_addr_and_name = self.getEncodedAddressAndName(self.hdr_from_address)
        if not enc_addr_and_name:
            enc_addr_and_name = self.encodeAddress(self.hdr_from_address, self.hdr_from_address_orig)

        enc_addr_with_name = None
        enc_addr           = enc_addr_and_name[0]
        if len(enc_addr_and_name[1]) > 0:
            enc_addr_with_name = '"' + enc_addr_and_name[1] + '" <' + enc_addr_and_name[0] + '>'
        
        self.changeMailFromAddress(enc_addr, enc_addr_with_name, return_path)
        
    # change header "From" field
    # change envelope "MAIL FROM" field when a return path is given
    def changeMailFromAddress(self, address, address_with_name=None, return_path=None):
        if address_with_name:
            self.chgheader('From', 1, address_with_name)
            self.hdr_from_address = address_with_name
        else:
            self.chgheader('From', 1, address)
            self.hdr_from_address = address

        self.config.logger.debug("Changed header \"From\" to \"{0}\".".format(self.hdr_from_address))
        self.hdr_from_domain = address[address.rindex('@') + 1:]
        
        if return_path:
            self.chgfrom(return_path)
            self.envlp_from_domain = return_path[return_path.rindex('@') + 1:]
            self.config.logger.debug("Changed envelope \"From\" to \"{0}\".".format(return_path))
                
    def __init__(self, config):
        self.is_internal_host      = None
        self.envlp_to_address      = None
        self.envlp_from_domain     = None
        self.hdr_from_domain       = None
        self.hdr_from_address      = None
        self.hdr_from_address_orig = None
        self.hdr_to_address        = None
        self.x_mail_domain         = None
        self.id                    = Milter.uniqueID()
        self.config                = config

        self.config.logger.debug('__init__')

    # check if a connecting SMTP client is an internal host
    def hello(self, hostname):
        if hostname in self.config.internal_hosts:
            self.is_internal_host = True
            self.config.logger.debug("Mail from internal host: \"{0}\"".format(hostname))
        else:
            self.is_internal_host = False
            self.config.logger.debug("Mail from external host: \"{0}\"".format(hostname))

        return Milter.CONTINUE

    # save the envelope RCP TO for later use
    def envrcpt(self, envelope_to, *str):
        self.envlp_to_address = envelope_to
        self.config.logger.debug("Envelope \"RCP TO\" address: \"{0}\"".format(envelope_to))

        return Milter.CONTINUE

    # save the envelope Return-Path for later use
    def envfrom(self, envelope_from, *str):
        self.config.logger.debug("Envelope \"MAIL FROM\" address: \"{0}\"".format(envelope_from))
        if self.is_internal_host:
            try:
                self.envlp_from_domain = envelope_from[envelope_from.rindex('@') + 1:].lower().translate(None, '<>')
                self.config.logger.debug("Envelope \"From\" domain: \"{0}\"".format(self.envlp_from_domain))
            except ValueError as excpt:
                self.config.logger.error("No @ character in From address: \"{0}\"".format(envelope_from))
                self.config.logger.exception("Exception: ", excpt)
                return Milter.REJECT

        return Milter.CONTINUE

    # store header fields for later use:
    #  - "To:"
    #  - "From:"
    #  - "X-Mail-Domian:"
    def header(self, field, value):
        field = field.lower()
        if field == 'to':
            match = self.config.addr_regex.search(value.lower())
            if match:
                self.hdr_to_address = match.group(1)
                self.config.logger.debug("Header \"To\" address: \"{0}\".".format(self.hdr_to_address))
            else:
                self.config.logger.error("Can't extract email address from header \"To:\" content: \"{0}\"".format(value.lower()))
                return Milter.REJECT

        elif field == 'from':
            self.hdr_from_address_orig = value
            match                      = self.config.addr_regex.search(value.lower())
            if match:
                self.hdr_from_address = match.group(1)
                self.config.logger.debug("Header \"From\" address: \"{0}\".".format(self.hdr_from_address))
            else:
                self.config.logger.error("Can't extract email address from header \"From:\" content: \"{0}\"".format(value.lower()))
                return Milter.REJECT

            if self.is_internal_host:
                try:
                    self.hdr_from_domain = value[value.rindex('@') + 1:].lower().translate(None, '<>')
                    self.config.logger.debug("Header \"From\" domain: \"{0}\"".format(self.hdr_from_domain))
                except ValueError as excpt:
                    self.config.logger.error("No @ character in From address: \"{0}\"".format(value))
                    self.config.logger.exception("Exception: ", excpt)
                    return Milter.REJECT

        elif field == 'x-mail-domain':
            self.x_mail_domain = value.lower()
            self.config.logger.debug("Header \"X-Mail-Domain\" domain: \"{0}\".".format(self.x_mail_domain))

        return Milter.CONTINUE


    # for mails from internal hosts:
    #   - check if domain in header "From:" field is a hosted domain
    #   - if not, generate an encoded address, set it in the "From:" field an save it in the lookup table
    #   - if not and "X-Mail-Domain" field is not set -> quarantine
    # for mails from external hosts:
    #   - do a lookup of the "To:" address whether there is a address mapping
    #   - if yes, change the "To:" and "From:" addresses and forward the mail
    def eom(self):
        if self.is_internal_host:
            if self.hdr_from_domain not in self.config.hosted_domains:
                if not self.x_mail_domain:
                    self.quarantine("DMARCMilter: header \"From\" domain is not one of the hosted domains! Quarantined!")
                    self.config.logger.warning("Header \"From\" domain \"{0}\" is not one of the hosted domains. Mail is quarantined!".format(self.hdr_from_domain))
                    return Milter.TEMPFAIL
                elif self.x_mail_domain not in self.config.hosted_domains:
                    self.quarantine("DMARCMilter: domain from \"X-Mail-Domain\" is not one of the hosted domains! Quarantined!")
                    self.config.logger.warning("Domain from \"X-Mail-Domain\" = \"{0}\" is not one of the hosted domains. Mail is quarantined!".format(self.x_mail_domain))
                    return Milter.TEMPFAIL
                else:
                    self.encodeMailFromAddress()
                    self.chgheader('X-Mail-Domain', 1, None)

            if self.hdr_from_domain != self.envlp_from_domain:
                self.quarantine("DMARCMilter: header \"From\" domain is not the same as envelope \"From\" domain! Quarantined!")
                self.config.logger.warning("Header \"From\" domain \"{0}\" is not the same as envelope \"From\" domain \"{1}\". Mail is quarantined!".format(self.hdr_from_domain, self.envlp_from_domain))
                return Milter.TEMPFAIL
            else:
                self.config.logger.debug("Mail with \"From\" domain \"{0}\" was accepted for sending.".format(self.hdr_from_domain))

            # remove Sender field as it contains the non encoded address and we don't need it anyway.
            self.chgheader('Sender', 1, None)

        else:
            addr_and_name = self.getDecodedAddress(self.hdr_to_address)
            if addr_and_name:
                new_to_addr = ''
                if addr_and_name.name:
                    new_to_addr = '"' + addr_and_name.name + '" <' + addr_and_name.addr + '>'
                else:
                    new_to_addr = addr_and_name.addr
                self.x_mail_domain = self.hdr_to_address[self.hdr_to_address.rindex('@') + 1:]
                # we are forwarding mail: we need to change the envelope Return-Path.
                return_path = self.config.return_paths[self.x_mail_domain]
                self.changeMailToAddress(addr_and_name.addr, new_to_addr)
                self.encodeMailFromAddress(return_path)

        return Milter.ACCEPT


    def close(self):
        self.config.logger.debug("Connection closed.")
        return Milter.CONTINUE

    def abort(self):
        self.config.logger.warning("Connection was aborted!")
        return Milter.CONTINUE

def getConfig():

    log_levels = dict(critical=logging.CRITICAL, error=logging.ERROR, warning=logging.WARNING, info=logging.INFO, debug=logging.DEBUG)
    parser = configargparse.ArgParser(default_config_files=['/etc/milters/dmarc.conf'])
    parser.add('-f',
               '--config-file',
               metavar='<config file>',
               help='An absolute path to the config file for DMARC Send Milter. (default: /etc/pymilters/dmarc_send.conf)',
               default='/etc/milters/dmarc.conf',
               is_config_file=True)
    parser.add('-s',
               '--socket',
               nargs=1,
               metavar='<socket file>',
               help='An absolute path to the Unix socket config file for DMARC Send Milter. (default: /var/run/dmarc_send.sock)',
               required=True,
               default=['/var/run/dmarc_send.sock'])
    parser.add('-v',
               '--log-level',
               nargs=1,
               type=str,
               choices=log_levels,
               metavar='<log level>',
               help="Verbosity level for logging of the DMARC Send Milter. Valid values: {0}. (default: \"warning\")".format(', '.join(log_levels.keys())),
               required=True,
               default=['warning'])
    parser.add('-i',
               '--internal-hosts',
               nargs="*",
               metavar='<hostname or IP address>',
               help='A list of host names/IP addresses that are considered internal hosts, that is hosts that use this mail server to send mail. (default: localhost)',
               required=True,
               default=['localhost'])
    parser.add('-d',
               '--hosted-domains',
               nargs="*",
               metavar='<hosted domain>',
               help='A list of domains for which this mail server is a DMARC compliant mail server. An absolute path to a file from which to read the list of domains can also be provided. (default: )',
               required=True,
               default=[])
    parser.add('-r',
               '--return-paths',
               nargs=1,
               metavar='<Return-Path table file>',
               help='An absolute path to a file from which to read the mapping of domains to their return path addresses. (default: <empty>)',
               required=True,
               default=[])
    parser.add('-t',
               '--timeout',
               nargs=1,
               type=int,
               choices=xrange(1, 600),
               metavar='timeout in [sec]',
               help='Connection timeout in seconds. (default: 60)',
               required=True,
               default=[60])
    config = parser.parse_args()
    config.log_level   = log_levels[config.log_level[0]]
    config.socket      = config.socket[0]
    config.config_file = config.config_file[0]
    config.timeout     = config.timeout[0]
    config.return_paths = config.return_paths[0]
    def readListFromFile(var):
        if len(var) > 0 and len(var[0]) > 0 and  var[0][0] == '/':
            try:
                with open(var[0]) as f:
                    list_from_file = f.readlines()
                var = []
                for i in range(len(list_from_file)):
                    var.append(str.strip(list_from_file[i]))
            except IOError as excpt:
                print "I/O error({0}): {1}".format(excpt.errno, excpt.strerror)
                exit(1)
        return var

    config.internal_hosts = readListFromFile(config.internal_hosts)
    config.hosted_domains = readListFromFile(config.hosted_domains)
    if config.return_paths:
        return_paths = {}
        try:
            with open(config.return_paths) as f:
                for line in f:
                    domain, return_path = line.partition(":")[::2]
                    return_paths[domain.strip()] = return_path.strip()
        except IOError as excpt:
            print "I/O error({0}): {1}".format(excpt.errno, excpt.strerror)
            exit(1)
        config.return_paths = return_paths

    config.addr_regex = re.compile("[<]?([A-Za-z0-9\.\!#\$%&'\*\+\-/=\?\^_`\{\|\}\~]+@[0-9a-zA-Z\-]+(\.[0-9a-zA-Z\-]+)*\.[a-zA-Z]+)[>]?[^@]*$")
    config.name_regex = re.compile('^([^<]+)[<].*$')

    config.logger = logging.getLogger('DMARCMilterLogger')
    config.logger.setLevel(config.log_level)

    handler   = logging.handlers.SysLogHandler(address='/dev/log', facility=logging.handlers.SysLogHandler.LOG_MAIL)
    formatter = logging.Formatter("%(asctime)s %(filename)s[%(process)d]: %(message)s", "%b %d %H:%M:%S")
    handler.setFormatter(formatter)
    config.logger.addHandler(handler)

    db = MySQLDatabase(
        'postfix',
        host="localhost",
        user="postfix",
        passwd="postfix")
    db_proxy.initialize(db)

    return config


def main():
    os.umask(007)
    Milter.set_flags(  Milter.QUARANTINE
                     + Milter.CHGHDRS
                     + Milter.DELRCPT
                     + Milter.ADDRCPT
                     + Milter.CHGFROM)

    config = getConfig()

    def instantiate():
        return DMARCMilter(config)

    Milter.factory = instantiate
    Milter.runmilter("dmarc_milter", config.socket, config.timeout)


if __name__ == "__main__":
    main()
