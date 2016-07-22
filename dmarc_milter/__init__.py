# coding=utf8
#
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
logger = logging.getLogger('DMARCMilterLogger')


class AddrMapping(Model):

    encoded_addr = CharField(null=False, max_length=255, index=True, unique=True)
    addr         = CharField(null=False, max_length=255)
    action_uuid  = CharField(null=False, max_length=36)
    created      = IntegerField(null=False)
    name         = CharField(null=True, max_length=255)

    class Meta:
        database    = db_proxy
        db_table    = 'email_address_mapping'
        primary_key = CompositeKey('addr', 'action_uuid')


class EmailAddress():

    def __init__(self, address=None):
        self.orig_addr = address
        self.addr      = None
        self.name      = None

        if address:
            self.cleanSetAddrAndName(address)


    @classmethod
    def fromData(cls, address, name):
        addr           = EmailAddress()
        addr.addr      = address
        addr.name      = name
        addr.orig_addr = addr.getNameAddress()

        return addr


    def cleanSetAddrAndName(self, address):
        self.orig_addr = address

        addr_regex = re.compile("[<]?([A-Za-z0-9\.\!#\$%&'\*\+\-/=\?\^_`\{\|\}\~]+@[0-9a-zA-Z\-]+(\.[0-9a-zA-Z\-]+)*\.[a-zA-Z]+)[>]?[^@]*$")

        match = addr_regex.search(address.lower())
        if match:
            self.addr = match.group(1)
            logger.debug("Parsed address: \"{0}\".".format(self.addr))
        else:
            logger.error("Can't extract email address from: \"{0}\"".format(address.lower()))
            raise Exception("Can't extract email address from: \"{0}\"".format(address.lower()))

        name_regex = re.compile('^([^<]+)[<].*$')

        match = name_regex.search(address)
        if match:
            self.name = match.group(1).strip().replace('"', '')
            if self.name.find(',') != -1:
                # if there is a comma in the name we expect the name is written like
                # "lastname, firstname"
                # we extract first and lastname and swap them
                self.name = re.sub(r'^([^,]+),(.*)$',
                                   r'\2 \1',
                                   self.name)
                self.name = self.name.strip()
                extra_chars = ' .#$&*+-/=?^_`{|}~'
                allowed_chars = string.digits + string.letters + extra_chars
                # erase non RFC compliant characters
                self.name = filter(allowed_chars.__contains__, self.name)
                # erase multiple spaces
                self.name = re.sub(r' {2,}',
                                   r' ',
                                   self.name)

    def getDomain(self):

        if self.addr:
            logger.debug("Extracted domain from address: \"{0}\"".format(self.addr[self.addr.rindex('@') + 1:]))
            return self.addr[self.addr.rindex('@') + 1:]


    def getNameAddress(self):
        if self.name:
            return '"' + self.name + '" <' + self.addr + '>'
        else:
            return self.addr


class DMARCMilter(Milter.Base):

    def log(self, *msg):
        for message in msg:
            logger.info(message)

    # encode an email address
    # expects that self.x_mail_domain and self.x_action_uuid is set
    # @param address pure email address used for encoding/lookup
    def encodeAddress(self, address, x_mail_domain, x_action_uuid):
        encoded_address = ''
        name            = None
        mapping         = None

        # if we have the name of the person from the comment of the mail address,
        # use it to extract first name + last name and try to build the encoded
        # address as "firstname.lastname.randomstring@mail-domain.tld"
        #  "firstname.lastname.randomstring" must not be longer than 64 characters
        if address.name and len(address.name) > 0:
            name_split = address.name.split(' ')
            if name_split and len(name_split) > 0:
                if len(name_split[0]) > 0 and len(name_split[0]) <= 52:
                    # we got a first name, start building the encoded address
                    encoded_address = name_split[0].lower() + "."
                    last_name  = "_".join(name_split[1:]).lower()
                    if len(last_name) > 1 and len(encoded_address + last_name) <= 51:
                        # we got a last name, add it to the encoded address
                        encoded_address += last_name + "."
                    # erase multiple dots
                    encoded_address = re.sub(r'\.{2,}',
                                             r'.',
                                             encoded_address)

        # build the rest of the encoded address with random string of 11 characters and the mail domain
        encoded_address += ''.join(random.choice(string.ascii_lowercase) for i in range(11)) + "@" + x_mail_domain

        logger.debug("Inserting new encoded address in DB: original address \"{0}\", encoded address \"{1}\".".format(address.addr, encoded_address))

        return AddrMapping.create(
            encoded_addr=encoded_address,
            addr=address.addr,
            action_uuid=x_action_uuid,
            created=int(time.time()),
            name=address.name)

    def getDecodedAddress(self, address):
        mapping = None
        try:
            mapping = AddrMapping.get(AddrMapping.encoded_addr == address)
            if mapping:
                logger.debug("Looked up address \"{0}\", found \"{1}\".".format(address, mapping.addr))
        except AddrMapping.DoesNotExist as excpt:
            logger.debug("Encoded address \"{0}\" wasn't found in lookup table.".format(address))

        return mapping

    # expects that self.x_action_uuid is set
    def getEncodedAddressAndName(self, address, x_action_uuid):
        mapping = None
        try:
            mapping = AddrMapping.get(AddrMapping.addr == address, AddrMapping.action_uuid == x_action_uuid)
            if mapping:
                logger.debug("Looked up address \"{0}\", action UUID \"{1}\", found address \"{2}\" and name \"{3}\".".format(address, x_action_uuid, mapping.encoded_addr, mapping.name))

        except AddrMapping.DoesNotExist as excpt:
            logger.debug("Address \"{0}\", action UUID \"{1}\" wasn't found in lookup table.".format(address, x_action_uuid))

        if mapping:
            return EmailAddress.fromData(address=mapping.encoded_addr, name=mapping.name)
        else:
            return None


    # change header and envelope "To" fields
    def changeMailToAddress(self, address):
        addr = address.getNameAddress()

        self.chgheader('To', 1, addr)
        self.addrcpt(address.addr)
        self.delrcpt(self.envlp_to.orig_addr)

        self.envlp_to.addr = address

        logger.debug("Changed header \"To\" address to \"{0}\", changed envelope \"To\" address to \"{1}\".".format(addr, address.addr))

    def setFrom(self, address):
        self.chgheader('From', 1, address.getNameAddress())
        self.hdr_from = address
        logger.debug("Changed header \"From\" to \"{0}\".".format(self.hdr_from.addr))

        # we changed the From mail address according to the "X-MAIL-DOMAIN" header:
        # we need to change the envelope Return-Path to have the same domain
        envlp_from = EmailAddress.fromData(address=self.config.return_paths[self.x_mail_domain], name=None)
        self.chgfrom(envlp_from.addr)
        self.envlp_from = envlp_from
        logger.debug("Changed envelope \"From\" to \"{0}\".".format(envlp_from.addr))

    # take the existing header "From" field and encode it
    # expects that self.x_mail_domain and self.x_action_uuid is set
    def encodeHdrFromAddress(self, from_address, x_mail_domain, x_action_uuid):
        address = self.getEncodedAddressAndName(from_address.addr, x_action_uuid)
        if not address:
            mapping = self.encodeAddress(from_address, x_mail_domain, x_action_uuid)
            address = EmailAddress.fromData(address=mapping.encoded_addr, name=mapping.name)
        return address

    def __init__(self, config):
        self.is_internal_host = None
        self.envlp_from       = EmailAddress()
        self.envlp_to         = EmailAddress()
        self.hdr_from         = EmailAddress()
        self.hdr_to           = EmailAddress()

        self.x_mail_domain    = None
        self.x_action_uuid    = None
        self.id               = Milter.uniqueID()
        self.config           = config

        logger.debug('__init__')

    # -----------------------------------------------------------------------------
    # Milter API implementation
    # -----------------------------------------------------------------------------

    # check if a connecting SMTP client is an internal host
    def hello(self, hostname):
        if hostname in self.config.internal_hosts:
            self.is_internal_host = True
            logger.debug("Mail from internal host: \"{0}\"".format(hostname))
        else:
            self.is_internal_host = False
            logger.debug("Mail from external host: \"{0}\"".format(hostname))

        return Milter.CONTINUE

    # save the envelope RCP TO for later use
    def envrcpt(self, envelope_to, *str):
        try:
            self.envlp_to.cleanSetAddrAndName(envelope_to)
            logger.debug("Envelope \"RCP To\" address: \"{0}\".".format(self.envlp_to.addr))
        except Exception as e:
            logger.error("Can't extract email address from envelope \"To:\": \"{0}\"".format(envelope_to.lower()))
            return Milter.REJECT

        return Milter.CONTINUE

    # save the envelope Return-Path for later use
    def envfrom(self, envelope_from, *str):
        try:
            self.envlp_from.cleanSetAddrAndName(envelope_from)
            logger.debug("Envelope \"MAIL FROM\" address: \"{0}\"".format(self.envlp_from.addr))
        except Exception as e:
            logger.error("Can't extract email address from envelope \"MAIL FROM:\": \"{0}\"".format(envelope_from.lower()))
            return Milter.REJECT

        return Milter.CONTINUE

    # store header fields for later use:
    #  - "To:"
    #  - "From:"
    #  - "X-Mail-Domian:"
    #  - "X-Action-UUID:"
    def header(self, field, value):
        field = field.lower()
        if field == 'to':
            try:
                self.hdr_to.cleanSetAddrAndName(value)
                logger.debug("Header \"To\" address: \"{0}\".".format(self.hdr_to.addr))
            except Exception as e:
                logger.error("Can't extract email address from header \"To:\" field: \"{0}\"".format(value.lower()))
                return Milter.REJECT

        elif field == 'from':
            try:
                self.hdr_from.cleanSetAddrAndName(value)
                logger.debug("Header \"From\" address: \"{0}\".".format(self.hdr_from.addr))
            except Exception as e:
                logger.error("Can't extract email address from header \"From:\" field: \"{0}\"".format(value.lower()))
                return Milter.REJECT

        elif field == 'x-mail-domain':
            self.x_mail_domain = value.lower()
            logger.debug("Header \"X-Mail-Domain\" domain: \"{0}\".".format(self.x_mail_domain))

        elif field == 'x-action-uuid':
            self.x_action_uuid = value.lower()
            logger.debug("Header \"X-Action-UUID\": \"{0}\".".format(self.x_action_uuid))

        return Milter.CONTINUE

    # for mails from internal hosts:
    #   - check if domain in header "From:" field is a hosted domain
    #   - if not and "X-Mail-Domain" field is not set -> quarantine
    #   - if not and "X-Action-UUID" field is not set -> quarantine
    #   - generate an encoded address, set it in the "From:" field an save it in the lookup table
    # for mails from external hosts:
    #   - do a lookup of the "To:" address whether there is a address mapping
    #   - if yes, change the "To:" and "From:" addresses and forward the mail
    def eom(self):
        try:
            if self.is_internal_host:
                if (    self.hdr_from.getDomain() not in self.config.hosted_domains
                    and self.hdr_to.getDomain()   not in self.config.hosted_domains):
                    if not self.x_mail_domain:
                        self.quarantine("DMARCMilter: header \"From\" domain is not one of the hosted domains and no \"X-Mail-Domain\" header set! Quarantined!")
                        logger.warning("Header \"From\" domain \"{0}\" is not one of the hosted domains and no \"X-Mail-Domain\" header set. Mail is quarantined!".format(self.hdr_from.getDomain()))
                        return Milter.TEMPFAIL
                    elif not self.x_action_uuid:
                        self.quarantine("DMARCMilter: header \"From\" domain is not one of the hosted domains and no \"X-Action-UUID\" header set! Quarantined!")
                        logger.warning("Header \"From\" domain \"{0}\" is not one of the hosted domains and no \"X-Action-UUID\" header set. Mail is quarantined!".format(self.hdr_from.getDomain()))
                        return Milter.TEMPFAIL
                    elif self.x_mail_domain not in self.config.hosted_domains:
                        self.quarantine("DMARCMilter: domain from \"X-Mail-Domain\" is not one of the hosted domains! Quarantined!")
                        logger.warning("Domain from \"X-Mail-Domain\" = \"{0}\" is not one of the hosted domains. Mail is quarantined!".format(self.x_mail_domain))
                        return Milter.TEMPFAIL
                    else:
                        
                        self.setFrom(self.encodeHdrFromAddress(self.hdr_from, self.x_mail_domain, self.x_action_uuid))
                        # remove auxiliary header fields
                        self.chgheader('X-Mail-Domain', 1, None)
                        self.chgheader('X-Action-UUID', 1, None)

                if self.hdr_from.getDomain() != self.envlp_from.getDomain():
                    self.quarantine("DMARCMilter: header \"From\" domain is not the same as envelope \"From\" domain! Quarantined!")
                    logger.warning("Header \"From\" domain \"{0}\" is not the same as envelope \"From\" domain \"{1}\". Mail is quarantined!".format(self.hdr_from.getDomain(), self.envlp_from.getDomain()))
                    return Milter.TEMPFAIL
                else:
                    logger.debug("Mail with \"From\" domain \"{0}\" was accepted for sending.".format(self.hdr_from.getDomain()))

                # remove Sender field as it contains the non encoded address and we don't need it anyway.
                self.chgheader('Sender', 1, None)

            else:
                # we got mail from an external server; check if there is a
                # mapping for the address in the "To:" field
                mapping = self.getDecodedAddress(self.hdr_to.addr)
                # if there is a mapping -> change the To field to the non
                # encoded address
                if mapping:
                    self.x_mail_domain = self.hdr_to.getDomain()
                    self.x_action_uuid = mapping.action_uuid

                    new_address = EmailAddress.fromData(address=mapping.addr, name=mapping.name)
                    self.changeMailToAddress(new_address)
                    self.setFrom(self.encodeHdrFromAddress(self.hdr_from, self.x_mail_domain, self.x_action_uuid))

                    self.chgheader('DKIM-Signature', 1, None)

        except ValueError as excpt:
            logger.error("Error extracting domain from address, no \"@\" character in email address")
            logger.exception("Exception: ", excpt)
            return Milter.REJECT

        except Exception as excpt:
            logger.error("Exception while processing mail! Rejecting mail!")
            logger.error("Exception: " + str(excpt))
            return Milter.REJECT

        return Milter.ACCEPT


    def close(self):
        logger.debug("Connection closed.")
        return Milter.CONTINUE

    def abort(self):
        logger.warning("Connection was aborted!")
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
    config              = parser.parse_args()
    config.log_level    = log_levels[config.log_level[0]]
    config.socket       = config.socket[0]
    config.config_file  = config.config_file[0]
    config.timeout      = config.timeout[0]
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
                print("I/O error({0}): {1}".format(excpt.errno, excpt.strerror))
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
            print("I/O error({0}): {1}".format(excpt.errno, excpt.strerror))
            exit(1)
        config.return_paths = return_paths

    db = MySQLDatabase(
        'postfix',
        host="localhost",
        user="postfix",
        passwd="postfix")
    db_proxy.initialize(db)

    return config


def init_logger(config):
  """ Configure the global logger object. """
  logger.setLevel(config.log_level)

  handler = logging.handlers.SysLogHandler(address='/dev/log', facility=logging.handlers.SysLogHandler.LOG_MAIL)
  formatter = logging.Formatter("%(asctime)s %(filename)s[%(process)d]: %(message)s", "%b %d %H:%M:%S")
  handler.setFormatter(formatter)
  logger.addHandler(handler)


def main():
    os.umask(007)
    Milter.set_flags(  Milter.QUARANTINE
                     + Milter.CHGHDRS
                     + Milter.DELRCPT
                     + Milter.ADDRCPT
                     + Milter.CHGFROM)

    config = getConfig()
    init_logger(config)

    def instantiate():
        return DMARCMilter(config)

    Milter.factory = instantiate
    Milter.runmilter("dmarc_milter", config.socket, config.timeout)


if __name__ == "__main__":
    main()
