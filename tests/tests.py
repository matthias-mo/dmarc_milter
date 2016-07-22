# coding=utf8

from unittest import TestCase
import logging
import logging.handlers
import re
import time
import string
import random

import Milter
from peewee import *

from dmarc_milter import init_logger, DMARCMilter, AddrMapping, db_proxy, EmailAddress, AddressMapper

class Config():
    def __init__(self):
        self.log_level    = logging.INFO
        self.socket       = "/tmp/dmarc.socket"
        self.timeout      = 5
        self.return_paths = {
            "action.advocacy-engine.com" : "bounce@action.advocacy-engine.com",
            "donor-engine.com"           : "bounce@donor-engine.com",
            "m.more-onion.com"           : "bounce@m.more-onion.com",
            "action.openrightsgroup.org" : "bounce@action.openrightsgroup.org"
        }
        self.internal_hosts = (
            "127.0.0.1",
            "localhost",
            "localhost.localdomain",
            "web.moreonion.com"
        )
        self.hosted_domains = (
            "action.advocacy-engine.com",
            "donor-engine.com",
            "m.more-onion.com",
            "action.openrightsgroup.org"
        )

        self.db = SqliteDatabase('/tmp/dmarc.db')
        db_proxy.initialize(self.db)

    def resetDB(self):
        AddrMapping.drop_table(fail_silently=True)
        AddrMapping.create_table()


class CTX():
    def __init__(self):
        self.is_quarantined    = False
        self.quarantine_reason = None
        self.header            = {'From' : None, 'To' : None, 'X-Mail-Domain' : None, 'X-Action-UUID' : None, 'Sender' : None}
        self.envlp_from        = None
        self.envlp_to          = None

    def chgheader(self, field, idx, value):
        self.header[field] = value

    def chgfrom(self, sender, params):
        self.envlp_from = sender

    def addrcpt(self, rcpt, params):
        self.envlp_to = rcpt

    def delrcpt(self, rcpt):
        if self.envlp_to == rcpt:
            self.envlp_to = None

    def quarantine(self, reason):
        self.is_quarantined    = True
        self.quarantine_reason = reason


class EmailAddresTest(TestCase):
    def test_EmailAddress_name_is_none(self):
        address = EmailAddress(address='Foo@Bar.Net')
        self.assertIsNone(address.name)

    def test_EmailAddress_name_has_comma_and_illegal_chars(self):
        address = EmailAddress(address='"van der Lastname, Firstname, ßüÖä §[]\° stuff" <Foo@Bar.Net>')
        self.assertEqual(address.name, 'Firstname stuff van der Lastname')


class AddressMapperTest(TestCase):
    def setUp(self):
        self.config = Config()
        init_logger(self.config)
        self.mapper = AddressMapper('foo.bar.net', '9bed7305-8af0-42ff-adee-744657f73917')
        self.config.resetDB()

    def test_encodeAddress_address(self):
        mapping = self.mapper.encodeAddress(
            EmailAddress(address='Foo@Bar.Net'),
        )
        match = re.match('^[a-z]{11}[@]foo\.bar\.net$', mapping.encoded_addr)
        self.assertIsNotNone(match)

    def test_encodeAddress_address_with_name(self):
        mapping = self.mapper.encodeAddress(
            EmailAddress(address='"Baz Boo" <Foo@Bar.Net>'),
        )
        match = re.match('^baz\.boo\.[a-z]{11}[@]foo\.bar\.net$', mapping.encoded_addr)
        self.assertIsNotNone(match)

    def test_encodeAddress_name(self):
        mapping = self.mapper.encodeAddress(
            EmailAddress(address='"Baz Boo" <Foo@Bar.Net>'),
        )
        self.assertEqual(mapping.name, "Baz Boo")

    def test_encodeAddress_mapping_name_is_none(self):
        mapping = self.mapper.encodeAddress(
            EmailAddress(address='Foo@Bar.Net'),
        )
        self.assertIsNone(mapping.name)

    def test_encodeAddress_peewee_encoded_addr(self):
        gen_mapping = self.mapper.encodeAddress(
            EmailAddress(address='Foo@Bar.Net'),
        )
        get_mapping = AddrMapping.get(AddrMapping.encoded_addr == gen_mapping.encoded_addr)
        self.assertEqual(get_mapping.addr, 'foo@bar.net')

    def test_encodeAddress_peewee_addr(self):
        x_action_uuid = '9bed7305-8af0-42ff-adee-744657f73917'
        self.mapper.encodeAddress(
            EmailAddress(address='Foo@Bar.Net'),
        )
        mapping = AddrMapping.get(AddrMapping.addr == 'foo@bar.net', AddrMapping.action_uuid == x_action_uuid)
        self.assertIsNone(mapping.name)

    def test_encodeAddress_peewee_created(self):
        x_action_uuid = '9bed7305-8af0-42ff-adee-744657f73917'
        self.mapper.encodeAddress(
            EmailAddress(address='Foo@Bar.Net'),
        )
        mapping = AddrMapping.get(AddrMapping.addr == 'foo@bar.net', AddrMapping.action_uuid == x_action_uuid)
        compare_time = int(time.time()) - 10
        self.assertGreater(mapping.created, compare_time)

    def test_encodeAddress_with_name_peewee_encoded_addr(self):
        gen_mapping = self.mapper.encodeAddress(
            EmailAddress(address='"Baz Boo" <Foo@Bar.Net>'),
        )
        get_mapping = AddrMapping.get(AddrMapping.encoded_addr == gen_mapping.encoded_addr)
        self.assertEqual(get_mapping.addr, 'foo@bar.net')

    def test_encodeAddress_with_name_peewee_addr(self):
        self.mapper.encodeAddress(
            EmailAddress(address='"Baz Boo" <Foo@Bar.Net>'),
        )
        mapping = AddrMapping.get(AddrMapping.addr == 'foo@bar.net', AddrMapping.action_uuid == self.mapper.action_uuid)
        self.assertEqual(mapping.name, 'Baz Boo')

    def test_encodeAddress_with_name_peewee_created(self):
        self.mapper.encodeAddress(
            EmailAddress(address='"Baz Boo" <Foo@Bar.Net>'),
        )
        mapping = AddrMapping.get(AddrMapping.addr == 'foo@bar.net', AddrMapping.action_uuid == self.mapper.action_uuid)
        compare_time = int(time.time()) - 10
        self.assertGreater(mapping.created, compare_time)

    def test_encodeAddress_with_name_peewee_funky_addr(self):
        self.mapper.encodeAddress(
            EmailAddress(address='"Baz Boo" <ASDd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@Bar.Net>'),
        )
        mapping = AddrMapping.get(AddrMapping.addr == 'asdd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@bar.net', AddrMapping.action_uuid == self.mapper.action_uuid)
        self.assertEqual(mapping.name, 'Baz Boo')

    def test_encodeAddress_with_name_peewee_funky_name(self):
        self.mapper.encodeAddress(
            EmailAddress(address='"jasdf 235"1&16134%$!^o"[asd} <Foo@Bar.Net>'),
        )
        mapping = AddrMapping.get(AddrMapping.addr == 'foo@bar.net', AddrMapping.action_uuid == self.mapper.action_uuid)
        self.assertEqual(mapping.name, 'jasdf 2351&16134%$!^o[asd}')

    def test_encodeAddress_with_name_peewee_funky_name2(self):
        self.mapper.encodeAddress(
            EmailAddress(address='"jasdf 8asdf"8asdfas 888" <Foo@Bar.Net>'),
        )
        mapping = AddrMapping.get(AddrMapping.addr == 'foo@bar.net', AddrMapping.action_uuid == self.mapper.action_uuid)
        self.assertEqual(mapping.name, 'jasdf 8asdf8asdfas 888')

    def test_getDecodedAddress_funky_encoded_addr(self):
        mapping = self.mapper.encodeAddress(
            EmailAddress(address='"Baz Boo" <ASDd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@Bar.Net>'),
        )
        decoded = AddrMapping.byAlias(EmailAddress(address=mapping.encoded_addr))
        self.assertEqual(decoded.addr, 'asdd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@bar.net')

    def test_AddrMapping_byAddressAndAction_funky_addr(self):
        gen_mapping = self.mapper.encodeAddress(
            EmailAddress(address='"Baz Boo" <ASDd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@Bar.Net>'),
        )
        mapping = AddrMapping.byAddressAndAction(EmailAddress(address='asdd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@bar.net'), self.mapper.action_uuid)
        self.assertEqual(mapping.encoded_addr, gen_mapping.encoded_addr)

    def test_AddrMapping_byAddressAndAction_funky_name(self):
        self.mapper.encodeAddress(
            EmailAddress(address='"jasdf 235"1&16134%$!^o"[asd} <Foo@Bar.Net>'),
        )
        mapping = AddrMapping.byAddressAndAction(EmailAddress(address='foo@bar.net'), self.mapper.action_uuid)
        self.assertEqual(mapping.name, 'jasdf 2351&16134%$!^o[asd}')

    def test_getAliasAddress_hdr_from_address_with_name(self):
        from_address = EmailAddress(address='"jasdf 235"1&16134%$!^o"[asd} <aSdd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@baK.ORG>')
        new_address = self.mapper.getAliasAddress(from_address)
        mapping = AddrMapping.get(AddrMapping.addr == 'asdd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@bak.org', AddrMapping.action_uuid == self.mapper.action_uuid)
        self.assertEqual(new_address.getNameAddress(), '"' + mapping.name + '" <' + mapping.encoded_addr + '>')

    def test_getAliasAddress_hdr_from_address_without_name(self):
        from_address = EmailAddress(address='aSdd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@baK.ORG')
        new_address = self.mapper.getAliasAddress(from_address)
        mapping = AddrMapping.get(AddrMapping.addr == 'asdd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@bak.org', AddrMapping.action_uuid == self.mapper.action_uuid)
        self.assertEqual(new_address.getNameAddress(), mapping.encoded_addr)

    def test_getAliasAddress_hdr_from_domain_no_return_path(self):
        from_address = EmailAddress(address='"jasdf 235"1&16134%$!^o"[asd} <aSdd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@baK.ORG>')
        new_address = self.mapper.getAliasAddress(from_address)
        self.assertEqual(new_address.getDomain(), 'foo.bar.net')

    def test_getAliasAddress_2_times_same_from(self):
        from_address = EmailAddress(address='test@example.com')
        self.mapper.getAliasAddress(from_address)
        self.mapper.getAliasAddress(from_address)


class DMARCMilterTest(TestCase):

    def setUp(self):
        self.config = Config()
        init_logger(self.config)
        self.milter = DMARCMilter(self.config)
        self.milter._actions = Milter.QUARANTINE | Milter.CHGHDRS | Milter.DELRCPT | Milter.ADDRCPT | Milter.CHGFROM
        self.milter._ctx = CTX()
        self.config.resetDB()

    def test_getAliasAddress_return_path(self):
        mapper = AddressMapper('m.more-onion.com', '9bed7305-8af0-42ff-adee-744657f73917')
        from_address = EmailAddress(address='"jasdf 235"1&16134%$!^o"[asd} <aSdd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@baK.ORG>')
        new_address = mapper.getAliasAddress(from_address)
        self.milter.x_mail_domain = mapper.domain
        self.milter.setFrom(new_address)
        self.assertEqual(self.milter.envlp_from.getDomain(), 'm.more-onion.com')

    def test_hello_internal(self):
        self.milter.hello("localhost.localdomain")
        self.assertTrue(self.milter.is_internal_host)

    def test_hello_external(self):
        self.milter.hello("localdomain")
        self.assertFalse(self.milter.is_internal_host)

    def test_hello_return(self):
        result = self.milter.hello("foobar")
        self.assertEqual(result, Milter.CONTINUE)

    def test_envrcpt(self):
        self.milter.envrcpt("Foo@Bar.Net")
        self.assertEqual(self.milter.envlp_to.addr, "foo@bar.net")

    def test_envrcpt_return(self):
        result = self.milter.envrcpt("Foo@Bar.Net")
        self.assertEqual(result, Milter.CONTINUE)

    def test_envfrom(self):
        self.milter.is_internal_host = True
        self.milter.envfrom('asdd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@bak.bang.bong.org (cron daemon)')
        self.assertEqual(self.milter.envlp_from.getDomain(), 'bak.bang.bong.org')

    def test_envfrom_return_continue(self):
        result = self.milter.envfrom('asdd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@bak.bang.bong.org')
        self.assertEqual(result, Milter.CONTINUE)

    def test_envfrom_return_reject(self):
        self.milter.is_internal_host = True
        result = self.milter.envfrom('bak.bang.bong.org')
        self.assertEqual(result, Milter.REJECT)

    def test_header_to(self):
        self.milter.header('To', '"jasdf 235"1&16134%$!^o"[asd} <aSdd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@baK.NonG.NonG.ORG>')
        self.assertEqual(self.milter.hdr_to.addr, 'asdd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@bak.nong.nong.org')

    def test_header_to_return_continue(self):
        result = self.milter.header('To', '"jasdf 235"1&16134%$!^o"[asd} <aSdd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@baK.NonG.NonG.ORG>')
        self.assertEqual(result, Milter.CONTINUE)

    def test_header_to_return_reject(self):
        result = self.milter.header('To', '!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38baK.NonG.NonG.ORG>')
        self.assertEqual(result, Milter.REJECT)

    def test_header_hdr_to_domain(self):
        self.milter.is_internal_host = True
        self.milter.header('To', '"jasdf 235"1&16134%$!^o"[asd} <aSdd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@baK.NonG.NonG.ORG> (foo bar)')
        self.assertEqual(self.milter.hdr_to.getDomain(), 'bak.nong.nong.org')

    def test_header_from_external_address(self):
        self.milter.header('From', '"jasdf 235"1&16134%$!^o"[asd} <aSdd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@baK.NonG.NonG.ORG>')
        self.assertEqual(self.milter.hdr_from.addr, 'asdd..!#$%&a*k+asd-wq/q=p?a^u{i}p~f|38@bak.nong.nong.org')

    def test_header_from_internal_domain(self):
        self.milter.is_internal_host = True
        self.milter.header('From', '"jasdf 235"1&16134%$!^o"[asd} <aSdd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@baK.NonG.NonG.ORG> (Foo Bar Baz)')
        self.assertEqual(self.milter.hdr_from.getDomain(), 'bak.nong.nong.org')

    def test_header_from_return_continue(self):
        self.milter.is_internal_host = True
        result = self.milter.header('From', '"jasdf 235"1&16134%$!^o"[asd} <aSdd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@baK.NonG.NonG.ORG>')
        self.assertEqual(result, Milter.CONTINUE)

    def test_header_from_return_reject(self):
        result = self.milter.header('From', 'aS()dd..!#$%&a*k+asd-WQ/q=p?a^u{i}p~f|38@b)aK.NonG.NonG.ORG>')
        self.assertEqual(result, Milter.REJECT)

    def test_header_from_return_reject2(self):
        self.milter.is_internal_host = True
        result = self.milter.header('From', 'baK.NonG.NonG.ORG>')
        self.assertEqual(result, Milter.REJECT)

    def test_header_x_mail_domain(self):
        self.milter.header("X-Mail-Domain", "foo.Faa.Bar.Net")
        self.assertEqual(self.milter.x_mail_domain, "foo.faa.bar.net")

    def _prepare_eom(self, hdr_from, hdr_to, envlp_from, envlp_to, hostname, x_mail_domain=None, x_action_uuid=None):
        self.milter._ctx.header['From'] = hdr_from
        self.milter._ctx.header['To']   = hdr_to
        self.milter._ctx.envlp_from     = envlp_from
        self.milter._ctx.envlp_to       = envlp_to
        self.milter.hello(hostname)
        self.milter.envrcpt(envlp_to)
        self.milter.envfrom(envlp_from)
        self.milter.header('From', hdr_from)
        self.milter.header('To', hdr_to)
        if x_mail_domain:
            self.milter.header('X-Mail-Domain', x_mail_domain)
        if x_action_uuid:
            self.milter.header('X-Action-UUID', x_action_uuid)
        return self.milter.eom()

    # -------------------------------------------------------------------------------------
    # internal host, header From hosted, header From != envlp From
    # -------------------------------------------------------------------------------------
    def test_eom_is_internal_yes_is_hosted_yes_envlp_from_not_equ_hdr_from(self):
        result = self._prepare_eom(
            hdr_from='"Foo Bar" <foO.BAR.mONION@M.moRE-onion.COM>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='mee@mee.mau.at',
            envlp_to='recipient@address.com',
            hostname='localhost')
        self.assertEqual(result, Milter.TEMPFAIL)

    # -------------------------------------------------------------------------------------
    # internal host, header "From" in hosted domains, header "From" == "envlp From"
    # -------------------------------------------------------------------------------------
    def test_eom_is_internal_yes_is_hosted_yes_envlp_from_equ_hdr_from(self):
        result = self._prepare_eom(
            hdr_from='"Foo Bar" <foO.BAR.mONION@M.moRE-onion.COM>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost')
        self.assertEqual(result, Milter.ACCEPT)

    def test_eom_is_internal_yes_is_hosted_yes_envlp_from_equ_hdr_from_check_hdr_from(self):
        self._prepare_eom(
            hdr_from='"Foo Bar" <foO.BAR.mONION@M.moRE-onion.COM>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost')
        self.assertEqual(self.milter._ctx.header['From'], '"Foo Bar" <foO.BAR.mONION@M.moRE-onion.COM>')

    def test_eom_is_internal_yes_is_hosted_yes_envlp_from_equ_hdr_from_check_hdr_to(self):
        self._prepare_eom(
            hdr_from='"Foo Bar" <foO.BAR.mONION@M.moRE-onion.COM>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost')
        self.assertEqual(self.milter._ctx.header['To'], '"The Recipient" <recipient@address.com>')

    def test_eom_is_internal_yes_is_hosted_yes_envlp_from_equ_hdr_from_check_envlp_from(self):
        self._prepare_eom(
            hdr_from='"Foo Bar" <foO.BAR.mONION@M.moRE-onion.COM>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost')
        self.assertEqual(self.milter._ctx.envlp_from, self.config.return_paths['m.more-onion.com'])

    def test_eom_is_internal_yes_is_hosted_yes_envlp_from_equ_hdr_from_check_envlp_to(self):
        self._prepare_eom(
            hdr_from='"Foo Bar" <foO.BAR.mONION@M.moRE-onion.COM>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost')
        self.assertEqual(self.milter._ctx.envlp_to, 'recipient@address.com')

    # -------------------------------------------------------------------------------------
    # internal host, header "From" NOT in hosted domains,
    # X-Mail-Domain is set and NOT IN hosted domains
    # -------------------------------------------------------------------------------------
    def test_eom_is_internal_yes_is_hosted_no_x_mail_domain_not_in_hosted_domains(self):
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='some.random.xmail.domain.net')
        self.assertEqual(result, Milter.TEMPFAIL)

    # -------------------------------------------------------------------------------------
    # internal host, header "From" NOT in hosted domains,
    # X-Mail-Domain is set and IN hosted domains
    # -------------------------------------------------------------------------------------
    def test_eom_is_internal_yes_is_hosted_no_x_mail_domain_in_hosted_domains(self):
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='m.more-onion.com',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        self.assertEqual(result, Milter.ACCEPT)

    def test_eom_is_internal_yes_is_hosted_yes_evlp_from_eq_hdr_from_z1436_nr1(self):
        self._prepare_eom(
            hdr_from='Stuart Fyfe <stuart.fyfe1@ntlworld.com <mailto:stuart.fyfe1@ntlworld.com>>',
            hdr_to='GLEN, John <john.glen.mp@parliament.uk <mailto:john.glen.mp@parliament.uk>>',
            envlp_from='bounce@action.openrightsgroup.org',
            envlp_to='john.glen.mp@parliament.uk',
            hostname='localhost',
            x_mail_domain='action.openrightsgroup.org',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        encoded_addr_regex = re.compile('\"Stuart Fyfe\" <stuart\.fyfe\.[a-zA-Z0-9]*@action\.openrightsgroup\.org')
        self.assertTrue(encoded_addr_regex.match(self.milter._ctx.header['From']))

    def test_eom_is_internal_yes_is_hosted_yes_evlp_from_eq_hdr_from_z1436_nr2(self):
        self._prepare_eom(
            hdr_from='Stuart Fyfe <stuart.fyfe1@ntlworld.com <mailto:stuart.fyfe1@ntlworld.com>>',
            hdr_to='GLEN, John <john.glen.mp@parliament.uk <mailto:john.glen.mp@parliament.uk>>',
            envlp_from='bounce@action.openrightsgroup.org',
            envlp_to='john.glen.mp@parliament.uk',
            hostname='localhost',
            x_mail_domain='action.openrightsgroup.org',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        self.assertEqual(self.milter._ctx.header['To'], 'GLEN, John <john.glen.mp@parliament.uk <mailto:john.glen.mp@parliament.uk>>')

    def test_eom_is_internal_yes_is_hosted_yes_evlp_from_eq_hdr_from_z1436_nr3(self):
        self._prepare_eom(
            hdr_from='Stuart Fyfe <stuart.fyfe1@ntlworld.com <mailto:stuart.fyfe1@ntlworld.com>>',
            hdr_to='GLEN, John <john.glen.mp@parliament.uk <mailto:john.glen.mp@parliament.uk>>',
            envlp_from='bounce@action.openrightsgroup.org',
            envlp_to='john.glen.mp@parliament.uk',
            hostname='localhost',
            x_mail_domain='action.openrightsgroup.org',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        self.assertEqual(self.milter._ctx.envlp_from, 'bounce@action.openrightsgroup.org')

    def test_eom_is_internal_yes_is_hosted_yes_evlp_from_eq_hdr_from_z1436_nr4(self):
        self._prepare_eom(
            hdr_from='Stuart Fyfe <stuart.fyfe1@ntlworld.com <mailto:stuart.fyfe1@ntlworld.com>>',
            hdr_to='GLEN, John <john.glen.mp@parliament.uk <mailto:john.glen.mp@parliament.uk>>',
            envlp_from='bounce@action.openrightsgroup.org',
            envlp_to='john.glen.mp@parliament.uk',
            hostname='localhost',
            x_mail_domain='action.openrightsgroup.org',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        self.assertEqual(self.milter._ctx.envlp_to, 'john.glen.mp@parliament.uk')

    def test_eom_is_internal_yes_is_hosted_no_x_mail_domain_in_hosted_domains_check_hdr_from(self):
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='m.more-onion.com',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        mapping = AddrMapping.get(AddrMapping.addr == 'some.supporter_name@some.address.net', AddrMapping.action_uuid == '9bed7305-8af0-42ff-adee-744657f73917')
        self.assertEqual(self.milter._ctx.header['From'], '"Firstname Last Name" <' + mapping.encoded_addr + '>')

    def test_eom_is_internal_yes_is_hosted_no_x_mail_domain_in_hosted_domains_check_hdr_to(self):
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='m.more-onion.com',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        self.assertEqual(self.milter._ctx.header['To'], '"The Recipient" <recipient@address.com>')

    def test_eom_is_internal_yes_is_hosted_no_x_mail_domain_in_hosted_domains_check_envlp_from(self):
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='m.more-onion.com',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        self.assertEqual(self.milter._ctx.envlp_from, self.config.return_paths['m.more-onion.com'])

    def test_eom_is_internal_yes_is_hosted_no_x_mail_domain_in_hosted_domains_check_envlp_to(self):
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='m.more-onion.com',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        self.assertEqual(self.milter._ctx.envlp_to, 'recipient@address.com')

    # -------------------------------------------------------------------------------------
    # internal host, header "From" NOT in hosted domains, X-Mail-Domain is NOT set
    # -------------------------------------------------------------------------------------
    def test_eom_is_internal_yes_is_hosted_no_x_mail_domain_undefined(self):
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost')
        self.assertEqual(result, Milter.TEMPFAIL)

    # -------------------------------------------------------------------------------------
    # internal host, header "From" NOT in hosted domains, X-Mail-Domain IS set,
    # X-Action-UUID is not set
    # -------------------------------------------------------------------------------------
    def test_eom_is_internal_yes_is_hosted_no_x_mail_domain_in_hosted_domains_x_action_uuid_not_set(self):
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='m.more-onion.com')
        self.assertEqual(result, Milter.TEMPFAIL)

    # -------------------------------------------------------------------------------------
    # internal host, 2 actions
    # -------------------------------------------------------------------------------------
    def test_eom_is_internal_2_actions_has_1st_mapping(self):
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='m.more-onion.com',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@other-address.com>',
            envlp_from='bounce@action.advocacy-engine.com',
            envlp_to='recipient@other-address.com',
            hostname='localhost',
            x_mail_domain='action.advocacy-engine.com',
            x_action_uuid='7f2e3be8-156e-4211-a35a-a654ff4ab99e')
        mapping = AddrMapping.get(AddrMapping.addr == 'some.supporter_name@some.address.net', AddrMapping.action_uuid == '9bed7305-8af0-42ff-adee-744657f73917')
        match = re.match('^firstname\.last_name\.[a-z]{11}[@]m\.more\-onion\.com$', mapping.encoded_addr)
        self.assertIsNotNone(match)

    def test_eom_is_internal_2_actions_has_2nd_mapping(self):
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='m.more-onion.com',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@other-address.com>',
            envlp_from='bounce@action.advocacy-engine.com',
            envlp_to='recipient@other-address.com',
            hostname='localhost',
            x_mail_domain='action.advocacy-engine.com',
            x_action_uuid='7f2e3be8-156e-4211-a35a-a654ff4ab99e')
        mapping = AddrMapping.get(AddrMapping.addr == 'some.supporter_name@some.address.net', AddrMapping.action_uuid == '7f2e3be8-156e-4211-a35a-a654ff4ab99e')
        match = re.match('^firstname\.last_name\.[a-z]{11}[@]action\.advocacy\-engine\.com$', mapping.encoded_addr)
        self.assertIsNotNone(match)

    def test_eom_is_internal_2_times_same_action(self):
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='m.more-onion.com',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>',
            hdr_to='"The Recipient" <recipient@address.com>',
            envlp_from='bounce@m.more-onion.com',
            envlp_to='recipient@address.com',
            hostname='localhost',
            x_mail_domain='m.more-onion.com',
            x_action_uuid='9bed7305-8af0-42ff-adee-744657f73917')
        mapping = AddrMapping.get(AddrMapping.addr == 'some.supporter_name@some.address.net', AddrMapping.action_uuid == '9bed7305-8af0-42ff-adee-744657f73917')
        match = re.match('^firstname\.last_name\.[a-z]{11}[@]m\.more\-onion\.com$', mapping.encoded_addr)
        self.assertIsNotNone(match)

    # -------------------------------------------------------------------------------------
    # internal host, "From" domain is not hosted, "To" domain is internal host
    # -------------------------------------------------------------------------------------
    def test_eom_is_internal_hdr_from_not_hosted_hdr_to_internal(self):
        result = self._prepare_eom(
            hdr_from='webdev@web.moreonion.com',
            hdr_to='hosting@donor-engine.com',
            envlp_from='root@web.moreonion.com',
            envlp_to='hosting@donor-engine.com',
            hostname='web.moreonion.com')
        self.assertEqual(result, Milter.ACCEPT)

    # -------------------------------------------------------------------------------------
    # external host, header "To" address has mapping
    # -------------------------------------------------------------------------------------
    def test_eom_is_not_internal_hdr_to_has_mapping(self):
        mapper = AddressMapper('m.more-onion.com', '9bed7305-8af0-42ff-adee-744657f73917')
        mapping = mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>'),
        )
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"' + mapping.name + '" <' + mapping.encoded_addr + '>',
            envlp_from='bounce@some.address.net',
            envlp_to=mapping.encoded_addr,
            hostname='some.address.net')
        self.assertEqual(result, Milter.ACCEPT)

    def test_eom_is_not_internal_hdr_to_has_mapping_check_mapped_hdr_to(self):
        mapper = AddressMapper('m.more-onion.com', '9bed7305-8af0-42ff-adee-744657f73917')
        mapping = mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>'),
        )
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"' + mapping.name + '" <' + mapping.encoded_addr + '>',
            envlp_from='bounce@some.address.net',
            envlp_to=mapping.encoded_addr,
            hostname='some.address.net')
        self.assertEqual(self.milter._ctx.header['To'], '"Firstname Last Name" <some.supporter_name@some.address.net>')

    def test_eom_is_not_internal_hdr_to_has_mapping_check_mapped_envlp_to(self):
        mapper = AddressMapper('m.more-onion.com', '9bed7305-8af0-42ff-adee-744657f73917')
        mapping = mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>'),
        )
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"' + mapping.name + '" <' + mapping.encoded_addr + '>',
            envlp_from='bounce@some.address.net',
            envlp_to=mapping.encoded_addr,
            hostname='some.address.net')
        self.assertEqual(self.milter._ctx.envlp_to, 'some.supporter_name@some.address.net')

    def test_eom_is_not_internal_hdr_to_has_mapping_check_z1436_nr5(self):
        mapper = AddressMapper('action.openrightsgroup.org', '9bed7305-8af0-42ff-adee-744657f73917')
        mapping = mapper.encodeAddress(
            EmailAddress(address='Stuart Fyfe <stuart.fyfe1@ntlworld.com <mailto:stuart.fyfe1@ntlworld.com>>'),
        )
        self._prepare_eom(
            hdr_from='GLEN, John <john.glen.mp@parliament.uk <mailto:john.glen.mp@parliament.uk>>',
            hdr_to='"' + mapping.name + '" <' + mapping.encoded_addr + '>',
            envlp_from='bounce@parliament.uk',
            envlp_to=mapping.encoded_addr,
            hostname='parliament.uk')

        self.assertEqual(self.milter._ctx.envlp_to, 'stuart.fyfe1@ntlworld.com')

    # -------------------------------------------------------------------------------------
    # external host, header "To" address has mapping, header "From" has mapping
    # -------------------------------------------------------------------------------------
    def test_eom_is_not_internal_hdr_to_has_mapping_hdr_from_has_mapping(self):
        mapper = AddressMapper('m.more-onion.com', '9bed7305-8af0-42ff-adee-744657f73917')
        recipient_mapping = mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>'),
        )
        mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>'),
        )
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"' + recipient_mapping.name + '" <' + recipient_mapping.encoded_addr + '>',
            envlp_from='bounce@some.address.net',
            envlp_to=recipient_mapping.encoded_addr,
            hostname='some.address.net')
        self.assertEqual(result, Milter.ACCEPT)

    def test_eom_is_not_internal_hdr_to_has_mapping_hdr_from_has_mapping_check_mapped_hdr_from(self):
        mapper = AddressMapper('m.more-onion.com', '9bed7305-8af0-42ff-adee-744657f73917')
        recipient_mapping = mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>'),
        )
        sender_mapping = mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>'),
        )
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"' + recipient_mapping.name + '" <' + recipient_mapping.encoded_addr + '>',
            envlp_from='bounce@some.address.net',
            envlp_to=recipient_mapping.encoded_addr,
            hostname='some.address.net')
        self.assertEqual(self.milter._ctx.header['From'], '"Firstname Last Name" <' + sender_mapping.encoded_addr + '>')

    def test_eom_is_not_internal_hdr_to_has_mapping_hdr_from_has_mapping_check_mapped_envlp_from(self):
        mapper = AddressMapper('m.more-onion.com', '9bed7305-8af0-42ff-adee-744657f73917')
        recipient_mapping = mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>'),
        )
        mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>'),
        )
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"' + recipient_mapping.name + '" <' + recipient_mapping.encoded_addr + '>',
            envlp_from='bounce@some.address.net',
            envlp_to=recipient_mapping.encoded_addr,
            hostname='some.address.net')
        self.assertEqual(self.milter._ctx.envlp_from, self.config.return_paths[self.milter.x_mail_domain])

    # -------------------------------------------------------------------------------------
    # external host, header "To" address has mapping, header "From" has no mapping
    # -------------------------------------------------------------------------------------
    def test_eom_is_not_internal_hdr_to_has_mapping_hdr_from_has_no_mapping(self):
        mapper = AddressMapper('m.more-onion.com', '9bed7305-8af0-42ff-adee-744657f73917')
        recipient_mapping = mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>'),
        )
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.other.ADDRESS.net>',
            hdr_to='"' + recipient_mapping.name + '" <' + recipient_mapping.encoded_addr + '>',
            envlp_from='bounce@some.other.address.net',
            envlp_to=recipient_mapping.encoded_addr,
            hostname='some.other.address.net')
        self.assertEqual(result, Milter.ACCEPT)

    def test_eom_is_not_internal_hdr_to_has_mapping_hdr_from_has_no_mapping_check_hdr_from(self):
        mapper = AddressMapper('m.more-onion.com', '9bed7305-8af0-42ff-adee-744657f73917')
        recipient_mapping = mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>'),
        )
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"' + recipient_mapping.name + '" <' + recipient_mapping.encoded_addr + '>',
            envlp_from='bounce@some.address.net',
            envlp_to=recipient_mapping.encoded_addr,
            hostname='some.address.net')
        get_mapping = AddrMapping.get(AddrMapping.addr == 'some.external_person@some.address.net', AddrMapping.action_uuid == mapper.action_uuid)
        self.assertEqual(self.milter._ctx.header['From'], '"' + get_mapping.name + '" <' + get_mapping.encoded_addr + '>')

    def test_eom_is_not_internal_hdr_to_has_mapping_hdr_from_has_no_mapping_check_envlp_from(self):
        mapper = AddressMapper('m.more-onion.com', '9bed7305-8af0-42ff-adee-744657f73917')
        recipient_mapping = mapper.encodeAddress(
            EmailAddress(address='"Firstname Last Name" <Some.Supporter_Name@some.ADDRESS.net>'),
        )
        self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"' + recipient_mapping.name + '" <' + recipient_mapping.encoded_addr + '>',
            envlp_from='bounce@some.address.net',
            envlp_to=recipient_mapping.encoded_addr,
            hostname='some.address.net')
        self.assertEqual(self.milter._ctx.envlp_from, self.config.return_paths[mapper.domain])

    # -------------------------------------------------------------------------------------
    # external host, header To address has no mapping
    # -------------------------------------------------------------------------------------
    def test_eom_is_not_internal_hdr_to_has_no_mapping(self):
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"Firstname Last Name" <some.LOCAL.part@m.MORE-onion.com>',
            envlp_from='bounce@some.address.net',
            envlp_to='some.local.part@m.more-onion.com',
            hostname='some.address.net')
        self.assertEqual(result, Milter.ACCEPT)

    def test_eom_is_not_internal_hdr_to_has_no_mapping_check_hdr_from(self):
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"Firstname Last Name" <some.LOCAL.part@m.MORE-onion.com>',
            envlp_from='bounce@some.address.net',
            envlp_to='some.local.part@m.more-onion.com',
            hostname='some.address.net')
        self.assertEqual(self.milter._ctx.header['From'], '"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>')

    def test_eom_is_not_internal_hdr_to_has_no_mapping_check_envlp_from(self):
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"Firstname Last Name" <some.LOCAL.part@m.MORE-onion.com>',
            envlp_from='bounce@some.address.net',
            envlp_to='some.local.part@m.more-onion.com',
            hostname='some.address.net')
        self.assertEqual(self.milter._ctx.envlp_from, 'bounce@some.address.net')

    def test_eom_is_not_internal_hdr_to_has_no_mapping_check_hdr_to(self):
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"Firstname Last Name" <some.LOCAL.part@m.MORE-onion.com>',
            envlp_from='bounce@some.address.net',
            envlp_to='some.local.part@m.more-onion.com',
            hostname='some.address.net')
        self.assertEqual(self.milter._ctx.header['To'], '"Firstname Last Name" <some.LOCAL.part@m.MORE-onion.com>')

    def test_eom_is_not_internal_hdr_to_has_no_mapping_check_envlp_to(self):
        result = self._prepare_eom(
            hdr_from='"Firstname Last Name" <Some.eXternal_person@some.ADDRESS.net>',
            hdr_to='"Firstname Last Name" <some.LOCAL.part@m.MORE-onion.com>',
            envlp_from='bounce@some.address.net',
            envlp_to='some.local.part@m.more-onion.com',
            hostname='some.address.net')
        self.assertEqual(self.milter._ctx.envlp_to, 'some.local.part@m.more-onion.com')
