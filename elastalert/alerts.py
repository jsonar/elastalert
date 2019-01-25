# -*- coding: utf-8 -*-
import ConfigParser
import copy
import json
import os
import socket
import urllib
import urlparse
from email.mime.text import MIMEText
from email.utils import formatdate
from smtplib import SMTP
from smtplib import SMTP_SSL
from smtplib import SMTPAuthenticationError
from smtplib import SMTPException

import pymongo
from staticconf.loader import yaml_loader
from texttable import Texttable

from constants import DISPATCHER_CONF, SYSLOG_DEFAULT_HOST, SYSLOG_DEFAULT_PORT, SYSLOG_DEFAULT_PROTOCOL

from util import EAException
from util import elasticsearch_client
from util import elastalert_logger
from util import get_sonar_connection
from util import lookup_es_key

from rule_type_definitions.aggregation_rules import MetricAggregationRule
from rule_type_definitions.cardinality_rule import CardinalityRule
from rule_type_definitions.compare_rules import BlacklistRule, WhitelistRule, ChangeRule
from rule_type_definitions.frequency_rules import FrequencyRule, FlatlineRule
from rule_type_definitions.new_terms_rule import NewTermsRule
from rule_type_definitions.spike_rule import SpikeRule


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


class BasicMatchString(object):
    """ Creates a string containing fields in match for the given rule. """

    def __init__(self, rule, match):
        self.rule = rule
        self.match = match

    def _ensure_new_line(self):
        while self.text[-2:] != '\n\n':
            self.text += '\n'

    def _add_custom_alert_text(self):
        missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
        alert_text = unicode(self.rule.get('alert_text', ''))
        if 'alert_text_args' in self.rule:
            alert_text_args = self.rule.get('alert_text_args')
            alert_text_values = [lookup_es_key(self.match, arg) for arg in alert_text_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i, text_value in enumerate(alert_text_values):
                if text_value is None:
                    alert_value = self.rule.get(alert_text_args[i])
                    if alert_value:
                        alert_text_values[i] = alert_value

            alert_text_values = [missing if val is None else val for val in alert_text_values]
            alert_text = alert_text.format(*alert_text_values)
        elif 'alert_text_kw' in self.rule:
            kw = {}
            for name, kw_name in self.rule.get('alert_text_kw').items():
                val = lookup_es_key(self.match, name)

                # Support referencing other top-level rule properties
                # This technically may not work if there is a top-level rule property with the same name
                # as an es result key, since it would have been matched in the lookup_es_key call above
                if val is None:
                    val = self.rule.get(name)

                kw[kw_name] = missing if val is None else val
            alert_text = alert_text.format(**kw)

        self.text += alert_text

    def _add_rule_text(self):
        self.text += self.rule['type'].get_match_str(self.match)

    def _add_top_counts(self):
        for key, counts in self.match.items():
            if key.startswith('top_events_'):
                self.text += '%s:\n' % (key[11:])
                top_events = counts.items()

                if not top_events:
                    self.text += 'No events found.\n'
                else:
                    top_events.sort(key=lambda x: x[1], reverse=True)
                    for term, count in top_events:
                        self.text += '%s: %s\n' % (term, count)

                self.text += '\n'

    def _add_match_items(self):
        match_items = self.match.items()
        match_items.sort(key=lambda x: x[0])
        for key, value in match_items:
            if key.startswith('top_events_'):
                continue
            value_str = unicode(value)
            value_str.replace('\\n', '\n')
            if type(value) in [list, dict]:
                try:
                    value_str = self._pretty_print_as_json(value)
                except TypeError:
                    # Non serializable object, fallback to str
                    pass
            self.text += '%s: %s\n' % (key, value_str)

    def _pretty_print_as_json(self, blob):
        try:
            return json.dumps(blob, cls=DateTimeEncoder, sort_keys=True, indent=4, ensure_ascii=False)
        except UnicodeDecodeError:
            # This blob contains non-unicode, so lets pretend it's Latin-1 to show something
            return json.dumps(blob, cls=DateTimeEncoder, sort_keys=True, indent=4,
                              encoding='Latin-1', ensure_ascii=False)

    def __str__(self):
        self.text = ''
        if 'alert_text' not in self.rule:
            self.text += self.rule['name'] + '\n\n'

        self._add_custom_alert_text()
        self._ensure_new_line()
        if self.rule.get('alert_text_type') != 'alert_text_only':
            self._add_rule_text()
            self._ensure_new_line()
            if self.rule.get('top_count_keys'):
                self._add_top_counts()
            if self.rule.get('alert_text_type') != 'exclude_fields':
                self._add_match_items()
        return self.text


class SonarFormattedMatchString:
    def __init__(self, rule, match):
        self.rule = rule
        self.match = match
        self.match_time = match[rule['timestamp_field']]

    def __str__(self):
        """
        :return: A human readable string describing the event that raised the alert.
        """

        text = "Rule \"{}\" generated an alert at {}.  ".format(self.rule['name'], self.match_time)
        if isinstance(self.rule['type'], BlacklistRule):
            text += "{} occurrences of blacklisted value {} occurred in field {}.".format(
                self.match['doc_count'], self.match['watched_field_value'], self.match['watched_field'])

        elif isinstance(self.rule['type'], WhitelistRule):
            text += "{} occurrences of non-whitelisted value {} occurred in field {}.".format(
                self.match['doc_count'], self.match['watched_field_value'], self.match['watched_field'])

        elif isinstance(self.rule['type'], FlatlineRule):
            if self.rule.get('query_key'):
                text += "{} events in timeframe with a value {} for key {}. Minimum of {} expected.".format(
                    self.match['num_hits'],
                    self.match['key'],
                    self.rule['query_key'],
                    self.rule['threshold'])
            else:
                text += "{} events in timeframe. Minimum of {} expected".format(self.match['num_hits'],
                                                                                   self.rule['threshold'])
        elif isinstance(self.rule['type'], ChangeRule):
            text += "The values of {0} for value {1} of query key {2} contain {3} entries that differ from the value " \
                    "of {0} when the rule last ran.".format(self.rule['compare_key'], self.match['watched_field_value'],
                                                           self.rule['query_key'], self.match['doc_count'])

        elif isinstance(self.rule['type'], FrequencyRule):
            if self.rule.get('query_key'):
                text += "{} events in timeframe where {} was {}. Less than {} events expected.".format(
                    self.match['num_hits'],
                    self.rule['query_key'],
                    self.match[self.rule['query_key']],
                    self.rule['num_events']
                    )
            else:
                text += "{} events in timeframe. Maximum of {} expected.".format(self.match['num_hits'],
                                                                                   self.rule['num_events'])
        elif isinstance(self.rule['type'], SpikeRule):
            text += "{} hits in spike. {} hits in previous window.".format(self.match['spike_count'],
                                                                          self.match['reference_count'])
        elif isinstance(self.rule['type'], CardinalityRule):
            if self.rule.get('query_key'):
                text += "Cardinality of field {} for value {} of query key {} is {}. " \
                        "This is not between {} and {}".format(self.rule['cardinality_field'],
                                                               self.match['key'],
                                                               self.rule['query_key'],
                                                               self.match['cardinality'],
                                                               self.rule['min_cardinality'],
                                                               self.rule['max_cardinality'])
            else:
                text += "Cardinality of field {} is {}. This is not between {} and {}.".format(
                    self.rule['cardinality_field'], self.match['cardinality'],
                        self.rule['min_cardinality'], self.rule['max_cardinality'])

        elif isinstance(self.rule['type'], NewTermsRule):
            text += 'New term: {} occurred in field {}.'.format(self.match['watched_field_value'],
                                                               self.match['watched_field'])

        elif isinstance(self.rule['type'], MetricAggregationRule):
            text += '{} is the {} of field {}. This is not between {} and {}.'.format(
                self.match['{}_{}'.format(self.rule['metric_agg_key'], self.rule['metric_agg_type'])],
                self.rule['metric_agg_type'], self.rule['metric_agg_key'], self.rule['min_threshold'],
                self.rule['max_threshold']
            )

        if self.rule.get('timeframe'):
            text += ' The Timeframe for this rule was: {}'.format(self.rule.get('timeframe'))

        return text


class SyslogFormattedMatch:
    """Object containing the data and instructions on formatting needed to output messages to syslog in
    cef, leef or json format. It does this using the $out functionality of sonar, by storing the necessary data in a
    collection and then projecting all fields of the temporary collection to an out stage configured to send the data
    onwards to syslog in the appropriate format"""
    def __init__(self, rule, match, sonar_con, syslog_host, syslog_port, syslog_protocol, output_format,
                 vendor, product, version):
        """
        :param rule: The rule dictionary containing the parameters of the running rule
        :param match: Information about what triggered this alert. Contents vary by rule type.
        :param dispatch_config: config parser loaded from dispatcher.conf
        :param sonar_con: Pymongo connection to sonar
        """
        self.rule = rule
        self.match = match
        self.sonar_con = sonar_con
        self.sonargd = self.sonar_con['sonargd']
        self.alerts_collection = self.sonargd['tmp_alert']
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self.syslog_protocol = syslog_protocol
        self.output_format = output_format
        self.vendor = vendor
        self.product = product
        self.version = version

    def output_alert(self):
        if self.output_format == 'cef':
            self.output_cef()
        elif self.output_format == 'leef':
            self.output_leef()
        else:
            self.output_json()

    def generate_base_json(self):
        """"
        Inserts a json document containing the rule specific information about the event that triggered the alert
        """
        out_json = {'rule': self.rule['name'], 'match_time': self.match[self.rule['timestamp_field']]}

        if self.rule.get('timeframe'):
            out_json.update({'timeframe': str(self.rule.get('timeframe'))})

        if isinstance(self.rule['type'], BlacklistRule):
            out_json.update({'blacklist_field': self.match['watched_field'],
                             'blacklisted_value': self.match['watched_field_value'],
                             'occurrences': self.match['doc_count']})

        elif isinstance(self.rule['type'], WhitelistRule):
            out_json.update({'whitelist_field': self.match['watched_field'],
                             'non-whitelist_value': self.match['watched_field_value'],
                             'occurrences': self.match['doc_count']})

        elif isinstance(self.rule['type'], FlatlineRule):
            if self.rule.get('query_key'):
                out_json.update({'num_hits': self.match['count'],
                                 'threshold': self.rule['threshold'],
                                 'query_key': self.rule['query_key'],
                                 'query_key_value': self.match['key']
                                 })
            else:
                out_json.update({'num_hits': self.match['num_hits'], 'threshold': self.rule['threshold']})

        elif isinstance(self.rule['type'], ChangeRule):
            out_json.update({'compare_key': self.rule['compare_key'],
                             'query_key': self.rule['query_key'],
                             'query_key_value': self.match['watched_field_value'],
                             'num_changed_values': self.match['doc_count']})

        elif isinstance(self.rule['type'], FrequencyRule):
            if self.rule.get('query_key'):
                out_json.update({'frequency': self.match['count'],
                                 'threshold': self.rule['num_events'],
                                 'query_key': self.rule['query_key'],
                                 'query_key_value': self.match[self.rule['query_key']]
                                 })
            else:
                out_json.update({'frequency': self.match['num_hits'], 'threshold': self.rule['num_events']})

        elif isinstance(self.rule['type'], SpikeRule):
            out_json.update({'spike_window_hits': self.match['spike_count'],
                             'reference_window_hits': self.match['reference_count']})

        elif isinstance(self.rule['type'], CardinalityRule):
            if self.rule.get('query_key'):
                out_json.update({'cardinality_field': self.rule['cardinality_field'],
                                 'cardinality': self.match['cardinality'],
                                 'min_cardinality': self.rule['min_cardinality'],
                                 'max_cardinality': self.rule['min_cardinality'],
                                 'query_key': self.rule['query_key'],
                                 'query_key_value': self.match['key']
                                 })
            else:
                out_json.update({'cardinality_field': self.rule['cardinality_field'],
                                 'cardinality': self.match['cardinality'],
                                 'min_cardinality': self.rule['min_cardinality'],
                                 'max_cardinality': self.rule['min_cardinality']
                                 })

        elif isinstance(self.rule['type'], NewTermsRule):
            out_json.update({'new_term': self.match['watched_field_value'],
                             'new_term_field': self.match['watched_field']})

        elif isinstance(self.rule['type'], MetricAggregationRule):
            out_json.update({'metric-agg_result': self.match['{}_{}'.format(self.rule['metric_agg_key'],
                                                                            self.rule['metric_agg_type'])],
                             'metric_agg_type': self.rule['metric_agg_type'],
                             'metric_agg_key': self.rule['metric_agg_key'],
                             'min_threshold': self.rule['min_threshold'],
                             'max_threshold': self.rule['max_threshold']
                             })

        self.alerts_collection.insert_one(out_json)

        return out_json

    def drop_tmp_collection(self):
        self.sonargd.drop_collection('tmp_alert')

    def output_json(self):
        self.generate_base_json()

        self.alerts_collection.aggregate([{'$project': {'*': 1, '_id': 0}},
                                          {'$out': {
                                                'format': 'json',
                                                'fstype': 'syslog',
                                                'syslog_params': {
                                                        'sendto': self.syslog_host,
                                                        'loglevel': 'notice',
                                                        'facility': 'user',
                                                        'protocol': self.syslog_protocol,
                                                        'port': self.syslog_port
                                                }}}]

                                         )
        self.drop_tmp_collection()

    def output_cef(self):
        # CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        self.generate_base_json()
        doc = self.alerts_collection.find_one()
        rule_name = doc['rule']
        match_time = doc['match_time']
        self.alerts_collection.aggregate([
            {'$addFields': {'end': match_time}},
            {"$project": {"*": 1, 'rule': 0, 'match_time': 0}},
            {'$out': {
                     "fstype": "syslog",
                     'syslog_params': {
                         'sendto': self.syslog_host,
                         'loglevel': 'notice',
                         'facility': 'user',
                         'protocol': self.syslog_protocol,
                         'port': self.syslog_port
                     },
                     "format": "cef",
                     "cef_params": {
                         "vendor": self.vendor,
                         "product": self.product,
                         "product_version": self.version,
                         'name': rule_name,
                         "ignore_fields": ["_id"]
                     }}}])
        self.drop_tmp_collection()

    def output_leef(self):
        # LEEF:2 | Vendor | Product | Version | EventID |\tkey1=value1\tkey2=value2
        self.generate_base_json()
        doc = self.alerts_collection.find_one()
        match_time = doc['match_time']
        event_id = doc['_id']
        self.alerts_collection.aggregate([{'$addFields': {'devTime': match_time}},
                                          {'$project': {'*': 1, 'match_time': 0, '_id': 0}},
                                          {"$out": {"format": "leef",
                                                    "fstype": "syslog",
                                                    'product': self.product,
                                                    'eventid': event_id,
                                                    'product_version': self.version,
                                                    "syslog_params":
                                                        {"protocol": self.syslog_protocol,
                                                         "sendto": self.syslog_host,
                                                         "port": self.syslog_port,
                                                         "loglevel": "notice"}}}])

        self.drop_tmp_collection()


class Alerter(object):
    """ Base class for types of alerts.

    :param rule: The rule configuration.
    """
    required_options = frozenset([])

    def __init__(self, rule):
        self.rule = rule
        # pipeline object is created by ElastAlerter.send_alert()
        # and attached to each alerters used by a rule before calling alert()
        self.pipeline = None
        self.resolve_rule_references(self.rule)
        self.dispatch_conf = ConfigParser.ConfigParser()
        self.dispatch_conf.read(DISPATCHER_CONF)

        self.sonar_uri = self.dispatch_conf.get('dispatch', 'sonarw_uri')
        self.sonar_con = get_sonar_connection(self.sonar_uri)

        try:
            self.syslog_host = socket.gethostbyname(self.dispatch_conf.get('remote_syslog', 'host'))
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError, socket.error):
            elastalert_logger.warning('No host field set in remote_syslog section of dispatcher.conf.'
                                      ' Defaulting to {}'.format(SYSLOG_DEFAULT_HOST))
            self.syslog_host = SYSLOG_DEFAULT_HOST

        try:
            self.syslog_port = int(self.dispatch_conf.get('remote_syslog', 'port'))
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            elastalert_logger.warning('No port field set in remote_syslog section of dispatcher.conf.'
                                      ' Defaulting to {}'.format(SYSLOG_DEFAULT_PORT))
            self.syslog_port = SYSLOG_DEFAULT_PORT

        try:
            self.syslog_protocol = self.dispatch_conf.get('remote_syslog', 'protocol').lower()
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            elastalert_logger.warning('No protocol field set in remote_syslog section of dispatcher.conf.'
                                      ' Defaulting to {}'.format(SYSLOG_DEFAULT_PROTOCOL))
            self.syslog_protocol = SYSLOG_DEFAULT_PROTOCOL

        try:
            self.output_format = self.sonar_con['lmrm__sonarg']['lmrm__ae_config'].find_one()['syslogType']
        except Exception as e:
            elastalert_logger.error('Failed to get syslog output format. Error: {}'.format(e))
            self.output_format = json

        self.vendor = 'jSonar'
        self.product = 'SonarW'
        try:
            self.version = self.sonar_con['admin']['sonarg'].find_one()['version']
        except KeyError:
            self.version = 'unknown_version'


    def resolve_rule_references(self, root):
        # Support referencing other top-level rule properties to avoid redundant copy/paste
        if type(root) == list:
            # Make a copy since we may be modifying the contents of the structure we're walking
            for i, item in enumerate(copy.copy(root)):
                if type(item) == dict or type(item) == list:
                    self.resolve_rule_references(root[i])
                else:
                    root[i] = self.resolve_rule_reference(item)
        elif type(root) == dict:
            # Make a copy since we may be modifying the contents of the structure we're walking
            for key, value in root.copy().iteritems():
                if type(value) == dict or type(value) == list:
                    self.resolve_rule_references(root[key])
                else:
                    root[key] = self.resolve_rule_reference(value)

    def resolve_rule_reference(self, value):
        strValue = unicode(value)
        if strValue.startswith('$') and strValue.endswith('$') and strValue[1:-1] in self.rule:
            if type(value) == int:
                return int(self.rule[strValue[1:-1]])
            else:
                return self.rule[strValue[1:-1]]
        else:
            return value

    def alert(self, match):
        """ Send an alert. Match is a dictionary of information about the alert.

        :param match: A dictionary of relevant information to the alert.
        """
        raise NotImplementedError()

    def get_info(self):
        """ Returns a dictionary of data related to this alert. At minimum, this should contain
        a field type corresponding to the type of Alerter. """
        return {'type': 'Unknown'}

    def create_title(self, matches):
        """ Creates custom alert title to be used, e.g. as an e-mail subject or JIRA issue summary.

        :param matches: A list of dictionaries of relevant information to the alert.
        """
        if 'alert_subject' in self.rule:
            return self.create_custom_title(matches)

        return self.create_default_title(matches)

    def create_custom_title(self, matches):
        alert_subject = unicode(self.rule['alert_subject'])

        if 'alert_subject_args' in self.rule:
            alert_subject_args = self.rule['alert_subject_args']
            alert_subject_values = [lookup_es_key(matches[0], arg) for arg in alert_subject_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i, subject_value in enumerate(alert_subject_values):
                if subject_value is None:
                    alert_value = self.rule.get(alert_subject_args[i])
                    if alert_value:
                        alert_subject_values[i] = alert_value

            missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
            alert_subject_values = [missing if val is None else val for val in alert_subject_values]
            return alert_subject.format(*alert_subject_values)

        return alert_subject

    def create_alert_body(self, matches):
        body = self.get_aggregation_summary_text(matches)
        if self.rule.get('alert_text_type') != 'aggregation_summary_only':
            for match in matches:
                body += unicode(BasicMatchString(self.rule, match))
                # Separate text of aggregated alerts with dashes
                if len(matches) > 1:
                    body += '\n----------------------------------------\n'
        return body

    def get_aggregation_summary_text__maximum_width(self):
        """Get maximum width allowed for summary text."""
        return 80

    def get_aggregation_summary_text(self, matches):
        text = ''
        if 'aggregation' in self.rule and 'summary_table_fields' in self.rule:
            text = self.rule.get('summary_prefix', '')
            summary_table_fields = self.rule['summary_table_fields']
            if not isinstance(summary_table_fields, list):
                summary_table_fields = [summary_table_fields]
            # Include a count aggregation so that we can see how many of each aggregation_key were encountered
            summary_table_fields_with_count = summary_table_fields + ['count']
            text += "Aggregation resulted in the following data for summary_table_fields ==> {0}:\n\n".format(
                summary_table_fields_with_count
            )
            text_table = Texttable(max_width=self.get_aggregation_summary_text__maximum_width())
            text_table.header(summary_table_fields_with_count)
            # Format all fields as 'text' to avoid long numbers being shown as scientific notation
            text_table.set_cols_dtype(['t' for i in summary_table_fields_with_count])
            match_aggregation = {}

            # Maintain an aggregate count for each unique key encountered in the aggregation period
            for match in matches:
                key_tuple = tuple([unicode(lookup_es_key(match, key)) for key in summary_table_fields])
                if key_tuple not in match_aggregation:
                    match_aggregation[key_tuple] = 1
                else:
                    match_aggregation[key_tuple] = match_aggregation[key_tuple] + 1
            for keys, count in match_aggregation.iteritems():
                text_table.add_row([key for key in keys] + [count])
            text += text_table.draw() + '\n\n'
            text += self.rule.get('summary_prefix', '')
        return unicode(text)

    def create_default_title(self, matches):
        return self.rule['name']

    def get_account(self, account_file):
        """ Gets the username and password from an account file.

        :param account_file: Path to the file which contains user and password information.
        It can be either an absolute file path or one that is relative to the given rule.
        """
        if os.path.isabs(account_file):
            account_file_path = account_file
        else:
            account_file_path = os.path.join(os.path.dirname(self.rule['rule_file']), account_file)
        account_conf = yaml_loader(account_file_path)
        if 'user' not in account_conf or 'password' not in account_conf:
            raise EAException('Account file must have user and password fields')
        self.user = account_conf['user']
        self.password = account_conf['password']


class DebugAlerter(Alerter):
    """ The debug alerter uses a Python logger (by default, alerting to terminal). """

    def alert(self, matches):
        qk = self.rule.get('query_key', None)
        for match in matches:
            if qk in match:
                elastalert_logger.info(
                    'Alert for %s, %s at %s:' % (self.rule['name'], match[qk],
                                                 lookup_es_key(match, self.rule['timestamp_field'])))
            else:
                elastalert_logger.info('Alert for %s at %s:' % (self.rule['name'],
                                                                lookup_es_key(match, self.rule['timestamp_field'])))
            elastalert_logger.info(unicode(BasicMatchString(self.rule, match)))

    def get_info(self):
        return {'type': 'debug'}


class SyslogAlerter(Alerter):
    """Sends payloads to rsyslog/sonar gateway."""

    def __init__(self, *args):
        super(SyslogAlerter, self).__init__(*args)

    def alert(self, matches):
        for match in matches:
            output = SyslogFormattedMatch(self.rule, match, self.sonar_con, self.syslog_host, self.syslog_port,
                                          self.syslog_protocol, self.output_format, self.vendor,
                                          self.product, self.version)
            output.output_alert()
            elastalert_logger.info('Alert sent to Syslog')

    def get_info(self):
        return {
            'type': 'syslog'
        }


class SonarDispatcherAlerter(Alerter):
    """Sends an email alert through sonardispatcher."""
    required_options = frozenset(['email'])

    def __init__(self, *args):
        super(SonarDispatcherAlerter, self).__init__(*args)
        # Convert email to a list if it isn't already
        if isinstance(self.rule['email'], basestring):
            self.rule['email'] = [self.rule['email']]
        self.es_client = elasticsearch_client(self.rule)

    def alert(self, matches):
        """
        Sends the alert to sonar dispatcher to be emailed to the system admin address configured in sonar
        :param matches: dictionary containing rule specific information about the event that raised the alert
        """
        subject = '[SonarK Alerts] Rule "{}" alert'.format(self.rule['name'])
        if not self.rule['bundle_alerts']:
            for match in matches:
                self.es_client.index(
                    'lmrm__scheduler-lmrm__dispatched_jobs',
                    '_doc',
                    {
                        'name': 'sonark_alerts',
                        'emails': self.rule['email'],
                        'type': 'send_email',
                        'subject': subject,
                        'email_content': str(SonarFormattedMatchString(self.rule, match))
                    })

            elastalert_logger.info('Alert sent to SonarDispatcher')

        else:
            email_content = ''
            for match in matches:
                email_content += str(SonarFormattedMatchString(self.rule, match)) + '\n'

            self.es_client.index(
                'lmrm__scheduler-lmrm__dispatched_jobs',
                '_doc',
                {
                    'name': 'sonark_alerts',
                    'emails': self.rule['email'],
                    'type': 'send_email',
                    'subject': subject,
                    'email_content': email_content
                })

            elastalert_logger.info('Bundled Alerts sent to SonarDispatcher')

    def get_info(self):
        return {
            'type': 'sonardispatcher',
            'recipients': self.rule['email']
        }


class EmailAlerter(Alerter):
    """ Sends an email alert """
    required_options = frozenset(['email'])

    def __init__(self, *args):
        super(EmailAlerter, self).__init__(*args)

        self.smtp_host = self.rule.get('smtp_host', 'localhost')
        self.smtp_ssl = self.rule.get('smtp_ssl', False)
        self.from_addr = self.rule.get('from_addr', 'ElastAlert')
        self.smtp_port = self.rule.get('smtp_port')
        if self.rule.get('smtp_auth_file'):
            self.get_account(self.rule['smtp_auth_file'])
        self.smtp_key_file = self.rule.get('smtp_key_file')
        self.smtp_cert_file = self.rule.get('smtp_cert_file')
        # Convert email to a list if it isn't already
        if isinstance(self.rule['email'], basestring):
            self.rule['email'] = [self.rule['email']]
        # If there is a cc then also convert it a list if it isn't
        cc = self.rule.get('cc')
        if cc and isinstance(cc, basestring):
            self.rule['cc'] = [self.rule['cc']]
        # If there is a bcc then also convert it to a list if it isn't
        bcc = self.rule.get('bcc')
        if bcc and isinstance(bcc, basestring):
            self.rule['bcc'] = [self.rule['bcc']]
        add_suffix = self.rule.get('email_add_domain')
        if add_suffix and not add_suffix.startswith('@'):
            self.rule['email_add_domain'] = '@' + add_suffix

    def alert(self, matches):
        body = self.create_alert_body(matches)

        # Add JIRA ticket if it exists
        if self.pipeline is not None and 'jira_ticket' in self.pipeline:
            url = '%s/browse/%s' % (self.pipeline['jira_server'], self.pipeline['jira_ticket'])
            body += '\nJIRA ticket: %s' % (url)

        to_addr = self.rule['email']
        if 'email_from_field' in self.rule:
            recipient = lookup_es_key(matches[0], self.rule['email_from_field'])
            if isinstance(recipient, basestring):
                if '@' in recipient:
                    to_addr = [recipient]
                elif 'email_add_domain' in self.rule:
                    to_addr = [recipient + self.rule['email_add_domain']]
            elif isinstance(recipient, list):
                to_addr = recipient
                if 'email_add_domain' in self.rule:
                    to_addr = [name + self.rule['email_add_domain'] for name in to_addr]
        if self.rule.get('email_format') == 'html':
            email_msg = MIMEText(body.encode('UTF-8'), 'html', _charset='UTF-8')
        else:
            email_msg = MIMEText(body.encode('UTF-8'), _charset='UTF-8')
        email_msg['Subject'] = self.create_title(matches)
        email_msg['To'] = ', '.join(to_addr)
        email_msg['From'] = self.from_addr
        email_msg['Reply-To'] = self.rule.get('email_reply_to', email_msg['To'])
        email_msg['Date'] = formatdate()
        if self.rule.get('cc'):
            email_msg['CC'] = ','.join(self.rule['cc'])
            to_addr = to_addr + self.rule['cc']
        if self.rule.get('bcc'):
            to_addr = to_addr + self.rule['bcc']

        try:
            if self.smtp_ssl:
                if self.smtp_port:
                    self.smtp = SMTP_SSL(self.smtp_host, self.smtp_port,
                                         keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
                else:
                    self.smtp = SMTP_SSL(self.smtp_host, keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
            else:
                if self.smtp_port:
                    self.smtp = SMTP(self.smtp_host, self.smtp_port)
                else:
                    self.smtp = SMTP(self.smtp_host)
                self.smtp.ehlo()
                if self.smtp.has_extn('STARTTLS'):
                    self.smtp.starttls(keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
            if 'smtp_auth_file' in self.rule:
                self.smtp.login(self.user, self.password)
        except (SMTPException, socket.error) as e:
            raise EAException("Error connecting to SMTP host: %s" % e)
        except SMTPAuthenticationError as e:
            raise EAException("SMTP username/password rejected: %s" % e)
        self.smtp.sendmail(self.from_addr, to_addr, email_msg.as_string())
        self.smtp.close()

        elastalert_logger.info("Sent email to %s" % to_addr)

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])

        # If the rule has a query_key, add that value plus timestamp to subject
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                subject += ' - %s' % (qk)

        return subject

    def get_info(self):
        return {'type': 'email',
                'recipients': self.rule['email']}
