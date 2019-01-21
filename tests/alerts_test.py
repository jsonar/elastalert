# -*- coding: utf-8 -*-
import datetime
import json

import mock
import pytest

from elastalert.alerts import Alerter
from elastalert.alerts import BasicMatchString
from elastalert.alerts import EmailAlerter
from elastalert.opsgenie import OpsGenieAlerter
from elastalert.util import ts_add


class mock_rule:
    def get_match_str(self, event):
        return str(event)


def test_basic_match_string(ea):
    ea.rules[0]['top_count_keys'] = ['username']
    match = {'@timestamp': '1918-01-17', 'field': 'value', 'top_events_username': {'bob': 10, 'mallory': 5}}
    alert_text = unicode(BasicMatchString(ea.rules[0], match))
    assert 'anytest' in alert_text
    assert 'some stuff happened' in alert_text
    assert 'username' in alert_text
    assert 'bob: 10' in alert_text
    assert 'field: value' in alert_text

    # Non serializable objects don't cause errors
    match['non-serializable'] = {open: 10}
    alert_text = unicode(BasicMatchString(ea.rules[0], match))

    # unicode objects dont cause errors
    match['snowman'] = u'☃'
    alert_text = unicode(BasicMatchString(ea.rules[0], match))

    # Pretty printed objects
    match.pop('non-serializable')
    match['object'] = {'this': {'that': [1, 2, "3"]}}
    alert_text = unicode(BasicMatchString(ea.rules[0], match))
    assert '"this": {\n        "that": [\n            1, \n            2, \n            "3"\n        ]\n    }' in alert_text

    ea.rules[0]['alert_text'] = 'custom text'
    alert_text = unicode(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'anytest' not in alert_text

    ea.rules[0]['alert_text_type'] = 'alert_text_only'
    alert_text = unicode(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'some stuff happened' not in alert_text
    assert 'username' not in alert_text
    assert 'field: value' not in alert_text

    ea.rules[0]['alert_text_type'] = 'exclude_fields'
    alert_text = unicode(BasicMatchString(ea.rules[0], match))
    assert 'custom text' in alert_text
    assert 'some stuff happened' in alert_text
    assert 'username' in alert_text
    assert 'field: value' not in alert_text


def test_email():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com', 'owner': 'owner_value',
            'alert_subject': 'Test alert for {0}, owned by {1}', 'alert_subject_args': ['test_term', 'owner'], 'snowman': u'☃'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body


def test_email_from_field():
    rule = {'name': 'test alert', 'email': ['testing@test.test'], 'email_add_domain': 'example.com',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_from_field': 'data.user', 'owner': 'owner_value'}
    # Found, without @
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': 'qlo'}}])
        assert mock_smtp.mock_calls[4][1][1] == ['qlo@example.com']

    # Found, with @
    rule['email_add_domain'] = '@example.com'
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': 'qlo'}}])
        assert mock_smtp.mock_calls[4][1][1] == ['qlo@example.com']

    # Found, list
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': ['qlo', 'foo']}}])
        assert mock_smtp.mock_calls[4][1][1] == ['qlo@example.com', 'foo@example.com']

    # Not found
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'foo': 'qlo'}}])
        assert mock_smtp.mock_calls[4][1][1] == ['testing@test.test']

    # Found, wrong type
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()
        alert = EmailAlerter(rule)
        alert.alert([{'data': {'user': 17}}])
        assert mock_smtp.mock_calls[4][1][1] == ['testing@test.test']


def test_email_with_unicode_strings():
    rule = {'name': 'test alert', 'email': u'testing@test.test', 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com', 'owner': 'owner_value',
            'alert_subject': 'Test alert for {0}, owned by {1}', 'alert_subject_args': ['test_term', 'owner'], 'snowman': u'☃'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, [u'testing@test.test'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value, owned by owner_value' in body


def test_email_with_auth():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'alert_subject': 'Test alert for {0}', 'alert_subject_args': ['test_term'], 'smtp_auth_file': 'file.txt',
            'rule_file': '/tmp/foo.yaml'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        with mock.patch('elastalert.alerts.yaml_loader') as mock_open:
            mock_open.return_value = {'user': 'someone', 'password': 'hunter2'}
            mock_smtp.return_value = mock.Mock()
            alert = EmailAlerter(rule)

        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().login('someone', 'hunter2'),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected


def test_email_with_cert_key():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'alert_subject': 'Test alert for {0}', 'alert_subject_args': ['test_term'], 'smtp_auth_file': 'file.txt',
            'smtp_cert_file': 'dummy/cert.crt', 'smtp_key_file': 'dummy/client.key', 'rule_file': '/tmp/foo.yaml'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        with mock.patch('elastalert.alerts.yaml_loader') as mock_open:
            mock_open.return_value = {'user': 'someone', 'password': 'hunter2'}
            mock_smtp.return_value = mock.Mock()
            alert = EmailAlerter(rule)

        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile='dummy/cert.crt', keyfile='dummy/client.key'),
                    mock.call().login('someone', 'hunter2'),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected


def test_email_with_cc():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'cc': 'tester@testing.testing'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test', 'tester@testing.testing'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'CC: tester@testing.testing' in body
        assert 'From: testfrom@test.test' in body


def test_email_with_bcc():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'bcc': 'tester@testing.testing'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test', 'tester@testing.testing'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'CC: tester@testing.testing' not in body
        assert 'From: testfrom@test.test' in body


def test_email_with_cc_and_bcc():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'], 'from_addr': 'testfrom@test.test',
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'cc': ['test1@test.com', 'test2@test.com'], 'bcc': 'tester@testing.testing'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value'}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(
                        mock.ANY,
                        [
                            'testing@test.test',
                            'test@test.test',
                            'test1@test.com',
                            'test2@test.com',
                            'tester@testing.testing'
                        ],
                        mock.ANY
        ),
            mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'CC: test1@test.com,test2@test.com' in body
        assert 'From: testfrom@test.test' in body


def test_email_with_args():
    rule = {
        'name': 'test alert',
        'email': ['testing@test.test', 'test@test.test'],
        'from_addr': 'testfrom@test.test',
        'type': mock_rule(),
        'timestamp_field': '@timestamp',
        'email_reply_to': 'test@example.com',
        'alert_subject': 'Test alert for {0} {1}',
        'alert_subject_args': ['test_term', 'test.term'],
        'alert_text': 'Test alert for {0} and {1} {2}',
        'alert_text_args': ['test_arg1', 'test_arg2', 'test.arg3'],
        'alert_missing_value': '<CUSTOM MISSING VALUE>'
    }
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value', 'test_arg1': 'testing', 'test': {'term': ':)', 'arg3': u'☃'}}])
        expected = [mock.call('localhost'),
                    mock.call().ehlo(),
                    mock.call().has_extn('STARTTLS'),
                    mock.call().starttls(certfile=None, keyfile=None),
                    mock.call().sendmail(mock.ANY, ['testing@test.test', 'test@test.test'], mock.ANY),
                    mock.call().close()]
        assert mock_smtp.mock_calls == expected

        body = mock_smtp.mock_calls[4][1][2]
        # Extract the MIME encoded message body
        body_text = body.split('\n\n')[-1][:-1].decode('base64')

        assert 'testing' in body_text
        assert '<CUSTOM MISSING VALUE>' in body_text
        assert '☃' in body_text

        assert 'Reply-To: test@example.com' in body
        assert 'To: testing@test.test' in body
        assert 'From: testfrom@test.test' in body
        assert 'Subject: Test alert for test_value :)' in body


def test_email_query_key_in_subject():
    rule = {'name': 'test alert', 'email': ['testing@test.test', 'test@test.test'],
            'type': mock_rule(), 'timestamp_field': '@timestamp', 'email_reply_to': 'test@example.com',
            'query_key': 'username'}
    with mock.patch('elastalert.alerts.SMTP') as mock_smtp:
        mock_smtp.return_value = mock.Mock()

        alert = EmailAlerter(rule)
        alert.alert([{'test_term': 'test_value', 'username': 'werbenjagermanjensen'}])

        body = mock_smtp.mock_calls[4][1][2]
        lines = body.split('\n')
        found_subject = False
        for line in lines:
            if line.startswith('Subject'):
                assert 'werbenjagermanjensen' in line
                found_subject = True
        assert found_subject


def test_opsgenie_basic():
    rule = {'name': 'testOGalert', 'opsgenie_key': 'ogkey',
            'opsgenie_account': 'genies', 'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
            'opsgenie_recipients': ['lytics'], 'type': mock_rule()}
    with mock.patch('requests.post') as mock_post:

        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00'}])
        print("mock_post: {0}".format(mock_post._mock_call_args_list))
        mcal = mock_post._mock_call_args_list
        print('mcal: {0}'.format(mcal[0]))
        assert mcal[0][0][0] == ('https://api.opsgenie.com/v2/alerts')

        assert mock_post.called

        assert mcal[0][1]['headers']['Authorization'] == 'GenieKey ogkey'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['responders'] == [{'id': 'lytics', 'type': 'user'}]
        assert mcal[0][1]['json']['source'] == 'ElastAlert'


def test_opsgenie_frequency():
    rule = {'name': 'testOGalert', 'opsgenie_key': 'ogkey',
            'opsgenie_account': 'genies', 'opsgenie_addr': 'https://api.opsgenie.com/v2/alerts',
            'opsgenie_recipients': ['lytics'], 'type': mock_rule(),
            'filter': [{'query': {'query_string': {'query': '*hihi*'}}}],
            'alert': 'opsgenie'}
    with mock.patch('requests.post') as mock_post:

        alert = OpsGenieAlerter(rule)
        alert.alert([{'@timestamp': '2014-10-31T00:00:00'}])

        assert alert.get_info()['recipients'] == rule['opsgenie_recipients']

        print("mock_post: {0}".format(mock_post._mock_call_args_list))
        mcal = mock_post._mock_call_args_list
        print('mcal: {0}'.format(mcal[0]))
        assert mcal[0][0][0] == ('https://api.opsgenie.com/v2/alerts')

        assert mock_post.called

        assert mcal[0][1]['headers']['Authorization'] == 'GenieKey ogkey'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['responders'] == [{'id': 'lytics', 'type': 'user'}]
        assert mcal[0][1]['json']['source'] == 'ElastAlert'
        assert mcal[0][1]['json']['source'] == 'ElastAlert'


def test_kibana(ea):
    rule = {'filter': [{'query': {'query_string': {'query': 'xy:z'}}}],
            'name': 'Test rule!',
            'es_host': 'test.testing',
            'es_port': 12345,
            'timeframe': datetime.timedelta(hours=1),
            'index': 'logstash-test',
            'include': ['@timestamp'],
            'timestamp_field': '@timestamp'}
    match = {'@timestamp': '2014-10-10T00:00:00'}
    with mock.patch("elastalert.elastalert.elasticsearch_client") as mock_es:
        mock_create = mock.Mock(return_value={'_id': 'ABCDEFGH'})
        mock_es_inst = mock.Mock()
        mock_es_inst.index = mock_create
        mock_es_inst.host = 'test.testing'
        mock_es_inst.port = 12345
        mock_es.return_value = mock_es_inst
        link = ea.generate_kibana_db(rule, match)

    assert 'http://test.testing:12345/_plugin/kibana/#/dashboard/temp/ABCDEFGH' == link

    # Name and index
    dashboard = json.loads(mock_create.call_args_list[0][1]['body']['dashboard'])
    assert dashboard['index']['default'] == 'logstash-test'
    assert 'Test rule!' in dashboard['title']

    # Filters and time range
    filters = dashboard['services']['filter']['list']
    assert 'xy:z' in filters['1']['query']
    assert filters['1']['type'] == 'querystring'
    time_range = filters['0']
    assert time_range['from'] == ts_add(match['@timestamp'], -rule['timeframe'])
    assert time_range['to'] == ts_add(match['@timestamp'], datetime.timedelta(minutes=10))

    # Included fields active in table
    assert dashboard['rows'][1]['panels'][0]['fields'] == ['@timestamp']


def test_alert_text_kw(ea):
    rule = ea.rules[0].copy()
    rule['alert_text'] = '{field} at {time}'
    rule['alert_text_kw'] = {
        '@timestamp': 'time',
        'field': 'field',
    }
    match = {'@timestamp': '1918-01-17', 'field': 'value'}
    alert_text = unicode(BasicMatchString(rule, match))
    body = '{field} at {@timestamp}'.format(**match)
    assert body in alert_text


def test_alert_text_global_substitution(ea):
    rule = ea.rules[0].copy()
    rule['owner'] = 'the owner from rule'
    rule['priority'] = 'priority from rule'
    rule['abc'] = 'abc from rule'
    rule['alert_text'] = 'Priority: {0}; Owner: {1}; Abc: {2}'
    rule['alert_text_args'] = ['priority', 'owner', 'abc']

    match = {
        '@timestamp': '2016-01-01',
        'field': 'field_value',
        'abc': 'abc from match',
    }

    alert_text = unicode(BasicMatchString(rule, match))
    assert 'Priority: priority from rule' in alert_text
    assert 'Owner: the owner from rule' in alert_text

    # When the key exists in both places, it will come from the match
    assert 'Abc: abc from match' in alert_text


def test_alert_text_kw_global_substitution(ea):
    rule = ea.rules[0].copy()
    rule['foo_rule'] = 'foo from rule'
    rule['owner'] = 'the owner from rule'
    rule['abc'] = 'abc from rule'
    rule['alert_text'] = 'Owner: {owner}; Foo: {foo}; Abc: {abc}'
    rule['alert_text_kw'] = {
        'owner': 'owner',
        'foo_rule': 'foo',
        'abc': 'abc',
    }

    match = {
        '@timestamp': '2016-01-01',
        'field': 'field_value',
        'abc': 'abc from match',
    }

    alert_text = unicode(BasicMatchString(rule, match))
    assert 'Owner: the owner from rule' in alert_text
    assert 'Foo: foo from rule' in alert_text

    # When the key exists in both places, it will come from the match
    assert 'Abc: abc from match' in alert_text


def test_resolving_rule_references(ea):
    rule = {
        'name': 'test_rule',
        'type': mock_rule(),
        'owner': 'the_owner',
        'priority': 2,
        'list_of_things': [
            '1',
            '$owner$',
            [
                '11',
                '$owner$',
            ],
        ],
        'nested_dict': {
            'nested_one': '1',
            'nested_owner': '$owner$',
        },
        'resolved_string_reference': '$owner$',
        'resolved_int_reference': '$priority$',
        'unresolved_reference': '$foo$',
    }
    alert = Alerter(rule)
    assert 'the_owner' == alert.rule['resolved_string_reference']
    assert 2 == alert.rule['resolved_int_reference']
    assert '$foo$' == alert.rule['unresolved_reference']
    assert 'the_owner' == alert.rule['list_of_things'][1]
    assert 'the_owner' == alert.rule['list_of_things'][2][1]
    assert 'the_owner' == alert.rule['nested_dict']['nested_owner']

