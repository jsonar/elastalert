"""
@author Joey Andres <joey@jsonar.com>
"""
import datetime

import json
import mock
import pytest

from elastalert.saved_search import SavedSearch
import elastalert.elastalert
import elastalert.util
from elastalert.util import dt_to_ts
from elastalert.util import ts_to_dt

from conftest import mock_es_client, mock_ruletype, mock_alert


saved_search_fixture = {
    "_id": "search:cda06a40-435a-11e8-b293-0f09fae50313",
    "found": True,
    "_source": {
        "_id": "search:cda06a40-435a-11e8-b293-0f09fae50313",
        "type": "search",
        "updated_at": "2018-04-19T00:24:39.794Z",
        "search": {
            "title": "ElastAlertSaveSearch 2",
            "description": "",
            "hits": 0,
            "columns": [
                "_source"
            ],
            "sort": [
                "date_field",
                "desc"
            ],
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": "{\"index\":\"555174f0-3ce1-11e8-b680-d944e4d3c256\",\"highlightAll\":true,\"version\":true,\"query\":{\"language\":\"lucene\",\"query\":\"string_field: lol\"},\"filter\":[{\"$state\":{\"store\":\"appState\"},\"meta\":{\"alias\":null,\"disabled\":false,\"index\":\"555174f0-3ce1-11e8-b680-d944e4d3c256\",\"key\":\"Server IP\",\"negate\":true,\"params\":{\"query\":\"1.0.0.0\",\"type\":\"phrase\"},\"type\":\"phrase\",\"value\":\"1.0.0.0\"},\"query\":{\"match\":{\"Server IP\":{\"query\":\"1.0.0.0\",\"type\":\"phrase\"}}}},{\"$state\":{\"store\":\"appState\"},\"meta\":{\"alias\":null,\"disabled\":false,\"index\":\"555174f0-3ce1-11e8-b680-d944e4d3c256\",\"key\":\"Server IP\",\"negate\":false,\"params\":{\"query\":\"2.0.0.0\",\"type\":\"phrase\"},\"type\":\"phrase\",\"value\":\"2.0.0.0\"},\"query\":{\"match\":{\"Server IP\":{\"query\":\"2.0.0.0\",\"type\":\"phrase\"}}}},{\"$state\":{\"store\":\"appState\"},\"meta\":{\"alias\":null,\"disabled\":false,\"index\":\"555174f0-3ce1-11e8-b680-d944e4d3c256\",\"key\":\"float_field\",\"negate\":false,\"params\":{\"gte\":0.1,\"lt\":0.5},\"type\":\"range\",\"value\":\"0.1 to 0.5\"},\"range\":{\"float_field\":{\"gte\":0.1,\"lt\":0.5}}}]}"
            }
        }
    },
    "_version": 1,
    "_index": ".kibana",
    "_type": "doc"
}

class saved_search_mock_es_client(mock_es_client):
    def __init__(self, host='es', port=14900):
        super(saved_search_mock_es_client, self).__init__(host, port)
        self.get = mock.Mock(return_value=saved_search_fixture)

@pytest.fixture
def savedSearchConfig():
    rules = [{'es_host': '',
              'es_port': 14900,
              'name': 'anytest',
              'saved_source_id': 'search:17a500b0-3e9c-11e8-86cb-550185e26ed7',
              'filter': [],
              'include': ['@timestamp'],
              'aggregation': datetime.timedelta(0),
              'realert': datetime.timedelta(0),
              'processed_hits': {},
              'timestamp_field': '@timestamp',
              'match_enhancements': [],
              'rule_file': 'blah.yaml',
              'max_query_size': 10000,
              'ts_to_dt': ts_to_dt,
              'dt_to_ts': dt_to_ts,
              '_source_enabled': True}]
    conf = {'rules_folder': 'rules',
            'run_every': datetime.timedelta(minutes=10),
            'buffer_time': datetime.timedelta(minutes=5),
            'alert_time_limit': datetime.timedelta(hours=24),
            'es_host': 'es',
            'es_port': 14900,
            'writeback_index': 'wb',
            'rules': rules,
            'max_query_size': 10000,
            'old_query_limit': datetime.timedelta(weeks=1),
            'disable_rules_on_error': False,
            'scroll_keepalive': '30s'}


    elastalert.elastalert.elasticsearch_client = saved_search_mock_es_client
    SavedSearch._get_es_client = saved_search_mock_es_client

    with mock.patch('elastalert.elastalert.get_rule_hashes'):
        with mock.patch('elastalert.elastalert.load_rules') as load_conf:
            load_conf.return_value = conf
            savedSearchConfig = elastalert.elastalert.ElastAlerter(['--pin_rules'])
    savedSearchConfig.rules[0]['type'] = mock_ruletype()
    savedSearchConfig.rules[0]['alert'] = [mock_alert()]
    savedSearchConfig.writeback_es = mock_es_client()
    savedSearchConfig.writeback_es.search.return_value = {'hits': {'hits': []}}
    savedSearchConfig.writeback_es.index.return_value = {'_id': 'ABCD'}
    savedSearchConfig.current_es = mock_es_client('', '')
    return savedSearchConfig

saved_search_fixture_without_filters = {
    "_id": "search:cda06a40-435a-11e8-b293-0f09fae50313",
    "found": True,
    "_source": {
        "_id": "search:cda06a40-435a-11e8-b293-0f09fae50313",
        "type": "search",
        "updated_at": "2018-04-19T00:47:09.453Z",
        "search": {
            "title": "ElastAlertSaveSearch 3",
            "description": "",
            "hits": 0,
            "columns": [
                "_source"
            ],
            "sort": [
                "date_field",
                "desc"
            ],
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": "{\"index\":\"555174f0-3ce1-11e8-b680-d944e4d3c256\",\"highlightAll\":true,\"version\":true,\"query\":{\"language\":\"lucene\",\"query\":\"string_field: lol\"},\"filter\":[]}"
            }
        }
    },
    "_version": 1,
    "_index": ".kibana",
    "_type": "doc"
}

@pytest.fixture
def savedSearchConfigWithoutFilters():
    rules = [{'es_host': '',
              'es_port': 14900,
              'name': 'anytest',
              'saved_source_id': 'search:17a500b0-3e9c-11e8-86cb-550185e26ed7',
              'filter': [],
              'include': ['@timestamp'],
              'aggregation': datetime.timedelta(0),
              'realert': datetime.timedelta(0),
              'processed_hits': {},
              'timestamp_field': '@timestamp',
              'match_enhancements': [],
              'rule_file': 'blah.yaml',
              'max_query_size': 10000,
              'ts_to_dt': ts_to_dt,
              'dt_to_ts': dt_to_ts,
              '_source_enabled': True}]
    conf = {'rules_folder': 'rules',
            'run_every': datetime.timedelta(minutes=10),
            'buffer_time': datetime.timedelta(minutes=5),
            'alert_time_limit': datetime.timedelta(hours=24),
            'es_host': 'es',
            'es_port': 14900,
            'writeback_index': 'wb',
            'rules': rules,
            'max_query_size': 10000,
            'old_query_limit': datetime.timedelta(weeks=1),
            'disable_rules_on_error': False,
            'scroll_keepalive': '30s'}


    elastalert.elastalert.elasticsearch_client = saved_search_without_filters_mock_es_client
    SavedSearch._get_es_client = saved_search_without_filters_mock_es_client

    with mock.patch('elastalert.elastalert.get_rule_hashes'):
        with mock.patch('elastalert.elastalert.load_rules') as load_conf:
            load_conf.return_value = conf
            savedSearchConfigWithoutFilters = elastalert.elastalert.ElastAlerter(['--pin_rules'])
    savedSearchConfigWithoutFilters.rules[0]['type'] = mock_ruletype()
    savedSearchConfigWithoutFilters.rules[0]['alert'] = [mock_alert()]
    savedSearchConfigWithoutFilters.writeback_es = mock_es_client()
    savedSearchConfigWithoutFilters.writeback_es.search.return_value = {'hits': {'hits': []}}
    savedSearchConfigWithoutFilters.writeback_es.index.return_value = {'_id': 'ABCD'}
    savedSearchConfigWithoutFilters.current_es = mock_es_client('', '')
    return savedSearchConfigWithoutFilters

class saved_search_without_filters_mock_es_client(mock_es_client):
    def __init__(self, host='es', port=14900):
        super(saved_search_without_filters_mock_es_client, self).__init__(host, port)
        self.get = mock.Mock(return_value=saved_search_fixture_without_filters)

saved_search_fixture_without_query_string = {
    "_id": "search:cda06a40-435a-11e8-b293-0f09fae50313",
    "found": True,
    "_source": {
        "_id": "search:cda06a40-435a-11e8-b293-0f09fae50313",
        "type": "search",
        "updated_at": "2018-04-19T01:04:42.579Z",
        "search": {
            "title": "ElastAlertSaveSearch 4",
            "description": "",
            "hits": 0,
            "columns": [
                "_source"
            ],
            "sort": [
                "date_field",
                "desc"
            ],
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": "{\"index\":\"555174f0-3ce1-11e8-b680-d944e4d3c256\",\"highlightAll\":true,\"version\":true,\"query\":{\"language\":\"lucene\",\"query\":\"\"},\"filter\":[{\"$state\":{\"store\":\"appState\"},\"meta\":{\"alias\":null,\"disabled\":false,\"index\":\"555174f0-3ce1-11e8-b680-d944e4d3c256\",\"key\":\"Server IP\",\"negate\":true,\"params\":{\"query\":\"1.0.0.0\",\"type\":\"phrase\"},\"type\":\"phrase\",\"value\":\"1.0.0.0\"},\"query\":{\"match\":{\"Server IP\":{\"query\":\"1.0.0.0\",\"type\":\"phrase\"}}}},{\"$state\":{\"store\":\"appState\"},\"meta\":{\"alias\":null,\"disabled\":false,\"index\":\"555174f0-3ce1-11e8-b680-d944e4d3c256\",\"key\":\"Server IP\",\"negate\":false,\"params\":{\"query\":\"2.0.0.0\",\"type\":\"phrase\"},\"type\":\"phrase\",\"value\":\"2.0.0.0\"},\"query\":{\"match\":{\"Server IP\":{\"query\":\"2.0.0.0\",\"type\":\"phrase\"}}}},{\"$state\":{\"store\":\"appState\"},\"meta\":{\"alias\":null,\"disabled\":false,\"index\":\"555174f0-3ce1-11e8-b680-d944e4d3c256\",\"key\":\"float_field\",\"negate\":false,\"params\":{\"gte\":0.1,\"lt\":0.5},\"type\":\"range\",\"value\":\"0.1 to 0.5\"},\"range\":{\"float_field\":{\"gte\":0.1,\"lt\":0.5}}}]}"
            }
        }
    },
    "_version": 1,
    "_index": ".kibana",
    "_type": "doc"
}

class saved_search_without_query_string_mock_es_client(mock_es_client):
    def __init__(self, host='es', port=14900):
        super(saved_search_without_query_string_mock_es_client, self).__init__(host, port)
        self.get = mock.Mock(return_value=saved_search_fixture_without_query_string)

@pytest.fixture
def savedSearchConfigWithoutQueryString():
    rules = [{'es_host': '',
              'es_port': 14900,
              'name': 'anytest',
              'saved_source_id': 'search:17a500b0-3e9c-11e8-86cb-550185e26ed7',
              'filter': [],
              'include': ['@timestamp'],
              'aggregation': datetime.timedelta(0),
              'realert': datetime.timedelta(0),
              'processed_hits': {},
              'timestamp_field': '@timestamp',
              'match_enhancements': [],
              'rule_file': 'blah.yaml',
              'max_query_size': 10000,
              'ts_to_dt': ts_to_dt,
              'dt_to_ts': dt_to_ts,
              '_source_enabled': True}]
    conf = {'rules_folder': 'rules',
            'run_every': datetime.timedelta(minutes=10),
            'buffer_time': datetime.timedelta(minutes=5),
            'alert_time_limit': datetime.timedelta(hours=24),
            'es_host': 'es',
            'es_port': 14900,
            'writeback_index': 'wb',
            'rules': rules,
            'max_query_size': 10000,
            'old_query_limit': datetime.timedelta(weeks=1),
            'disable_rules_on_error': False,
            'scroll_keepalive': '30s'}


    elastalert.elastalert.elasticsearch_client = saved_search_without_query_string_mock_es_client
    SavedSearch._get_es_client = saved_search_without_query_string_mock_es_client

    with mock.patch('elastalert.elastalert.get_rule_hashes'):
        with mock.patch('elastalert.elastalert.load_rules') as load_conf:
            load_conf.return_value = conf
            savedSearchConfigWithoutQueryString = elastalert.elastalert.ElastAlerter(['--pin_rules'])
    savedSearchConfigWithoutQueryString.rules[0]['type'] = mock_ruletype()
    savedSearchConfigWithoutQueryString.rules[0]['alert'] = [mock_alert()]
    savedSearchConfigWithoutQueryString.writeback_es = mock_es_client()
    savedSearchConfigWithoutQueryString.writeback_es.search.return_value = {'hits': {'hits': []}}
    savedSearchConfigWithoutQueryString.writeback_es.index.return_value = {'_id': 'ABCD'}
    savedSearchConfigWithoutQueryString.current_es = mock_es_client('', '')
    return savedSearchConfigWithoutQueryString

def test_saved_search(savedSearchConfig):
    saved_search = SavedSearch("search:17a500b0-3e9c-11e8-86cb-550185e26ed7", savedSearchConfig)

    query_doc = saved_search.get_query()

    assert 'must' in query_doc['query']['filtered']
    assert isinstance(query_doc['query']['filtered']['must'], list)
    assert 'must_not' in query_doc['query']['filtered']
    assert isinstance(query_doc['query']['filtered']['must_not'], list)

    # We use the json modules equality operator, so convert dict to json object.
    expected_must_doc = json.loads(json.dumps({
        "must": [
            {u"query_string": {u"query": u"string_field: lol"}},
            {u"query": {u"match": {u"Server IP": {u"query": u"2.0.0.0", u"type": u"phrase"}}}},
            {u"range": {u"float_field": {u"lt": 0.5, u"gte": 0.1}}}
        ]
    }))
    actual_must_doc = json.loads(json.dumps({
        "must": query_doc['query']['filtered']['must']
    }))

    assert expected_must_doc == actual_must_doc

    actual_must_not_doc = json.loads(json.dumps({
        'must_not': [
            {u"query": {u"match": {u"Server IP": {u"query": u"1.0.0.0", u"type": u"phrase"}}}}
        ]
    }))

    expected_must_not_doc = json.loads(json.dumps({
        'must_not': query_doc['query']['filtered']['must_not']
    }))

    assert expected_must_not_doc == actual_must_not_doc

def test_saved_search_with_out_filters(savedSearchConfigWithoutFilters):
    saved_search = SavedSearch("search:17a500b0-3e9c-11e8-86cb-550185e26ed7", savedSearchConfigWithoutFilters)

    query_doc = saved_search.get_query()

    assert 'must' in query_doc['query']['filtered']
    assert isinstance(query_doc['query']['filtered']['must'], list)
    assert 'must_not' in query_doc['query']['filtered']
    assert isinstance(query_doc['query']['filtered']['must_not'], list)

    # We use the json modules equality operator, so convert dict to json object.
    expected_must_doc = json.loads(json.dumps({
        "must": [
            {u"query_string": {u"query": u"string_field: lol"}}
        ]
    }))
    actual_must_doc = json.loads(json.dumps({
        "must": query_doc['query']['filtered']['must']
    }))

    assert expected_must_doc == actual_must_doc
    assert len(query_doc['query']['filtered']['must_not']) is 0

def test_saved_search_with_out_query(savedSearchConfigWithoutQueryString):
    saved_search = SavedSearch("search:17a500b0-3e9c-11e8-86cb-550185e26ed7", savedSearchConfigWithoutQueryString)

    query_doc = saved_search.get_query()

    assert 'must' in query_doc['query']['filtered']
    assert isinstance(query_doc['query']['filtered']['must'], list)
    assert 'must_not' in query_doc['query']['filtered']
    assert isinstance(query_doc['query']['filtered']['must_not'], list)

    # We use the json modules equality operator, so convert dict to json object.
    expected_must_doc = json.loads(json.dumps({
        "must": [
            {u"query": {u"match": {u"Server IP": {u"query": u"2.0.0.0", u"type": u"phrase"}}}},
            {u"range": {u"float_field": {u"lt": 0.5, u"gte": 0.1}}}
        ]
    }))
    actual_must_doc = json.loads(json.dumps({
        "must": query_doc['query']['filtered']['must']
    }))

    assert expected_must_doc == actual_must_doc

    actual_must_not_doc = json.loads(json.dumps({
        'must_not': [
            {u"query": {u"match": {u"Server IP": {u"query": u"1.0.0.0", u"type": u"phrase"}}}}
        ]
    }))

    expected_must_not_doc = json.loads(json.dumps({
        'must_not': query_doc['query']['filtered']['must_not']
    }))

    assert expected_must_not_doc == actual_must_not_doc