"""
@author Joey Andres <joey@jsonar.com>
"""

import datetime

import json
import mock
import pytest

from elastalert.saved_visualization import SavedVisualization
import elastalert.elastalert
import elastalert.util
from elastalert.util import dt_to_ts
from elastalert.util import ts_to_dt

from conftest import mock_es_client, mock_ruletype, mock_alert


saved_visualization_fixture = {
    "_id": "visualization:4c6af1b0-3da7-11e8-b895-d1a4c996486c",
    "found": True,
    "_source": {
        "_id": "visualization:4c6af1b0-3da7-11e8-b895-d1a4c996486c",
        "type": "visualization",
        "updated_at": "2018-04-20T16:37:46.454Z",
        "visualization": {
            "title": "Pie Test 6",
            "visState": "{\"aggs\":[{\"enabled\":true,\"id\":\"1\",\"params\":{},\"schema\":\"metric\",\"type\":\"count\"},{\"enabled\":true,\"id\":\"2\",\"params\":{\"field\":\"string_field\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\",\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"size\":5},\"schema\":\"segment\",\"type\":\"terms\"},{\"enabled\":true,\"id\":\"3\",\"params\":{\"extended_bounds\":{},\"field\":\"float_field\",\"interval\":0.1},\"schema\":\"segment\",\"type\":\"histogram\"}],\"aggs_dsl\":{\"2\":{\"aggs\":{\"3\":{\"histogram\":{\"field\":\"float_field\",\"interval\":0.1,\"min_doc_count\":1}}},\"terms\":{\"field\":\"string_field\",\"order\":{\"_count\":\"desc\"},\"size\":5}}},\"params\":{\"addLegend\":true,\"addTooltip\":true,\"isDonut\":true,\"labels\":{\"last_level\":true,\"show\":false,\"truncate\":100,\"values\":true},\"legendPosition\":\"right\",\"type\":\"pie\"},\"title\":\"Pie Test 6\",\"type\":\"pie\"}",
            "uiStateJSON": "{\"spy\":{\"mode\":{\"name\":\"table\"}}}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": "{\"index\":\"555174f0-3ce1-11e8-b680-d944e4d3c256\",\"filter\":[],\"query\":{\"language\":\"lucene\",\"query\":\"\"}}"
            }
        }
    },
    "_version": 1,
    "_index": ".kibana",
    "_type": "doc"
}


class saved_visualization_mock_es_client(mock_es_client):
    def __init__(self, host='es', port=14900):
        super(saved_visualization_mock_es_client, self).__init__(host, port)
        self.get = mock.Mock(return_value=saved_visualization_fixture)

@pytest.fixture
def savedVisConfig():
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


    elastalert.elastalert.elasticsearch_client = saved_visualization_mock_es_client
    SavedVisualization._get_es_client = saved_visualization_mock_es_client

    with mock.patch('elastalert.elastalert.get_rule_hashes'):
        with mock.patch('elastalert.elastalert.load_rules') as load_conf:
            load_conf.return_value = conf
            savedVisConfig = elastalert.elastalert.ElastAlerter(['--pin_rules'])
    savedVisConfig.rules[0]['type'] = mock_ruletype()
    savedVisConfig.rules[0]['alert'] = [mock_alert()]
    savedVisConfig.writeback_es = mock_es_client()
    savedVisConfig.writeback_es.search.return_value = {'hits': {'hits': []}}
    savedVisConfig.writeback_es.index.return_value = {'_id': 'ABCD'}
    savedVisConfig.current_es = mock_es_client('', '')
    return savedVisConfig


def test_visualization_search_get_query(savedVisConfig):
    saved_vis = SavedVisualization("search:17a500b0-3e9c-11e8-86cb-550185e26ed7", savedVisConfig)

    query_doc = saved_vis.get_query()

    assert 'must' in query_doc['query']['filtered']
    assert isinstance(query_doc['query']['filtered']['must'], list)
    assert 'must_not' in query_doc['query']['filtered']
    assert isinstance(query_doc['query']['filtered']['must_not'], list)

    # We use the json modules equality operator, so convert dict to json object.
    expected_must_doc = json.loads(json.dumps({
        "must": []
    }))
    actual_must_doc = json.loads(json.dumps({
        "must": query_doc['query']['filtered']['must']
    }))

    assert expected_must_doc == actual_must_doc

    actual_must_not_doc = json.loads(json.dumps({
        'must_not': []
    }))

    expected_must_not_doc = json.loads(json.dumps({
        'must_not': query_doc['query']['filtered']['must_not']
    }))

    assert expected_must_not_doc == actual_must_not_doc


def test_visualization_search_get_aggs(savedVisConfig):
    saved_vis = SavedVisualization("search:17a500b0-3e9c-11e8-86cb-550185e26ed7", savedVisConfig)
    expected_aggs_doc = json.loads(json.dumps({
        "2": {
            "terms": {
                "field": "string_field",
                "size": 5,
                "order": {
                    "_count": "desc"
                }
            },
            "aggs": {
                "3": {
                    "histogram": {
                        "field": "float_field",
                        "interval": 0.1,
                        "min_doc_count": 1
                    }
                }
            }
        }
    }))

    assert expected_aggs_doc == saved_vis.get_aggs()