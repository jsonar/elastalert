from datetime import timedelta

from elasticsearch.exceptions import ElasticsearchException

from .ruletypes import RuleType
from ..util import elastalert_logger


class CompareRule(RuleType):
    """ A base class for matching a specific term by passing it to a compare function """
    required_options = frozenset(['compound_compare_key'])

    def __init__(self, rules, args=None):
        super(CompareRule, self).__init__(rules, args=None)
        self.rules['use_run_every_query_size'] = True
        self.rules['realert'] = timedelta(0)
        self.agg_key = None

    def expand_entries(self, list_type):
        """ Expand entries specified in files using the '!file' directive, if there are
        any, then add everything to a set.
        """
        entries_set = set()
        for entry in self.rules[list_type]:
            if entry.startswith("!file"):  # - "!file /path/to/list"
                filename = entry.split()[1]
                with open(filename, 'r') as f:
                    for line in f:
                        entries_set.add(line.rstrip())
            else:
                entries_set.add(entry)
        self.rules[list_type] = entries_set

    def generate_aggregation_query(self, key):
        self.agg_key = key
        agg_query = {'{}'.format(key): {'terms': {'field': key}}}
        return agg_query

    def generate_item_clauses(self, value_list, field):
        item_clauses = []
        for item in value_list:
            clause = {"term": {field: item}}
            item_clauses.append(clause)

            if item.upper() == 'NULL':
                clause = {"bool": {"must_not": {"exists": {"field": field}}}}
                item_clauses.append(clause)
            elif item == '""':
                clause = {"term": {field: ""}}
                item_clauses.append(clause)

        if self.rules.get('ignore_null'):
                clause = {"bool": {"must_not": {"exists": {"field": field}}}}
                item_clauses.append(clause)

        return item_clauses

    def compare(self, event):
        """ An event is a match if this returns true """
        raise NotImplementedError()

    def add_data(self, data):
        # If compare returns true, add it as a match
        for event in data:
            if self.compare(event):
                self.add_match(event)

    def add_aggregation_data(self, payload):
        for timestamp, payload_data in list(payload.items()):
            self.check_matches(timestamp, payload_data)

    def check_matches(self, timestamp, aggregation_data):
        for item in aggregation_data['{}'.format(self.agg_key)]['buckets']:
            match = {'timestamp_field': self.rules['timestamp_field'], self.rules['timestamp_field']: timestamp,
                     'watched_field': self.agg_key, 'watched_field_value': item['key'], "doc_count": item['doc_count']}
            self.add_match(match)


class BlacklistRule(CompareRule):
    """ A CompareRule where the compare function checks a given key against a blacklist """
    required_options = frozenset(['compare_key', 'blacklist'])

    def __init__(self, rules, args=None):
        super(BlacklistRule, self).__init__(rules, args=None)
        self.expand_entries('blacklist')

        self.item_clauses = self.generate_item_clauses(self.rules['blacklist'], self.rules['compare_key'])

        self.rules['aggregation_query_element'] = self.generate_aggregation_query(self.rules['compare_key'])

    def compare(self, event):
        return True

    def extend_query(self, base_query):
        """nests the query inside another boolean query to only get documents on the blacklist"""
        inner_query = base_query['query']
        query = {"query": {"bool": {"must": [inner_query, {"bool": {"should": self.item_clauses}}]}},
                 'script_fields': base_query['script_fields']}
        return query


class WhitelistRule(CompareRule):
    """ A CompareRule where the compare function checks a given term against a whitelist """
    required_options = frozenset(['compare_key', 'whitelist', 'ignore_null'])

    def __init__(self, rules, args=None):
        super(WhitelistRule, self).__init__(rules, args=None)
        self.expand_entries('whitelist')
        self.item_clauses = self.generate_item_clauses(self.rules['whitelist'], self.rules['compare_key'])
        # if self.rules['bundle_alerts']:
        self.rules['aggregation_query_element'] = self.generate_aggregation_query(self.rules['compare_key'])

    def compare(self, event):
        return True

    def extend_query(self, base_query):
        """nests the query inside another boolean query to only get documents on the blacklist"""
        inner_query = base_query['query']
        query = {"query": {"bool": {"must": [inner_query, {"bool": {"must_not": self.item_clauses}}]}},
                 'script_fields': base_query['script_fields']}
        return query


class ChangeRule(CompareRule):
    """ A rule that will store values for a certain term and match if those values change """
    required_options = frozenset(['query_key', 'compound_compare_key', 'ignore_null'])
    change_map = {}
    occurrence_time = {}

    def __init__(self,rules, args=None):
        super(ChangeRule, self).__init__(rules, args=None)
        # self.expand_entries('compound_compare_key')
        self.rules['aggregation_query_element'] = self.generate_aggregation_query(self.rules['query_key'])

    def compare(self, event):
        return True

    def extend_query(self, current_es, query, rule, timestamp_field, starttime, endtime, index):

        query_key_values = self.get_query_keys_in_timewindow(current_es, query, rule, timestamp_field,
                                                            starttime, endtime, index)
        if query_key_values:
            resp = self.get_old_query_key_values(current_es, query_key_values, rule, timestamp_field,
                                                 starttime, endtime, index)
            if resp:
                item_clauses = self.generate_item_clauses(resp, rule)
                # Build the main query from the generated clauses
                inner_query = query['query']
                query = {"query": {"bool": {"must": [inner_query, {"bool": {"must_not": item_clauses}}]}},
                         'script_fields': query['script_fields']}

                return query

    def get_query_keys_in_timewindow(self, current_es, query, rule, timestamp_field, starttime, endtime, index):
        # Find what values of query key are inside the queried time range
        try:
            #if rule.get('timeframe'):
            query_key_terms_query = {'query': {'bool': {'must': [
                {'range': {timestamp_field: {'gt': starttime, 'lte': endtime}}}]}},
                "aggs": {"key_values": {"terms": {"field": rule['query_key']}}}}
            query_key_values = current_es.search(index=index, size=0,
                                                          body=query_key_terms_query, ignore_unavailable=True)
            return query_key_values

        except ElasticsearchException as e:
            # Elasticsearch sometimes gives us GIGANTIC error messages
            # (so big that they will fill the entire terminal buffer)
            if len(str(e)) > 1024:
                e = str(e)[:1024] + '... (%d characters removed)' % (len(str(e)) - 1024)

            elastalert_logger.error('Error getting query keys in timewindow for change rule: %s' % (e),
                                    {'rule': rule['name'], 'query': query})

    def get_old_query_key_values(self, current_es, query_key_values, rule, timestamp_field, starttime, endtime, index):
        # Get the oldest value in the time range for each compare key for each query key
        request = []
        req_head = {'index': index, 'type': rule.get('doc_type')}
        if query_key_values['aggregations']['key_values']['buckets']:
            if rule.get('timeframe'):
                time_clause = {'range': {timestamp_field: {'gt': starttime - rule['timeframe'], 'lte': endtime}}}
            else:
                time_clause = {'range': {timestamp_field: {'lte': starttime}}}
            for field in rule['compound_compare_key']:
                for key_field in query_key_values['aggregations']['key_values']['buckets']:
                    key = key_field['key']

                    req_body = {
                        'sort': [{timestamp_field: {'order': 'desc'}}],
                        'query': {"bool": {"must": [{'term': {rule['query_key']: key}},
                                                    {'exists': {'field': field}},
                                                    time_clause]}},
                        'size': 1,
                        'script_fields': {
                            "compare_key_field": {"script": {"source": "'{}'".format(field), "lang": "sonar"}}
                        }
                    }
                    request.extend([req_head, req_body])
            try:
                resp = current_es.msearch(body=request)
            except ElasticsearchException as e:
                # Elasticsearch sometimes gives us GIGANTIC error messages
                # (so big that they will fill the entire terminal buffer)
                if len(str(e)) > 1024:
                    e = str(e)[:1024] + '... (%d characters removed)' % (len(str(e)) - 1024)

                elastalert_logger.error('Error getting query keys in timewindow for change rule: %s' % (e),
                                        {'rule': rule['name'], 'query': request})
                return None
        else:
            resp = {'responses': []}

        return resp

    def generate_item_clauses(self, resp, rule):
        # Generate clauses that will match with any allowed values
        item_clauses = []
        for item in resp['responses']:
            if item['hits']['hits']:
                query_key_value = item['hits']['hits'][0]['_source'].get(rule['query_key'])
                compare_key = item['hits']['hits'][0]['_source'].get('compare_key_field')
                compare_key_value = item['hits']['hits'][0]['_source'].get(compare_key)

                if not rule.get('ignore _null'):
                    clause = {"bool": {"must": [
                        {"term": {rule['query_key']: query_key_value}},
                        {"term": {compare_key: compare_key_value}}
                                               ]}}
                else:  # Add the extra condition to ignore missing compare fields is ignore null is set
                    clause = {"bool": {"must": [
                        {"bool": {"should": [{"bool": {"must_not": [{"exists": {"field": compare_key}}]}},
                                  {"term": {compare_key: compare_key_value}}]}},
                        {"term": {rule['query_key']: query_key_value}}
                                               ]}}
                item_clauses.append(clause)

        return item_clauses
