from .ruletypes import RuleType
from ..util import (elasticsearch_client)


class SpikeRule(RuleType):
    """ A rule that uses two sliding windows to compare relative event frequency. """
    required_options = frozenset(['timeframe', 'spike_height', 'spike_type'])

    def __init__(self, *args):
        super(SpikeRule, self).__init__(*args)
        self.ref_data = None
        self.es = elasticsearch_client(self.rules)

    def add_terms_data(self, terms):
        for time, data in list(terms.items()):
            key_dict = {item['key']: 1 for item in data}
            missing_keys = [{'key': key, 'doc_count': 0} for key in self.ref_data if not key_dict.get(key)]
            data.extend(missing_keys)
            for item in data:
                self.check_matches(item['key'], item['doc_count'], time)
        self.ref_data = None

    def add_count_data(self, data):
        """ Add count data to the rule. Data should be of the form {ts: count}. """
        for time, count in list(data.items()):
            self.check_matches(None, count, time)
        self.ref_data = None

    def check_matches(self, key, count, time):
        ref_threshold = self.rules['threshold_ref']
        match_treshold = self.rules['threshold_cur']
        spike_height = self.rules['spike_height']
        spike_type = self.rules['spike_type']
        key_matches = False
        if count >= match_treshold:
            ref_val = self.ref_data.get(key, 0)
            if ref_val >= ref_threshold:
                if spike_type in ['up', 'both']:
                    if count >= ref_val * spike_height:
                        key_matches = True
                if spike_type in ['down', 'both']:
                    if count * spike_height <= ref_val:
                        key_matches = True
                if key_matches:
                    match = {'timestamp_field': self.rules['timestamp_field'], self.rules['timestamp_field']: time,
                             'spike_count': count, 'reference_count': ref_val, 'key': key}
                    self.add_match(match)

    def query_reference_window(self, query, rule, index):
        if self.rules.get('use_terms_query'):
            self.ref_data = self.es.search(index=index, body=query, size=0,
                                           ignore_unavailable=True)
            self.ref_data = self.ref_data['aggregations']['counts']['buckets']
            self.ref_data = {item['key']: item['doc_count'] for item in self.ref_data}
        else:
            self.ref_data = self.es.count(index=index, body=query, ignore_unavailable=True)
            self.ref_data = {None: self.ref_data['count']}
