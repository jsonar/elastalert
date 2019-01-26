from elastalert.rule_type_definitions.ruletypes import RuleType, EventWindow
from elastalert.util import new_get_event_ts, EAException, hashable, lookup_es_key, elastalert_logger, pretty_ts
from elastalert.util import (elasticsearch_client, get_sonar_connection)


class SpikeRule(RuleType):
    """ A rule that uses two sliding windows to compare relative event frequency. """
    required_options = frozenset(['timeframe', 'spike_height', 'spike_type'])

    def __init__(self, *args):
        super(SpikeRule, self).__init__(*args)
        elastalert_logger.warning('______________Spike_rule_init_________________')
        if self.rules.get(['query_key']):
            self.rules['use_count_query'] = False
            self.rules['aggregation_query_element'] = True
        else:
            self.rules['use_count_query'] = True
            self.rules['aggregation_query_element'] = False

        self.es = elasticsearch_client(self.rules)

    def generate_aggregation_query(self):
        agg_query = {'{}'.format(self.rules['query_key']): {'terms': {'field': self.rules['query_key']}}}
        return agg_query


'''
    def add_count_data(self, data):
        """ Add count data to the rule. Data should be of the form {ts: count}. """
        elastalert_logger.warning('adding count data {}'.format(data))
        if len(data) > 1:
            raise EAException('add_count_data can only accept one count at a time')
        for ts, count in data.iteritems():
            self.handle_event({self.ts_field: ts}, count, 'all')

    def add_aggregation_data(self, payload):
        elastalert_logger.warning('adding agg data {}'.format(payload))
        for timestamp, payload_data in payload.iteritems():
            self.check_matches(timestamp, payload_data)

    def check_matches(self):
        pass
        # TODO check that reference is above ref threshold
        # TODO check that match is above match threshold
        # TODO if spike up check that match > 3xreference
        # TODO if spike down check that matchX3 < reference

    def query_reference_window(self):
        pass
'''
