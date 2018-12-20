from datetime import timedelta
from elastalert.rule_type_definitions.ruletypes import RuleType
from elastalert.util import EAException


class CardinalityRule(RuleType):
    """ A rule that matches if cardinality of a field is above or below a threshold within a timeframe """
    required_options = frozenset(['timeframe', 'cardinality_field'])

    def __init__(self, *args):
        super(CardinalityRule, self).__init__(*args)
        if 'max_cardinality' not in self.rules and 'min_cardinality' not in self.rules:
            raise EAException("CardinalityRule must have one of either max_cardinality or min_cardinality")
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.cardinality_field = self.rules['cardinality_field']
        self.cardinality_cache = {}
        self.first_event = {}
        self.timeframe = self.rules['timeframe']
        self.rules['use_run_every_query_size'] = True
        self.rules['realert'] = timedelta(0)
        self.rules['aggregation_query_element'] = self.generate_aggregation_query()

    def generate_aggregation_query(self):
        qk = self.rules.get('query_key')

        if qk:

            agg_query = {'qk_agg': {'terms': {'field': qk},
                                    "aggs": {'unique_values': {'cardinality': {'field': self.cardinality_field}}}}
                         }
        else:
            agg_query = {'unique_values': {'cardinality': {'field': self.cardinality_field}}}

        return agg_query

    def add_aggregation_data(self, payload):
        for timestamp, payload_data in payload.iteritems():
            self.check_matches(timestamp, payload_data)

    def check_matches(self, timestamp, aggregation_data):
        if self.rules.get('query_key'):
            for item in aggregation_data['bucket_aggs']['buckets']:
                cardinality = int(item['qk_agg']['buckets'][0]['unique_values']['value'])
                if not (self.rules.get('max_cardinality', float('inf')) >= cardinality >= self.rules.get('min_cardinality', -1)):
                    key_value = item['qk_agg']['buckets'][0]['key']
                    match = {self.rules['timestamp_field']: timestamp, "key": key_value, "cardinality": cardinality}
                    self.add_match(match)
        else:
            if aggregation_data['unique_values']['value']:
                cardinality = int(aggregation_data['unique_values']['value'])
            else:
                cardinality = 0
            if not (self.rules.get('max_cardinality', float('inf')) >= cardinality >= self.rules.get('min_cardinality', -1)):
                match = {self.rules['timestamp_field']: timestamp, "cardinality": cardinality}
                self.add_match(match)

