import datetime
import configparser

from elastalert.constants import DISPATCHER_CONF, NEW_TERM_DB, NEW_TERM_COLL
from elastalert.rule_type_definitions.ruletypes import RuleType
from elastalert.util import (elasticsearch_client, get_sonar_connection)


class NewTermsRule(RuleType):
    """ Alerts on a new value in a list of fields. """

    def __init__(self, rule, args=None):
        super(NewTermsRule, self).__init__(rule, args)
        self.rules['use_run_every_query_size'] = True
        self.rules['realert'] = datetime.timedelta(0)
        self.agg_key = None
        self.rules['aggregation_query_element'] = self.generate_aggregation_query(self.rules['query_key'])

        conf = configparser.ConfigParser()
        conf.read(DISPATCHER_CONF)
        uri = conf.get('dispatch', 'sonarw_uri')

        self.sonar_con = get_sonar_connection(uri)
        self.terms_collection = self.sonar_con[NEW_TERM_DB][NEW_TERM_COLL]
        self.initialized = True

        if not self.terms_collection.find_one({'rule': self.rules['name']}):
            self.terms_collection.insert_one({'rule': self.rules['name']})

        self.initialized = False  # TODO should happen each restart? If not move this line into if

        self.es = elasticsearch_client(self.rules)

    def generate_aggregation_query(self, key):
        self.agg_key = key
        agg_query = {'{}'.format(key): {'terms': {'field': key}}}
        return agg_query

    def add_aggregation_data(self, payload):
        for timestamp, payload_data in list(payload.items()):
            self.check_matches(timestamp, payload_data)

    def check_matches(self, timestamp, aggregation_data, add_match=True):
        terms_list = [item['key'] for item in aggregation_data['bucket_aggs']['buckets']]

        pipe = [{'$match': {'rule': self.rules['name']}},
                {'$group': {'_id': '$rule', 'vals': {'$addToSet': "$term"}}},
                {'$project': {
                    'new_terms': {'$filter': {'input': terms_list, 'as': 'value', 'cond': {'$not': {
                        '$setIsSubset': [['$$value'], '$vals']}
                    }}}}}]

        try:
            new_terms = list(self.terms_collection.aggregate(pipe))[0]['new_terms']
        except IndexError:
            new_terms = []

        if new_terms:
            update = self.terms_collection.initialize_ordered_bulk_op()

            for term in new_terms:
                if add_match:
                    match = {'timestamp_field': self.rules['timestamp_field'], self.rules['timestamp_field']: timestamp,
                             'watched_field': self.agg_key, 'watched_field_value': term}
                    self.add_match(match)
                # add the new terms to the collection of known terms
                update.insert({'rule': self.rules['name'], 'term': term})

            update.execute()

    def check_initialization(self):
        if self.initialized:
            return True
        else:
            self.initialized = True
            return False

    def get_last_data_time(self, startime):
        start_window = startime - datetime.timedelta(**self.rules.get('terms_window_size', {'days': 30}))
        return start_window

    def run_initialization(self, query, rule, index):

            aggregation_data = self.es.search(index=index, size=0,
                                                          body=query, ignore_unavailable=True)
            self.check_matches(datetime.datetime.utcnow(), aggregation_data['aggregations'], add_match=False)

