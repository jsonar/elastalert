import datetime
import ConfigParser

from elastalert.constants import DISPATCHER_CONF, NEW_TERM_DB, NEW_TERM_COLL
from elastalert.rule_type_definitions.ruletypes import RuleType
from elastalert.util import (add_raw_postfix, EAException, elastalert_logger, elasticsearch_client, format_index, get_index,
lookup_es_key, ts_to_dt, ts_now, get_sonar_connection)


class NewTermsRule(RuleType):
    """ Alerts on a new value in a list of fields. """

    def __init__(self, rule, args=None):
        super(NewTermsRule, self).__init__(rule, args)
        self.rules['use_run_every_query_size'] = True
        self.rules['realert'] = datetime.timedelta(0)
        self.agg_key = None
        self.rules['aggregation_query_element'] = self.generate_aggregation_query(self.rules['query_key'])

        conf = ConfigParser.ConfigParser()
        conf.read(DISPATCHER_CONF)
        uri = conf.get('dispatch', 'sonarw_uri')

        self.sonar_con = get_sonar_connection(uri)
        self.terms_collection = self.sonar_con[NEW_TERM_DB][NEW_TERM_COLL]
        elastalert_logger.warning('___________init New Terms RUle_______________')

        self.terms_collection.insert_one({'rule': self.rules['name'],
                                          'term': 'lmrm__SONAR_ALERT_RULE_ACTIVE__',
                                          'time': datetime.datetime.utcnow()})

        self.es = elasticsearch_client(self.rules)

        self.initialized = False

    def generate_aggregation_query(self, key):
        self.agg_key = key
        agg_query = {'{}'.format(key): {'terms': {'field': key}}}
        return agg_query

    def add_aggregation_data(self, payload):
        for timestamp, payload_data in payload.iteritems():
            self.check_matches(timestamp, payload_data)

    def check_matches(self, timestamp, aggregation_data):
        terms_list = [item['key'] for item in aggregation_data['bucket_aggs']['buckets']]
        elastalert_logger.warning('terms list = {}'.format(terms_list))
        end_window = self.rules['starttime']
        start_window = self.rules['starttime'] - datetime.timedelta(**self.rules.get('terms_window_size', {'days': 30}))
        elastalert_logger.warning('startwindow: {}  endwindow: {}'.format(start_window, end_window))
        pipe = [{'$match': {'$and': [{'rule': self.rules['name']},
                                     {'time': {'$lte': end_window}},
                                     {'time': {'$gte': start_window}}]}},
                {'$group': {'_id': '$rule', 'vals': {'$addToSet': "$term"}}},
                {'$project': {
                    'new_terms': {'$filter': {'input': terms_list, 'as': 'value', 'cond': {'$not': {
                        '$setIsSubset': [['$$value'], '$vals']}
                    }}}}}]

        new_terms = list(self.terms_collection.aggregate(pipe))[0]['new_terms']
        elastalert_logger.warning('new_terms = {}'.format(new_terms))
        time_now = end_window + datetime.timedelta(**self.rules.get('terms_window_size', {'days': 30}))/2
        elastalert_logger.warning(time_now)

        update = self.terms_collection.initialize_ordered_bulk_op()

        for term in new_terms:
            match = {'timestamp_field': self.rules['timestamp_field'], self.rules['timestamp_field']: timestamp,
                     'watched_field': self.agg_key, 'watched_field_value': term}
            self.add_match(match)
            # add the new terms to the collection of known terms
            update.insert({'rule': self.rules['name'], 'term': term, 'time': time_now})

        for term in terms_list:
            update.find({'rule': self.rules['name'], 'term': term}).update({'$set': {'time': time_now}})

        update.execute()

        self.clean_sonar_collection(start_window)

    def check_initialization(self, query, rule, timestamp_field, starttime, endtime, index):
        if self.initialized == False:
            start_window = self.rules['starttime'] - datetime.timedelta(**self.rules.get('terms_window_size', {'days': 30}))
            self.terms_collection.remove({'rule': self.rules['name'], 'time': {'$lt': start_window}})

            step = datetime.timedelta(**self.rules.get('window_step_size', {'days': 1}))
            elastalert_logger.warning('query = {}'.format(query))
            query['aggs'] = self.rules['aggregation_query_element']

            # TODO break up run into smaller segments

            query['query']['bool']['must'].insert(0, {'range': {self.rules[timestamp_field]: {'gt': start_window,
                                                                                 'lte': starttime}}})
            aggregation_data = self.es.search(index=index, doc_type=rule.get('doc_type'), size=0,
                                                          body=query, ignore_unavailable=True)
            terms = [item['key'] for item in aggregation_data['hits']['aggregations'][self.rules['query_key']['buckets']]]
            elastalert_logger.warning('initial_response = {}'.format(terms))



    '''
    def extend_query(self, base_query):
        """nests the query inside another boolean query to only get documents on the blacklist"""
        inner_query = base_query['query']
        query = {"query": {"bool": {"must": [inner_query, {"bool": {"must_not":{ 'terms':{'aggs': }}}}]}}}
        return query

    def check_matches(self, timestamp, aggregation_data):
        for item in aggregation_data['{}'.format(self.agg_key)]['buckets']:
            match = {'timestamp_field': self.rules['timestamp_field'], self.rules['timestamp_field']: timestamp,
                     'watched_field': self.agg_key, 'watched_field_value': item['key'], "doc_count": item['doc_count']}
            self.add_match(match)
    '''

    def clean_sonar_collection(self, start_window):
        self.terms_collection.remove({'rule': self.rules['name'], 'time': {'$lt': start_window}})
