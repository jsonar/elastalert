"""
@author Joey Andres <joey@jsonar.com>
"""
import ast
import json
import re
from copy import deepcopy

from util import elastalert_logger
from util import elasticsearch_client
from util import get_filter_doc


class SavedSource:
    """
    Represents a Kibana Save Search object.
    """

    def __init__(self, id, conf):
        """
        :param id: SavedSearch id in elasticsearch's .kibana collection.
        :param conf: Elasticsearch configuration.
        """
        self.id = id
        self.conf = conf
        self.es = self._get_es_client(conf)
        self.raw_data = self.es.get(index='.kibana', doc_type='doc', id=self.id)
        self.scripted_fields = self.get_scripted_fields()
        # self.scripted_fields = {}

    def get_scripted_fields(self):
        scripted_fields = {}
        try:
            saved_object_index_pattern = self.es.get(
                index='.kibana', doc_type='doc', id='index-pattern:{}'.format(self.get_index_id()))

            scripts = saved_object_index_pattern['_source']['index-pattern']['fields']
            scripts = re.sub(r'\"{', '{', scripts)
            scripts = re.sub(r'}\"', '}', scripts)
            scripts = re.sub(r'\\\"', r'"', scripts)
            scripts = re.sub(r'true', 'True', scripts)
            scripts = re.sub(r'false', 'False', scripts)
            scripts = ast.literal_eval(scripts)
            for item in scripts:
                if item.get('scripted'):
                    script = json.dumps(item['script'])
                    scripted_fields[item['name']] = {"script": {"inline": script, "lang": "sonar"}}

        except Exception as e:
            elastalert_logger.exception('Failed to get scripted fields. Error {}'.format(e))

        return scripted_fields

    def _get_type(self):
        pass

    @staticmethod
    def _get_es_client(conf):
        """
        Created for testing reasons. Making it easier for us to mock this method.
        :param conf:
        :return:
        """
        return elasticsearch_client(conf)

    def _get_search_source(self):
        return json.loads(self.raw_data['_source'][self._get_type()]['kibanaSavedObjectMeta']['searchSourceJSON'])

    def get_index(self):
        """
        :return: elasticsearch index associated with the Saved Search
        """
        saved_object_index_pattern = self.es.get(
            index='.kibana', doc_type='doc', id='index-pattern:{}'.format(self.get_index_id()))

        return saved_object_index_pattern['_source']['index-pattern']['title']

    def get_index_id(self):
        """
        :return: elasticsearch index id associated with the Saved Search.
        """
        return self._get_search_source()['index']

    def _get_filter(self):
        """
        :return: elasticsearch filter object of the Saved Search.
        """
        raw_filters = deepcopy(self._get_search_source()['filter'])

        return get_filter_doc(raw_filters)

    def _get_query(self):
        """
        :return: elasticsearch query associated with the Saved Search.
        """
        raw_query = deepcopy(self._get_search_source()['query'])
        if 'query' not in raw_query or len(raw_query['query']) is 0:
            return None

        del raw_query['language']   # Clean up unnecessary fields.
        return {'query_string': raw_query}

    def get_query(self):
        """
        I used https://discuss.elastic.co/t/constructing-a-request-using-kibana-saved-search-information/91147/4 as a
        reference.
        :return: Query object
        """
        must_docs = []
        must_not_docs = []

        filter_doc = self._get_filter()

        if self._get_query() is not None:
            must_docs.append(self._get_query())
        must_docs = must_docs + filter_doc['must']

        must_not_docs = must_not_docs + filter_doc['must_not']


        return {
            'query': {
                'filtered': {
                    'must': must_docs,
                    'must_not': must_not_docs
                }
            },
            'script_fields': self.scripted_fields
        }  # TODO append scripted fields

    def get_timestamp_field(self):
        """
        Retrieves the timestamp field of the saved source.
        :return: Name of the timestamp field of the saved source if any. None otherwise.
        """
        index_pattern_doc = self.es.get(index='.kibana', doc_type='doc', id='index-pattern:{0}'.format(self.get_index_id()))
        return index_pattern_doc['_source']['index-pattern']['timeFieldName']
