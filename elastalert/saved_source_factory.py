"""
@author Joey Andres <joey@jsonar.com>
"""
import json
import datetime
from util import elasticsearch_client
from saved_search import SavedSearch
from saved_visualization import SavedVisualization


class SavedSourceFactory:
    def __init__(self, conf):
        """
        :param conf: Elasticsearch configuration.
        """
        self.conf = conf
        self.es = self._get_es_client(conf)

    def create(self, saved_source_id):
        """
        Factory method for creating SavedSource instance.
        :param saved_source_id: Id of the saved source in the kibana.doc index.
        :return: SavedSource instance.
        """
        raw_saved_source_data = self.es.get(index='.kibana', doc_type='doc', id=saved_source_id)

        saved_source_type = raw_saved_source_data['_source']['type']

        if saved_source_type == 'search':
            return SavedSearch(saved_source_id, self.conf)
        elif saved_source_type == 'visualization':
            return SavedVisualization(saved_source_id, self.conf)
        else:
            # TODO: Raise some exception.
            pass

    @staticmethod
    def _get_es_client(conf):
        """
        Created for testing reasons. Making it easier for us to mock this method.
        :param conf:
        :return:
        """
        return elasticsearch_client(conf)

# TODO(joey): Sandbox area. Delete when done with SES-208
# conf = {
#     'rules_folder': 'rules',
#     'run_every': datetime.timedelta(minutes=10),
#     'buffer_time': datetime.timedelta(minutes=5),
#     'alert_time_limit': datetime.timedelta(hours=24),
#     'es_host': 'localhost',
#     'es_port': 8088,
#     'writeback_index': 'wb',
#     'max_query_size': 10000,
#     'old_query_limit': datetime.timedelta(weeks=1),
#     'disable_rules_on_error': False,
#     'scroll_keepalive': '30s'
# }
# id = "visualization:4c6af1b0-3da7-11e8-b895-d1a4c996486c"
# saved_search = SavedSourceFactory(conf).create(id)
# print saved_search.get_timestamp_field()
# #print json.dumps(saved_search.get_aggs())