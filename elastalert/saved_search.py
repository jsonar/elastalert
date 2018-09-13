"""
@author Joey Andres <joey@jsonar.com>
"""
from saved_source import SavedSource


class SavedSearchInvalidIdError(Exception):
    def __init__(self,
                 message="SavedSearh is given an invalid id. "
                         "Ensure kibana.doc contains a document with the given id of type='search'."):
        super(SavedSearchInvalidIdError, self).__init__(message)


class SavedSearch(SavedSource):
    """
    Represents a Kibana Save Search object.
    """

    def __init__(self, id, conf):
        """
        :param id: SavedSearch id in elasticsearch's .kibana collection.
        :param conf: Elasticsearch configuration.
        """
        SavedSource.__init__(self, id, conf)

        if not self._is_saved_search(self.raw_data):
            raise SavedSearchInvalidIdError()

    def _get_type(self):
        return 'search'

    @staticmethod
    def _is_saved_search(es_doc):
        return es_doc['_source']['type'] == 'search'
