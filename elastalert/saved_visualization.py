"""
@author Joey Andres <joey@jsonar.com>
"""
import json

from saved_source import SavedSource


class SavedVisualizationInvalidIdError(Exception):
    def __init__(self,
                 message="SavedVisualization is given an invalid id. "
                         "Ensure kibana.doc contains a document with the given id of type='visualization'."):
        super(SavedVisualizationInvalidIdError, self).__init__(message)


class SavedVisualizationInvalidVisState(Exception):
    def __init__(self,
                 message="SavedVisualization is given an invalid visState. "
                         "Ensure sonark is running the lastest version."):
        super(SavedVisualizationInvalidIdError, self).__init__(message)


class SavedVisualization(SavedSource):
    """
    Represents a Kibana Saved visualization object.
    """

    def __init__(self, id, conf):
        """
        :param id: SavedVisualization id in elasticsearch's .kibana collection.
        :param conf: Elasticsearch configuration.
        """
        SavedSource.__init__(self, id, conf)

        if not self._is_saved_visualization(self.raw_data):
            raise SavedVisualizationInvalidIdError()

    def _get_type(self):
        return 'visualization'

    @staticmethod
    def _is_saved_visualization(es_doc):
        return es_doc['_source']['type'] == 'visualization'

    def get_aggs(self):
        # Note that visualization.visState.aggs_dsl is a special field by sonar to avoid
        # having to write our own dsl converter to convert the existing
        # visualization.visState.aggs field.
        visState = json.loads(self.raw_data['_source']['visualization']['visState'])

        is_sonar_visState = 'aggs_dsl' in visState
        if is_sonar_visState:
            return visState['aggs_dsl']
        else:
            # TODO: Raise an exception.
            raise SavedVisualizationInvalidVisState()
