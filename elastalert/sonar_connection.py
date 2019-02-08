import os
from elasticsearch import connection
import yaml


def getSonarConfig():
    full_path = os.environ.get('SONARK_CONFIG_PATH')
    if os.path.isfile(full_path):
        return yaml.load(open(full_path))
    else:
        raise Exception(
            "kibana.yml can't be found in the root directory of sonark. Ensure Sonark is installed properly.")


class SonarConnectionUrllib3HttpConnection(connection.Urllib3HttpConnection):
    def __init__(self, *args, **kwargs):
        super(SonarConnectionUrllib3HttpConnection, self).__init__(*args, **kwargs)
        self.headers.update({
            'sonarg-user': getSonarConfig()['elasticsearch.customHeaders']['sonarg-user']
        })


class SonarConnectionRequestsHttpConnection(connection.RequestsHttpConnection):
    def __init__(self, *args, **kwargs):
        kwargs['headers'] = {
            'sonarg-user': getSonarConfig()['elasticsearch.customHeaders']['sonarg-user']
        }
        super(SonarConnectionRequestsHttpConnection, self).__init__(*args, **kwargs)
