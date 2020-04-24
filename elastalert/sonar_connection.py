import os
from elasticsearch import connection
import yaml

from .constants import SONARK_CONF


def getSonarConfig():
    if os.path.isfile(SONARK_CONF):
        return yaml.load(open(SONARK_CONF), Loader=yaml.UnsafeLoader)
    else:
        raise Exception(
            "kibana.yml can't be found in {}. Ensure Sonark is installed properly.".format(SONARK_CONF))


class SonarConnectionUrllib3HttpConnection(connection.Urllib3HttpConnection):
    def __init__(self, *args, **kwargs):
        super(SonarConnectionUrllib3HttpConnection, self).__init__(*args, **kwargs)
        self.headers.update({
            'sonarg-user': getSonarConfig()['elasticsearch.customHeaders']['sonarg-user']
        })


class SonarConnectionRequestsHttpConnection(connection.RequestsHttpConnection):
    def __init__(self, *args, **kwargs):
        kwargs['timeout'] = 600
        kwargs['headers'] = {
            'sonarg-user': getSonarConfig()['elasticsearch.customHeaders']['sonarg-user']
        }
        super(SonarConnectionRequestsHttpConnection, self).__init__(*args, **kwargs)
