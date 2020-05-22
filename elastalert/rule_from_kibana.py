#!/usr/bin/env python
# -*- coding: utf-8 -*-



import json

import yaml
from elasticsearch.client import Elasticsearch

from .elastalert.kibana import filters_from_dashboard
from .sonar_connection import SonarConnectionUrllib3HttpConnection


def main():
    es_host = eval(input("Elasticsearch host: "))
    es_port = eval(input("Elasticsearch port: "))
    db_name = eval(input("Dashboard name: "))
    send_get_body_as = eval(input("Method for querying Elasticsearch[GET]: ")) or 'GET'
    es = Elasticsearch(
        connection_class=SonarConnectionUrllib3HttpConnection,  # Sonar: Insert sonarg-user in header.
        host=es_host,
        port=es_port,
        send_get_body_as=send_get_body_as)
    query = {'query': {'term': {'_id': db_name}}}
    res = es.search(index='kibana-int', body=query, _source_include=['dashboard'])
    if not res['hits']['hits']:
        print(("No dashboard %s found" % (db_name)))
        exit()

    db = json.loads(res['hits']['hits'][0]['_source']['dashboard'])
    config_filters = filters_from_dashboard(db)

    print("\nPartial Config file")
    print("-----------\n")
    print(("name: %s" % (db_name)))
    print(("es_host: %s" % (es_host)))
    print(("es_port: %s" % (es_port)))
    print("filter:")
    print((yaml.safe_dump(config_filters)))


if __name__ == '__main__':
    main()
