import os

SONARK_CONF = os.environ.get('SONARK_CONFIG_PATH')
JSONAR_LOCALDIR = os.environ.get('JSONAR_LOCALDIR')
DISPATCHER_CONF = JSONAR_LOCALDIR + '/dispatcher/dispatcher.conf'
SYSLOG_DEFAULT_HOST = '127.0.0.1'
SYSLOG_DEFAULT_PORT = 514
SYSLOG_DEFAULT_PROTOCOL = 'udp'

NEW_TERM_DB = 'lmrm__sonarg'
NEW_TERM_COLL = 'lmrm__elastalert_new_terms_reference'
