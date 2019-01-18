import copy
from datetime import timedelta

from elastalert.rule_type_definitions.ruletypes import RuleType, EventWindow
from elastalert.util import (EAException, new_get_event_ts, hashable, lookup_es_key, elastalert_logger, pretty_ts, dt_to_ts,
                             ts_to_dt)


class FrequencyRule(RuleType):
    """ A rule that matches if num_events number of events occur within a timeframe """
    required_options = frozenset(['num_events', 'timeframe'])

    def __init__(self, *args):
        super(FrequencyRule, self).__init__(*args)
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        self.get_ts = new_get_event_ts(self.ts_field)
        self.attach_related = self.rules.get('attach_related', False)

    def add_count_data(self, data):
        """ Add count data to the rule. Data should be of the form {ts: count}. """
        if len(data) > 1:
            raise EAException('add_count_data can only accept one count at a time')

        (ts, count), = data.items()

        event = ({self.ts_field: ts}, count)
        self.occurrences.setdefault('all', EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append(event)
        self.check_for_match('all')

    def add_terms_data(self, terms):
        for timestamp, buckets in terms.iteritems():
            for bucket in buckets:
                event = ({self.ts_field: timestamp,
                          self.rules['query_key']: bucket['key']}, bucket['doc_count'])
                self.occurrences.setdefault(bucket['key'], EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append(event)
                self.check_for_match(bucket['key'])

    def add_data(self, data):
        if 'query_key' in self.rules:
            qk = self.rules['query_key']
        else:
            qk = None

        for event in data:
            if qk:
                key = hashable(lookup_es_key(event, qk))
            else:
                # If no query_key, we use the key 'all' for all events
                key = 'all'

            # Store the timestamps of recent occurrences, per key
            self.occurrences.setdefault(key, EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)).append((event, 1))
            self.check_for_match(key, end=False)

        # We call this multiple times with the 'end' parameter because subclasses
        # may or may not want to check while only partial data has been added
        if key in self.occurrences:  # could have been emptied by previous check
            self.check_for_match(key, end=True)

    def check_for_match(self, key, end=False):
        # Match if, after removing old events, we hit num_events.
        # the 'end' parameter depends on whether this was called from the
        # middle or end of an add_data call and is used in subclasses
        timeframe_occurences_count = self.occurrences[key].count()
        if timeframe_occurences_count >= self.rules['num_events']:
            elastalert_logger.info("Match triggered! {} (> {}) events occurred in the last timeframe".format(
                timeframe_occurences_count, self.rules['num_events']))
            # Sonar: Added deep copies here and there since some "event" fields will be stringified at some point
            # down the line.
            event = copy.deepcopy(self.occurrences[key].data[-1][0])
            if self.attach_related:
                event['related_events'] = [copy.deepcopy(data[0]) for data in self.occurrences[key].data[:-1]]
            self.add_match(event)
            # Sonar: This is responsible for this ugly behaviour, as documented by one of the mainatainers:
            #   :see https://github.com/Yelp/elastalert/issues/807#issuecomment-263678089
            # self.occurrences.pop(key)

    def garbage_collect(self, timestamp):
        """ Remove all occurrence data that is beyond the timeframe away """
        stale_keys = []
        for key, window in self.occurrences.iteritems():
            if timestamp - lookup_es_key(window.data[-1][0], self.ts_field) > self.rules['timeframe']:
                stale_keys.append(key)
        map(self.occurrences.pop, stale_keys)

    def get_match_str(self, match):
        lt = self.rules.get('use_local_time')
        match_ts = lookup_es_key(match, self.ts_field)
        starttime = pretty_ts(dt_to_ts(ts_to_dt(match_ts) - self.rules['timeframe']), lt)
        endtime = pretty_ts(match_ts, lt)
        message = 'At least %d events occurred between %s and %s\n\n' % (self.rules['num_events'],
                                                                         starttime,
                                                                         endtime)
        return message


class FlatlineRule(FrequencyRule):
    """ A rule that matches when there is a low number of events given a timeframe. """
    required_options = frozenset(['timeframe', 'threshold'])

    def __init__(self, *args):
        # self.rules['realert'] = timedelta(10)
        super(FlatlineRule, self).__init__(*args)
        self.rules['realert'] = timedelta(0)
        self.threshold = self.rules['threshold']

        # Dictionary mapping query keys to the first events
        self.first_event = {}

    def check_for_match(self, key, end=True):

        count = self.occurrences[key].count()  # get the last value from the dict which is the count
        if count < self.rules['threshold']:
            # Do a deep-copy, otherwise we lose the datetime type in the timestamp field of the last event
            event = copy.deepcopy(self.occurrences[key].data[-1][0])
            event.update(key=key, count=count)
            self.add_match(event)
        self.occurrences.pop(key)

    def get_match_str(self, match):
        ts = match[self.rules['timestamp_field']]
        lt = self.rules.get('use_local_time')
        message = 'An abnormally low number of events occurred around %s.\n' % (pretty_ts(ts, lt))
        message += 'Between %s and %s, there were less than %s events.\n\n' % (
            pretty_ts(dt_to_ts(ts_to_dt(ts) - self.rules['timeframe']), lt),
            pretty_ts(ts, lt),
            self.rules['threshold']
        )
        return message

    def garbage_collect(self, ts):
        # We add an event with a count of zero to the EventWindow for each key. This will cause the EventWindow
        # to remove events that occurred more than one `timeframe` ago, and call onRemoved on them.
        default = ['all'] if 'query_key' not in self.rules else []
        for key in self.occurrences.keys() or default:
            self.occurrences.setdefault(
                key,
                EventWindow(self.rules['timeframe'], getTimestamp=self.get_ts)
            ).append(
                ({self.ts_field: ts}, 0)
            )
            self.first_event.setdefault(key, ts)
            # if self.rules.get('query_key'):
            #    self.check_for_match(key)
