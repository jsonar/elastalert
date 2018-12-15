# -*- coding: utf-8 -*-
import copy
import datetime

from blist import sortedlist
from elastalert.util import dt_to_ts
from elastalert.util import new_get_event_ts



class RuleType(object):
    """ The base class for a rule type.
    The class must implement add_data and add any matches to self.matches.

    :param rules: A rule configuration.
    """
    required_options = frozenset()

    def __init__(self, rules, args=None):
        self.matches = []
        self.rules = rules
        self.occurrences = {}
        self.rules['owner'] = self.rules.get('owner', '')
        self.rules['priority'] = self.rules.get('priority', '2')

    def add_data(self, data):
        """ The function that the ElastAlert client calls with results from ES.
        Data is a list of dictionaries, from Elasticsearch.

        :param data: A list of events, each of which is a dictionary of terms.
        """
        raise NotImplementedError()

    def add_match(self, event):
        """ This function is called on all matching events. Rules use it to add
        extra information about the context of a match. Event is a dictionary
        containing terms directly from Elasticsearch and alerts will report
        all of the information.

        :param event: The matching event, a dictionary of terms.
        """
        # Convert datetime's back to timestamps
        ts = self.rules.get('timestamp_field')
        if ts in event:
            event[ts] = dt_to_ts(event[ts])

        self.matches.append(copy.deepcopy(event))

    def get_match_str(self, match):
        """ Returns a string that gives more context about a match.

        :param match: The matching event, a dictionary of terms.
        :return: A user facing string describing the match.
        """
        return ''

    def garbage_collect(self, timestamp):
        """ Gets called periodically to remove old data that is useless beyond given timestamp.
        May also be used to compute things in the absence of new data.

        :param timestamp: A timestamp indicating the rule has been run up to that point.
        """
        pass

    def add_count_data(self, counts):
        """ Gets called when a rule has use_count_query set to True. Called to add data from querying to the rule.

        :param counts: A dictionary mapping timestamps to hit counts.
        """
        raise NotImplementedError()

    def add_terms_data(self, terms):
        """ Gets called when a rule has use_terms_query set to True.

        :param terms: A list of buckets with a key, corresponding to query_key, and the count """
        raise NotImplementedError()

    def add_aggregation_data(self, payload):
        """ Gets called when a rule has use_terms_query set to True.
        :param terms: A list of buckets with a key, corresponding to query_key, and the count """
        raise NotImplementedError()


class EventWindow(object):
    """ A container for hold event counts for rules which need a chronological ordered event window. """

    def __init__(self, timeframe, onRemoved=None, getTimestamp=new_get_event_ts('@timestamp')):
        self.timeframe = timeframe
        self.onRemoved = onRemoved
        self.get_ts = getTimestamp
        self.data = sortedlist(key=self.get_ts)
        self.running_count = 0

    def clear(self):
        self.data = sortedlist(key=self.get_ts)
        self.running_count = 0

    def append(self, event):
        """ Add an event to the window. Event should be of the form (dict, count).
        This will also pop the oldest events and call onRemoved on them until the
        window size is less than timeframe. """
        self.data.add(event)
        self.running_count += event[1]

        while self.duration() >= self.timeframe:
            oldest = self.data[0]
            self.data.remove(oldest)
            self.running_count -= oldest[1]
            self.onRemoved and self.onRemoved(oldest)

    def duration(self):
        """ Get the size in timedelta of the window. """
        if not self.data:
            return datetime.timedelta(0)
        return self.get_ts(self.data[-1]) - self.get_ts(self.data[0])

    def count(self):
        """ Count the number of events in the window. """
        return self.running_count

    def mean(self):
        """ Compute the mean of the value_field in the window. """
        if len(self.data) > 0:
            datasum = 0
            datalen = 0
            for dat in self.data:
                if "placeholder" not in dat[0]:
                    datasum += dat[1]
                    datalen += 1
            if datalen > 0:
                return datasum / float(datalen)
            return None
        else:
            return None

    def __iter__(self):
        return iter(self.data)

    def append_middle(self, event):
        """ Attempt to place the event in the correct location in our deque.
        Returns True if successful, otherwise False. """
        rotation = 0
        ts = self.get_ts(event)

        # Append left if ts is earlier than first event
        if self.get_ts(self.data[0]) > ts:
            self.data.appendleft(event)
            self.running_count += event[1]
            return

        # Rotate window until we can insert event
        while self.get_ts(self.data[-1]) > ts:
            self.data.rotate(1)
            rotation += 1
            if rotation == len(self.data):
                # This should never happen
                return
        self.data.append(event)
        self.running_count += event[1]
        self.data.rotate(-rotation)
