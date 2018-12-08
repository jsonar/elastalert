import re
from datetime import timedelta

from elastalert.rule_type_definitions.ruletypes import RuleType
from elastalert.util import lookup_es_key, elastalert_logger, hashable, ts_to_dt


class CompareRule(RuleType):
    """ A base class for matching a specific term by passing it to a compare function """
    required_options = frozenset(['compound_compare_key'])

    def __init__(self, rules, args=None):
        super(CompareRule, self).__init__(rules, args=None)
        self.rules['use_run_every_query_size'] = True
        self.rules['realert'] = timedelta(0)

    def expand_entries(self, list_type):
        """ Expand entries specified in files using the '!file' directive, if there are
        any, then add everything to a set.
        """
        entries_set = set()
        for entry in self.rules[list_type]:
            if entry.startswith("!file"):  # - "!file /path/to/list"
                filename = entry.split()[1]
                with open(filename, 'r') as f:
                    for line in f:
                        entries_set.add(line.rstrip())
            else:
                entries_set.add(entry)
        self.rules[list_type] = entries_set

    def generate_aggregation_query(self):
        return {'{}'.format(self.rules['compare_key']): {'terms': {'field': self.rules['compare_key']}}}

    def generate_item_clauses(self, value_list, field):  # TODO change this to handle a list of keys
        item_clauses = []
        for item in value_list:
            try:
                clause = {"match": {"{}".format(field): item}}  # TODO make these terms not matches
                item_clauses.append(clause)
            except ValueError:
                pass

            try:
                clause = {"match": {"{}".format(field): int(item)}}
                item_clauses.append(clause)
            except ValueError:
                try:
                    clause = {"match": {"{}".format(field): float(item)}}
                    item_clauses.append(clause)
                except ValueError:
                    pass
        # TODO deal with more datatypes
        # TODO handle ignore null for white lists
        return item_clauses

    def compare(self, event):
        """ An event is a match if this returns true """
        raise NotImplementedError()

    def add_data(self, data):  # TODO remove
        # If compare returns true, add it as a match
        for event in data:
            if self.compare(event):
                self.add_match(event)

    def add_aggregation_data(self, payload):
        for timestamp, payload_data in payload.iteritems():
            elastalert_logger.warning("{} {}".format(timestamp, payload_data))
            self.check_matches(timestamp, payload_data)

    def check_matches(self, timestamp, aggregation_data):
        for item in aggregation_data['{}'.format(self.rules['compare_key'])]['buckets']:
            match = {self.rules['timestamp_field']: timestamp, self.rules['compare_key']: item['key'], "doc_count": item['doc_count']}
            elastalert_logger.warning("{} {}".format(timestamp, item))
            self.add_match(match)


class BlacklistRule(CompareRule):
    """ A CompareRule where the compare function checks a given key against a blacklist """
    required_options = frozenset(['compare_key', 'blacklist'])

    def __init__(self, rules, args=None):
        super(BlacklistRule, self).__init__(rules, args=None)
        self.expand_entries('blacklist')

        self.item_clauses = self.generate_item_clauses(self.rules['blacklist'], self.rules['compare_key'])

        self.rules['aggregation_query_element'] = self.generate_aggregation_query()

    def compare(self, event):
        return True

    def extend_query(self, base_query):
        """nests the query inside another boolean query to only get documents on the blacklist"""
        inner_query = base_query['query']
        query = {"query": {"bool": {"must": [inner_query, {"bool": {"should": self.item_clauses}}]}}}
        return query


class WhitelistRule(CompareRule):
    """ A CompareRule where the compare function checks a given term against a whitelist """
    required_options = frozenset(['compare_key', 'whitelist', 'ignore_null'])

    def __init__(self, rules, args=None):
        super(WhitelistRule, self).__init__(rules, args=None)
        self.expand_entries('whitelist')
        self.item_clauses = self.generate_item_clauses(self.rules['whitelist'], self.rules['compare_key'])
        self.rules['aggregation_query_element'] = self.generate_aggregation_query()

    def compare(self, event):
        return True

    def extend_query(self, base_query):
        """nests the query inside another boolean query to only get documents on the blacklist"""
        inner_query = base_query['query']
        query = {"query": {"bool": {"must": [inner_query, {"bool": {"must_not": self.item_clauses}}]}}}
        return query


class ChangeRule(CompareRule):
    """ A rule that will store values for a certain term and match if those values change """
    required_options = frozenset(['query_key', 'compound_compare_key', 'ignore_null'])
    change_map = {}
    occurrence_time = {}

    def __init__(self,rules, args=None):
        super(ChangeRule, self).__init__(rules, args=None)
        self.expand_entries('compound_compare_key')
        self.last_values = []

        # self.item_clauses = self.generate_item_clauses(self.rules['compound_compare_key'], self.last_values)

    def extend_query(self, base_query):  # TODO make this work
        inner_query = base_query['query']
        query = {"query": {"bool": {"must": [inner_query, {"bool": {"must_not": self.item_clauses}}]}}}
        return query


    def get_last_values(self):
        for val in self.rules['compound_compare_key']:
            # TODO add a timestamp field to the sort
            old_val_query = {"sort": [{"{}"}],"query": {"bool"}}




    def compare(self, event):
        """
        key = hashable(lookup_es_key(event, self.rules['query_key']))
        values = []
        elastalert_logger.debug(" Previous Values of compare keys  " + str(self.occurrences))
        for val in self.rules['compound_compare_key']:
            lookup_value = lookup_es_key(event, val)
            values.append(lookup_value)
        elastalert_logger.debug(" Current Values of compare keys   " + str(values))

        changed = False
        for val in values:
            if not isinstance(val, bool) and not val and self.rules['ignore_null']:
                return False
        # If we have seen this key before, compare it to the new value
        if key in self.occurrences:
            for idx, previous_values in enumerate(self.occurrences[key]):
                elastalert_logger.debug(" " + str(previous_values) + " " + str(values[idx]))
                changed = previous_values != values[idx]
                if changed:
                    break
            if changed:
                self.change_map[key] = (self.occurrences[key], values)
                # If using timeframe, only return true if the time delta is < timeframe
                if key in self.occurrence_time:
                    changed = event[self.rules['timestamp_field']] - self.occurrence_time[key] <= self.rules['timeframe']

        # Update the current value and time
        elastalert_logger.debug(" Setting current value of compare keys values " + str(values))
        self.occurrences[key] = values
        if 'timeframe' in self.rules:
            self.occurrence_time[key] = event[self.rules['timestamp_field']]
        elastalert_logger.debug("Final result of comparision between previous and current values " + str(changed))
        return changed
        """
        return True

    def add_match(self, match):
        # TODO this is not technically correct
        # if the term changes multiple times before an alert is sent
        # this data will be overwritten with the most recent change
        change = self.change_map.get(hashable(lookup_es_key(match, self.rules['query_key'])))
        extra = {}
        if change:
            extra = {'old_value': change[0],
                     'new_value': change[1]}
            elastalert_logger.debug("Description of the changed records  " + str(dict(match.items() + extra.items())))
        # super(ChangeRule, self).add_match(dict(match.items() + extra.items()))
        # TODO add actual match currently commented to keep the log spam down
