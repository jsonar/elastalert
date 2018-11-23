from elastalert.rule_type_definitions.ruletypes import RuleType
from elastalert.util import lookup_es_key, elastalert_logger, hashable


class CompareRule(RuleType):
    """ A base class for matching a specific term by passing it to a compare function """
    required_options = frozenset(['compound_compare_key'])

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

    def compare(self, event):
        """ An event is a match if this returns true """
        raise NotImplementedError()

    def add_data(self, data):
        # If compare returns true, add it as a match
        for event in data:
            if self.compare(event):
                self.add_match(event)


class BlacklistRule(CompareRule):
    """ A CompareRule where the compare function checks a given key against a blacklist """
    required_options = frozenset(['compare_key', 'blacklist'])

    def __init__(self, rules, args=None):
        super(BlacklistRule, self).__init__(rules, args=None)
        self.expand_entries('blacklist')

    def compare(self, event):
        # Sonar: Since lists are always string, might aswell convert the term we extracted from document.
        term = str(lookup_es_key(event, self.rules['compare_key']))
        if term in self.rules['blacklist']:
            return True

        return False


class WhitelistRule(CompareRule):
    """ A CompareRule where the compare function checks a given term against a whitelist """
    required_options = frozenset(['compare_key', 'whitelist', 'ignore_null'])

    def __init__(self, rules, args=None):
        super(WhitelistRule, self).__init__(rules, args=None)
        self.expand_entries('whitelist')

    def compare(self, event):
        # Sonar: Since lists are always string, might aswell convert the term we extracted from document.
        term = str(lookup_es_key(event, self.rules['compare_key']))
        if term is None:
            return not self.rules['ignore_null']
        if term not in self.rules['whitelist']:
            return True

        return False


class ChangeRule(CompareRule):
    """ A rule that will store values for a certain term and match if those values change """
    required_options = frozenset(['query_key', 'compound_compare_key', 'ignore_null'])
    change_map = {}
    occurrence_time = {}

    def compare(self, event):
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
        super(ChangeRule, self).add_match(dict(match.items() + extra.items()))

