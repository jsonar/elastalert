import copy

from .ruletypes import RuleType
from ..util import EAException, total_seconds, ts_to_dt


class BaseAggregationRule(RuleType):
    def __init__(self, *args):
        super(BaseAggregationRule, self).__init__(*args)
        bucket_interval = self.rules.get('bucket_interval')
        if bucket_interval:
            if 'seconds' in bucket_interval:
                self.rules['bucket_interval_period'] = str(bucket_interval['seconds']) + 's'
            elif 'minutes' in bucket_interval:
                self.rules['bucket_interval_period'] = str(bucket_interval['minutes']) + 'm'
            elif 'hours' in bucket_interval:
                self.rules['bucket_interval_period'] = str(bucket_interval['hours']) + 'h'
            elif 'days' in bucket_interval:
                self.rules['bucket_interval_period'] = str(bucket_interval['days']) + 'd'
            elif 'weeks' in bucket_interval:
                self.rules['bucket_interval_period'] = str(bucket_interval['weeks']) + 'w'
            else:
                raise EAException("Unsupported window size")

            if self.rules.get('use_run_every_query_size'):
                if total_seconds(self.rules['run_every']) % total_seconds(self.rules['bucket_interval_timedelta']) != 0:
                    raise EAException("run_every must be evenly divisible by bucket_interval if specified")
            else:
                if total_seconds(self.rules['buffer_time']) % total_seconds(self.rules['bucket_interval_timedelta']) != 0:
                    raise EAException("Buffer_time must be evenly divisible by bucket_interval if specified")

    def generate_aggregation_query(self):
        raise NotImplementedError()

    def add_aggregation_data(self, payload):
        for timestamp, payload_data in list(payload.items()):
            if 'interval_aggs' in payload_data:
                self.unwrap_interval_buckets(timestamp, None, payload_data['interval_aggs']['buckets'])
            elif 'bucket_aggs' in payload_data:
                self.unwrap_term_buckets(timestamp, payload_data['bucket_aggs']['buckets'])
            else:
                self.check_matches(timestamp, None, payload_data)

    def unwrap_interval_buckets(self, timestamp, query_key, interval_buckets):
        for interval_data in interval_buckets:
            # Use bucket key here instead of start_time for more accurate match timestamp
            self.check_matches(ts_to_dt(interval_data['key_as_string']), query_key, interval_data)

    def unwrap_term_buckets(self, timestamp, term_buckets):
        for term_data in term_buckets:
            if 'interval_aggs' in term_data:
                self.unwrap_interval_buckets(timestamp, term_data['key'], term_data['interval_aggs']['buckets'])
            else:
                self.check_matches(timestamp, term_data['key'], term_data)

    def check_matches(self, timestamp, query_key, aggregation_data):
        raise NotImplementedError()


class MetricAggregationRule(BaseAggregationRule):
    """ A rule that matches when there is a low number of events given a timeframe. """
    required_options = frozenset(['metric_agg_key', 'metric_agg_type', 'doc_type'])
    allowed_aggregations = frozenset(['min', 'max', 'avg', 'sum', 'cardinality', 'value_count'])

    def __init__(self, *args):
        super(MetricAggregationRule, self).__init__(*args)
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        if self.rules.get('buffer_time'):
            self.rules['timeframe'] = self.rules['buffer_time']

        if 'max_threshold' not in self.rules and 'min_threshold' not in self.rules:
            raise EAException("MetricAggregationRule must have at least one of either max_threshold or min_threshold")

        self.metric_key = self.rules['metric_agg_key'] + '_' + self.rules['metric_agg_type']

        if not self.rules['metric_agg_type'] in self.allowed_aggregations:
            raise EAException("metric_agg_type must be one of %s" % (str(self.allowed_aggregations)))

        self.rules['aggregation_query_element'] = self.generate_aggregation_query()

    def get_match_str(self, match):
        message = 'Threshold violation, %s:%s %s (min: %s max : %s) \n\n' % (
            self.rules['metric_agg_type'],
            self.rules['metric_agg_key'],
            match[self.metric_key],
            self.rules.get('min_threshold'),
            self.rules.get('max_threshold')
        )
        return message

    def generate_aggregation_query(self):
        return {self.metric_key: {self.rules['metric_agg_type']: {'field': self.rules['metric_agg_key']}}}

    def check_matches(self, timestamp, query_key, aggregation_data):
        if "compound_query_key" in self.rules:
            self.check_matches_recursive(timestamp, query_key, aggregation_data, self.rules['compound_query_key'], dict())

        else:
            metric_val = aggregation_data[self.metric_key]['value']
            if self.crossed_thresholds(metric_val):
                match = {self.rules['timestamp_field']: timestamp,
                         self.metric_key: metric_val}
                if query_key is not None:
                    match[self.rules['query_key']] = query_key
                self.add_match(match)

    def check_matches_recursive(self, timestamp, query_key, aggregation_data, compound_keys, match_data):
        if len(compound_keys) < 1:
            # shouldn't get to this point, but checking for safety
            return

        match_data[compound_keys[0]] = aggregation_data['key']
        if 'bucket_aggs' in aggregation_data:
            for result in aggregation_data['bucket_aggs']['buckets']:
                self.check_matches_recursive(timestamp,
                                             query_key,
                                             result,
                                             compound_keys[1:],
                                             match_data)

        else:
            metric_val = aggregation_data[self.metric_key]['value']
            if self.crossed_thresholds(metric_val):
                match_data[self.rules['timestamp_field']] = timestamp
                match_data[self.metric_key] = metric_val

                # add compound key to payload to allow alerts to trigger for every unique occurence
                compound_value = [match_data[key] for key in self.rules['compound_query_key']]
                match_data[self.rules['query_key']] = ",".join(compound_value)

                self.add_match(match_data)

    def crossed_thresholds(self, metric_value):
        if metric_value is None:
            return False
        if 'max_threshold' in self.rules and metric_value > self.rules['max_threshold']:
            return True
        if 'min_threshold' in self.rules and metric_value < self.rules['min_threshold']:
            return True
        return False


class PercentageMatchRule(BaseAggregationRule):
    required_options = frozenset(['match_bucket_filter'])

    def __init__(self, *args):
        super(PercentageMatchRule, self).__init__(*args)
        self.ts_field = self.rules.get('timestamp_field', '@timestamp')
        if 'max_percentage' not in self.rules and 'min_percentage' not in self.rules:
            raise EAException("PercentageMatchRule must have at least one of either min_percentage or max_percentage")

        self.rules['realert'] = 0

        if self.rules.get('buffer_time'):
            self.rules['timeframe'] = self.rules['buffer_time']

        self.match_bucket_filter = self.rules['match_bucket_filter']
        self.rules['aggregation_query_element'] = self.generate_aggregation_query()

    def get_match_str(self, match):
        percentage_format_string = self.rules.get('percentage_format_string', None)
        message = 'Percentage violation, value: %s (min: %s max : %s) of %s items\n\n' % (
            percentage_format_string % (match['percentage']) if percentage_format_string else match['percentage'],
            self.rules.get('min_percentage'),
            self.rules.get('max_percentage'),
            match['denominator']
        )
        return message

    def generate_aggregation_query(self):
        return {
            'percentage_match_aggs': {
                'filters': {
                    'other_bucket': True,
                    'filters': {
                        'match_bucket': {
                            'bool': {
                                'must': self.remove_meta_from_filters(self.match_bucket_filter)
                            }
                        }
                    }
                }
            }
        }

    @staticmethod
    def remove_meta_from_filters(filters):
        match_bucket_filter_without_meta = []
        for filter_doc in copy.deepcopy(filters):
            if 'meta' in filter_doc:
                del filter_doc['meta']
            if '$state' in filter_doc:
                del filter_doc['$state']
            match_bucket_filter_without_meta.append(filter_doc)
        return match_bucket_filter_without_meta


    def check_matches(self, timestamp, query_key, aggregation_data):
        match_bucket_count = aggregation_data['percentage_match_aggs']['buckets']['match_bucket']['doc_count']
        other_bucket_count = aggregation_data['percentage_match_aggs']['buckets']['_other_']['doc_count']

        if match_bucket_count is None or other_bucket_count is None:
            return
        else:
            total_count = other_bucket_count + match_bucket_count
            if total_count == 0:
                return
            else:
                match_percentage = (match_bucket_count * 1.0) / (total_count * 1.0) * 100
                if self.percentage_violation(match_percentage):
                    match = {self.rules['timestamp_field']: timestamp, 'percentage': match_percentage, 'denominator': total_count}
                    if query_key is not None:
                        match[self.rules['query_key']] = query_key
                    self.add_match(match)

    def percentage_violation(self, match_percentage):
        if 'max_percentage' in self.rules and match_percentage > self.rules['max_percentage']:
            return True
        if 'min_percentage' in self.rules and match_percentage < self.rules['min_percentage']:
            return True
        return False
