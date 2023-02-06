import json
from datetime import datetime
from collections import OrderedDict
from enum import Enum


class AlarmSeverity(Enum):
    Warning = 0
    Minor = 1
    Major = 2
    Critical = 3
    Clear = 4

class Alarm(object):
    """
    This class represents an alarm as expected by dojot/alarm-manager
    """

    def __init__(self, domain, namespace, severity,
                 timestamp=datetime.now(), description=""):
        """Constructs an dojot alarm

        Note:
            The alarm timestamp will be set up here

        Args:
            param1 (str): Application domain.
            param2 (str): Alarm namespace.
            param3 (AlarmSeverity): Severity.
            param4 (datetime): timestamp.
            param5 (str): Alarm description.
            """

        if not isinstance(severity, AlarmSeverity):
            raise ValueError('Invalid severity value, it must be AlarmSeverity')

        if not isinstance(timestamp, datetime):
            raise ValueError('Invalid timestamp value, it must be datetime')

        self._domain = domain
        self._severity = severity
        self._timestamp = timestamp.isoformat()
        self._namespace = namespace
        self._description = description
        self._primary_subject = dict()
        self._additional_data = dict()

    @property
    def domain(self):
        return self._domain

    @property
    def severity(self):
        return self._severity

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def namespace(self):
        return self._namespace

    @property
    def description(self):
        return self._description

    @namespace.setter
    def namespace(self, value):
        self._namespace = value

    @description.setter
    def description(self, value):
        self._description = value

    def add_primary_subject(self, key, value):
        self._primary_subject[key] = value

    def add_additional_data(self, key, value):
        self._additional_data[key] = value

    def get_primary_subject(self, key):
        return self._primary_subject[key]

    def get_additional_data(self, key):
        return self._additional_data[key]

    def remove_primary_subject(self, key):
        if key in self._primary_subject:
            del self._primary_subject[key]

    def remove_additional_data(self, key):
        if key in self._additional_data:
            del self._additional_data[key]

    def serialize(self):
        """
        Alarm JSON format:
        {
            "namespace": "OpenFlow",
            "domain": "SecureChannelDown",
            "primarySubject": {
                "dpid": "012345678",
            },
            "additionalData": {
                "nports": "10"
            },
            "severity": "Critical",
            "eventTimestamp": "2018-03-01T11:02:08.361333"
        }
        """

        data = OrderedDict()
        data['namespace'] = self._namespace
        data['domain'] = self._domain
        data['primarySubject'] = self._primary_subject
        data['additionalData'] = self._additional_data
        data['severity'] = self._severity.name
        data['eventTimestamp'] = self._timestamp

        return json.dumps(data)
