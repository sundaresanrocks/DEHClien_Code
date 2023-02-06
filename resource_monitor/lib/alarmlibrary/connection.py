import logging
import json
import pika
from lib.alarmlibrary.alarm import Alarm
from lib.alarmlibrary.exceptions import (ConnectionClosed,
                                     InvalidAlarm,
                                     AuthenticationError,
                                     AlarmManagerException)

LOGGER = logging.getLogger(__name__)

# Exchange hard-coded declared as durable
DEFAULT = {
    'EXCHANGE': 'alarms.exchange',
    'EXCHANGE_TYPE': 'direct',
    'ROUTING_KEY': 'alarms',
    'HOST': 'localhost',
    'PORT': 5672,
    'USER': 'guest',
    'PASSWORD': 'guest'
}


class RabbitMqClientConnection(object):
    def __init__(self, exchange=DEFAULT['EXCHANGE'], exchange_type=DEFAULT['EXCHANGE_TYPE'],
                 default_routing_key=DEFAULT['ROUTING_KEY']):
        self._exchange = exchange
        self._exchange_type = exchange_type
        self._default_routing_key = default_routing_key
        self._host = None
        self._port = None
        self._user = None
        self._password = None
        self._connection = None
        self._channel = None

    def open(self, host=DEFAULT['HOST'], port=DEFAULT['PORT'],
             user=DEFAULT['USER'], password=DEFAULT['PASSWORD']):
        # keep for reopening the connection
        self._host = host
        self._port = port
        self._user = user
        self._password = password

        try:
            LOGGER.debug("Trying to connect to host=%s, port=%d, user=%s, password=%s",
                         host, port, user, password)
            credentials = pika.PlainCredentials(user, password)
            parameters = pika.ConnectionParameters(host, port, '/', credentials)
            self._connection = pika.BlockingConnection(parameters)
            self._channel = self._connection.channel()
            self._channel.exchange_declare(exchange=self._exchange,
                                           exchange_type=self._exchange_type,
                                           durable=True)
        except pika.exceptions.ProbableAuthenticationError:
            raise AuthenticationError("Invalid credentials: user=%s passwd=%s" % (user, password))
        except pika.exceptions.ConnectionClosed:
            raise ConnectionClosed("Could not connect to %s:%s", )
        except Exception as ex:
            #LOGGER.error("Connection to RabbitMQ server failed! %s", ex.message)
            #raise AlarmManagerException(ex.message)
            LOGGER.error("Connection to RabbitMQ server failed! ")

    def is_open(self):
        return (self._channel and self._connection and
                self._channel.is_open and self._connection.is_open)

    def close(self):
        if self._channel and self._channel.is_open:
            self._channel.close()
        if self._connection and self._connection.is_open:
            self._connection.close()

    def send(self, alarm, routing_key=None):
        if not isinstance(alarm, Alarm):
            raise InvalidAlarm("Invalid alarm type, it must be Alarm")

        delivered = False
        if self.is_open():
            if not routing_key:
                routing_key = self._default_routing_key

            message = alarm.serialize()
            parsed = json.loads(message)
            LOGGER.debug("Sending : exchange=%s routingkey=%s\nalarm= %s",
                         self._exchange, routing_key,
                         json.dumps(parsed, indent=2))
            try:
                delivered = self._channel.basic_publish(exchange=self._exchange,
                                                        routing_key=routing_key,
                                                        body=message)
            except pika.exceptions.ConnectionClosed:
                LOGGER.error("Connection to RabbitMQ server has been closed/reset!")
                delivered = False

        if not delivered:
            LOGGER.warning("Reconnecting to RabbitMQ server!")
            self.close()
            try:
                self.open(self._host, self._port, self._user, self._password)
                LOGGER.warning("Resending alarm!")
                delivered = self._channel.basic_publish(exchange=self._exchange,
                                                        routing_key=routing_key,
                                                        body=message)
            except Exception as ex:
                LOGGER.error("Alarm couldn't be delivered! Try later!")
                #raise AlarmManagerException(ex.message)

        return delivered
