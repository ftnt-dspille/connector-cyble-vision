"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, get_logger, ConnectorError

from .operations import operations, check_health_ext

logger = get_logger('cyble-vision')


class CybleVision(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('In execute() Operation:[{0}]'.format(operation))
        try:
            logger.debug('execute [{}]'.format(operation))
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def check_health(self, config):
        logger.info('starting health check')
        check_health_ext(config)
        logger.info('completed health check no errors')
