"""
===========================
Log Settings
===========================

The following settings control how logging happens at various levels

"""
__author__ = 'Sundaresan V'


import logging

logger = logging

LONG_FORMAT = '[%(levelname)s] [%(asctime)s] {%(filename)s:%(lineno)d} - %(message)s'
SHORT_FORMAT = '[%(levelname)s] - %(message)s'
TIME_FORMAT = '%y-%m-%d %H:%M:%S'


class LogSettings(object):
    """Class contains the logging settings used."""

    log_file_level = logging.DEBUG
    log_file_format = LONG_FORMAT
    log_file_format_time = TIME_FORMAT

    log_console_level = logging.ERROR
    log_console_level = logging.DEBUG
    log_console_level = logging.INFO
    log_console_format = LONG_FORMAT
    log_console_format_time = TIME_FORMAT

    log_report_level = logging.WARN
    log_format_level_message = logging.Formatter(SHORT_FORMAT)

    log_sandbox_file_level = logging.DEBUG
    log_sandbox_file_name = 'test.log'
    log_sandbox_format = LONG_FORMAT
    log_sandbox_format_time = TIME_FORMAT


def init_console_logger(log_settings=LogSettings()):
    """Initiates the console logger first so that errors/test ids can be displayed to the console"""
    #StreamHandler logs to console
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch_format = logging.Formatter(SHORT_FORMAT, log_settings.log_console_format_time)
    ch.setFormatter(ch_format)
    _logger = logging.getLogger()
    _logger.setLevel(logging.DEBUG)
    _logger.addHandler(ch)


def init_logger(log_file, log_settings=LogSettings()):
    """
    Internal function to set the logging details.
    The settings are applied for global logger
    """
    _logger = logging.getLogger()
    _logger.setLevel(logging.DEBUG)
    for handle in _logger.handlers:
        _logger.removeHandler(handle)
    if log_settings.log_console_level is not None:
        #StreamHandler logs to console
        ch = logging.StreamHandler()
        ch.setLevel(log_settings.log_console_level)
        ch_format = logging.Formatter(log_settings.log_console_format,
                                      log_settings.log_console_format_time)
        ch.setFormatter(ch_format)
        _logger.addHandler(ch)

    if log_settings.log_file_level is not None:
        #File handler
        fh = logging.FileHandler(log_file)
        fh.setLevel(log_settings.log_file_level)
        fh_format = logging.Formatter(log_settings.log_file_format, log_settings.log_file_format_time)
        fh.setFormatter(fh_format)
        _logger.addHandler(fh)

    return _logger

