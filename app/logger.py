# -*- coding: utf-8 -*-
import logging
from logging.handlers import RotatingFileHandler
import os
from .config import AppConfig


def setup_root_logger(cfg: AppConfig) -> logging.Logger:
    logger = logging.getLogger('powercontrol')
    logger.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))

    logdir = os.path.dirname(cfg.log_path) or '.'
    os.makedirs(logdir, exist_ok=True)

    fh = RotatingFileHandler(cfg.log_path, maxBytes=5_000_000, backupCount=3, encoding='utf-8')
    fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
    fh.setFormatter(fmt)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)

    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(ch)

    if cfg.silence_logs:
        logging.disable(logging.CRITICAL)

    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    return logger
