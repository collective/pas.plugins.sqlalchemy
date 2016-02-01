# -*- coding: utf-8 -*-

from .model import Base


def prepare(engine):
    Base.metadata.create_all(engine)
