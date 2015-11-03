# -*- coding: utf-8 -*-
from Products.PluggableAuthService.PluggableAuthService import MultiPlugins
from Products.PluggableAuthService.PluggableAuthService import \
    registerMultiPlugin
import plugin

plugins = set()


def initialize(context):
    if plugin.Plugin.meta_type not in MultiPlugins:
        registerMultiPlugin(plugin.Plugin.meta_type)
