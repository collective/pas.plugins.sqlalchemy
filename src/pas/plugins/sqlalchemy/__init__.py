# -*- coding: utf-8 -*-
from Products.PluggableAuthService.PluggableAuthService import MultiPlugins
from Products.PluggableAuthService.PluggableAuthService import \
    registerMultiPlugin
import plugin
from AccessControl.Permissions import add_user_folders
import os

plugins = set()


def initialize(context):
    if plugin.Plugin.meta_type not in MultiPlugins:
        registerMultiPlugin(plugin.Plugin.meta_type)
        context.registerClass(
                plugin.Plugin,
                permission=add_user_folders,
                icon=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                  'www', 'sql.png'),
                constructors=(plugin.manage_addSqlalchemyPluginForm,
                              plugin.addSqlalchemyPlugin),
                visibility=None
            )
