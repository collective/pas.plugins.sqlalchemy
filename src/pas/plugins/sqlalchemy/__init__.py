
def initialize(context):
    from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
    from AccessControl.Permissions import manage_users

    import plugin

    registerMultiPlugin(plugin.Plugin.meta_type)
    context.registerClass(plugin.Plugin,
            permission=manage_users,
            constructors=(plugin.manage_addSqlalchemyPlugin,
                          plugin.addSqlalchemyPlugin),
            visibility=None)

