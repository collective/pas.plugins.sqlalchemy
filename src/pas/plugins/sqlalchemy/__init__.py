plugins = set()

def initialize(context):
    from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
    from Products.PluggableAuthService.PluggableAuthService import MultiPlugins

    import plugin

    if plugin.Plugin.meta_type not in MultiPlugins:
        registerMultiPlugin(plugin.Plugin.meta_type)
