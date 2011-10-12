import plugin
import model

from z3c.saconfig import named_scoped_session
Session = named_scoped_session("pas.plugins.sqlalchemy")

plugin_name = "sql"


def install_pas_plugin(self):
    pas = self.acl_users
    if not plugin_name in pas.objectIds():
        manager = plugin.Plugin(plugin_name, "SQLAlchemy user/group/prop store")
        pas._setObject(plugin_name, manager)
        provider = pas[plugin_name]
        provider.manage_activateInterfaces([
            'IGroupsPlugin',
            'IGroupEnumerationPlugin',
            'IGroupIntrospection',
            'IGroupManagement',
            'IAuthenticationPlugin',
            'IUserEnumerationPlugin',
            'IUserManagement',
            'IUserAdderPlugin',
            'IRolesPlugin',
            'IRoleAssignerPlugin',
            'IPropertiesPlugin'])


def uninstall_pas_plugin(self):
    pas = self.acl_users
    if plugin_name in pas.objectIds():
        pas[plugin_name].manage_activateInterfaces([])
        pas.manage_delObjects([plugin_name])


def uninstall(context):
    if context.readDataFile('marker.txt') is None:
        return
    portal = context.getSite()
    uninstall_pas_plugin(portal)


def install(context):
    if context.readDataFile('marker.txt') is None:
        return
    portal = context.getSite()
    session = Session()
    model.Base.metadata.create_all(session.bind)
    install_pas_plugin(portal)
