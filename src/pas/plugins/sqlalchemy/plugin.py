import datetime
import logging
import sqlalchemy.exc
from sqlachemy import sql
from sqlachemy import types
import traceback

from AccessControl import ClassSecurityInfo
from AccessControl.SecurityManagement import getSecurityManager
from Globals import InitializeClass
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.permissions import ManageUsers
from Products.PluggableAuthService.permissions import SetOwnPassword
from Products.PluggableAuthService.utils import createViewName
from OFS.Cache import Cacheable
from DateTime import DateTime

# Pluggable Auth Service
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserAdderPlugin
from Products.PluggableAuthService.interfaces.plugins import IRolesPlugin
from Products.PluggableAuthService.interfaces.plugins import IRoleAssignerPlugin
from Products.PluggableAuthService.interfaces.plugins import IGroupsPlugin
from Products.PluggableAuthService.interfaces.plugins import IGroupEnumerationPlugin
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin

# PlonePAS
from Products.PlonePAS.interfaces.plugins import IUserManagement
from Products.PlonePAS.interfaces.capabilities import IDeleteCapability
from Products.PlonePAS.interfaces.capabilities import IPasswordSetCapability
from Products.PlonePAS.interfaces.capabilities import IAssignRoleCapability
from Products.PlonePAS.interfaces.plugins import IMutablePropertiesPlugin
from Products.PlonePAS.interfaces.group import IGroupIntrospection
from Products.PlonePAS.interfaces.group import IGroupManagement
from Products.PlonePAS.sheet import MutablePropertySheet
from Products.PlonePAS.plugins.group import PloneGroup

from pas.plugins.sqlalchemy import model
from z3c.saconfig import named_scoped_session
Session = named_scoped_session("pas.plugins.sqlalchemy")

logger = logging.getLogger("pas.plugins.sqlalchemy")

def safeencode(v):
    if isinstance(v, unicode):
        return v.encode('utf-8')
    return v

def safedecode(v):
    if isinstance(v, str):
        return v.decode('utf-8')
    return v

def graceful_recovery(default=None, log_args=True):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                value = func(*args, **kwargs)
            except sqlalchemy.exc.SQLAlchemyError, e:
                if log_args is False:
                    args = ()
                    kwargs = {}

                formatted_tb = traceback.format_exc()

                try:
                    exc_str = str(e)
                except:
                    exc_str = "<%s at 0x%x>" % ( e.__class__.__name__, id(e))

                logger.critical(
                    "caught SQL-exception: "
                    "%s (in method ``%s``; arguments were %s)\n\n%s" % (
                    exc_str,
                    func.__name__, ", ".join(
                        [repr(arg) for arg in args] +
                        ["%s=%s" % (name, repr(value)) for (name, value) in kwargs.items()]
                        ), formatted_tb))
                return default
            return value
        return wrapper
    return decorator


class Plugin(BasePlugin, Cacheable):
    meta_type = 'SQLAlchemy user/group/prop manager'
    security = ClassSecurityInfo()

    principal_class = model.Principal
    user_class = model.User
    group_class = model.Group

    def __init__(self, id, title=None):
        self.id = self.id = id
        self.title = title

    security.declarePrivate('invalidateCacheForChangedUser')
    def invalidateCacheForChangedUser(self, user_id):
        pass

    #
    # IUserManagement implementation
    #

    security.declarePrivate('doChangeUser')
    @graceful_recovery()
    def doChangeUser(self, login, password, **kw):
        # userSetPassword in PlonePAS expects a RuntimeError when a
        # plugin doesn't hold the user.
        query = Session.query(self.user_class).filter_by(login=login)
        user = query.first()
        if user is None:
            raise RuntimeError("User does not exist: login=%s" % login)
        user.set_password(password)

    security.declarePrivate('doDeleteUser')
    @graceful_recovery()
    def doDeleteUser(self, login):
        session = Session()
        query = session.query(self.user_class).filter_by(login=login)
        user = query.first()
        if user is None:
            return False

        session.delete(user)
        return True

    #
    # IPasswordSetCapability implementation
    #
    @graceful_recovery(False)
    def allowPasswordSet(self, userid):
        session = Session()
        user = session.query(self.user_class).filter_by(zope_id=id).first()
        if user is not None:
            return True
        return False

    #
    # IAuthenticationPlugin implementation
    #

    security.declarePrivate('authenticateCredentials')
    @graceful_recovery(log_args=False)
    def authenticateCredentials(self, credentials):
        login = credentials.get('login')
        password = credentials.get('password')

        if not login or not password:
            return None

        session = Session()
        user = session.query(model.User).filter_by(login=login).first()

        if user is not None and user.check_password(password):
            return (user.zope_id, user.login)

    #
    # IUserEnumerationPlugin implementation
    #
    security.declarePrivate('enumerateUsers')
    @graceful_recovery(())
    def enumerateUsers(self, id=None, login=None, exact_match=False,
                       sort_by=None, max_results=None, **kw):
        """See IUserEnumerationPlugin."""

        session = Session()
        view_name = createViewName('enumerateUsers', id or login)

        if not (id or login):
            return ()

        keywords = {}
        if id:
            keywords["zope_id"] = login
        if login:
            keywords["login"] = login

        for (term,value) in kw.items():
            if term not in self.user_class._properties:
                return ()
            keywords[term] = value

        cachekey = {
            '_exact_match': exact_match,
            '_sort_by': sort_by,
            '_max_results': max_results,
        }
        cachekey.update(keywords)
        cached_info = self.ZCacheable_get(
            view_name=view_name, keywords=cachekey)
        if cached_info is not None:
            return cached_info

        query = session.query(self.user_class)
        for (term,value) in keywords.items():
            if exact_match:
                query=query.filter_by(term=value)
            else:
                column=getattr(self.user_class, term)
                if isinstance(value, str):
                    query=query.filter(column.ilike("%%%s%%", value))
                elif isinstance(value, unicode):
                    query=query.filter(column.ilike(u"%%%s%%", value))
                else:
                    query=query.filter_by(term=value)

        all = {}
        for user in query:
            if max_results is not None and len(all) == max_results:
                break

            user_id = user.zope_id
            data = {
                'id': safeencode(user_id),
                'login': safeencode(user.login),
                'pluginid': self.getId(),
            }

            all[user_id] = data.setdefault(user_id, data)

        values = tuple(all.values())

        # Cache data upon success
        self.ZCacheable_set(values, view_name=view_name, keywords=cachekey)

        return values

    #
    # IUserAdderPlugin implementation
    #
    security.declarePrivate('doAddUser')
    def doAddUser(self, login, password):
        try:
            self.addUser(login, login, password)
        except KeyError:
            return False
        return True

    security.declarePrivate('addUser')
    @graceful_recovery(log_args=False)
    def addUser(self, user_id, login_name, password):
        session = Session()
        new_user = self.user_class(zope_id=user_id, login=login_name)
        new_user.set_password(password)
        session.add(new_user)

    security.declarePrivate('removeUser')
    @graceful_recovery()
    def removeUser(self, user_id): # raises keyerror
        session = Session()
        user = session.query(model.User).filter_by(name=user_id).first()
        if user is None:
            raise KeyError(user_id)

        session.delete(user)

   #
    # Allow users to change their own login name and password.
    #
    security.declareProtected(SetOwnPassword, 'getOwnUserInfo')
    def getOwnUserInfo(self):
        """Return current user's info."""

        user_id = getSecurityManager().getUser().getId()
        return self.getUserInfo(user_id)

    def allowRoleAssign(self, prinicipal_id, role_id):
        return True

    def doRemoveRolesToPrincipal(self, roles, principal_id):
        principal = self.getPrincipal(principal_id)
        for role in roles:
            principal.roles.remove(role)

    """ Assign a role to an identified principal
    """

    def assignRolesToPrincipal(self, roles, principal_id, setting=True):
        """Assign a specific set of roles, and only those roles, to a principal.

        o no return value
        o insert and delete roles on the SQL Backend based on the roles
          parameter
        """
        ignored_roles = ('Authenticated', 'Anonymous', 'Owner')
        roles = [role_id for role_id in roles if role_id not in ignored_roles]

        # remove actual roles that are not in the roles parameter
        actual_roles = self.getRolesForPrincipal(principal_id)
        self.doRemoveRolesToPrincipal(
            [role for role in actual_roles if role not in roles], principal_id)

        # insert new roles
        for role in roles:
            if role not in ignored_roles:
                self.doAssignRoleToPrincipal(principal_id, role, _no_cache=True)

        view_name = createViewName('getRolesForPrincipal', principal_id)
        self.ZCacheable_invalidate(view_name)

    def doAssignRoleToPrincipal(self, principal_id, role, _no_cache=False):

        """ Create a principal/role association in a Role Manager

        o Return a Boolean indicating whether the role was assigned or not
        """

        principal = self.getPrincipal(principal_id)
        if principal is None or role in principal.roles:
            return False

        principal.roles.add(role)

        if not _no_cache:
            view_name = createViewName('getRolesForPrincipal', principal_id)
            self.ZCacheable_invalidate(view_name)

        return True

    @graceful_recovery()
    def getPrincipal(self, principal_id):
        session = Session()
        query = session.query(self.principal_class).filter_by(zope_id=principal_id)
        return query.first()


    @graceful_recovery(())
    def getRolesForPrincipal(self, principal, request=None ):

        """ principal -> ( role_1, ... role_N )

        o Return a sequence of role names which the principal has.

        o May assign roles based on values in the REQUEST object, if present.
        """

        principal_id = principal.getId()
        view_name = createViewName('getRolesForPrincipal', principal_id)
        cached_info = self.ZCacheable_get(view_name)
        if cached_info is not None:
            return cached_info

        principal = self.getPrincipal(principal_id)
        if principal is None:
            return ()

        roles = tuple(principal.roles)
        self.ZCacheable_set(roles, view_name)
        return roles


    @graceful_recovery()
    def getPropertiesForUser(self, user, request=None):
        """Get property values for a user or group.
        Returns a dictionary of values or a PropertySheet.
        """

        view_name = createViewName('getPropertiesForUser', user.getId())
        cached_info = self.ZCacheable_get(view_name=view_name)
        if cached_info is not None:
            return MutablePropertySheet(self.id, **cached_info)
        data = None
        session = Session()
        principal = session.query(self.principal_class)\
                .filter_by(zope_id=user.getId()).first()
        if principal is None:
            # XXX: Should we cache a negative result?
            return {}

        for (attr_name, prop_name) in principal._properties:
            data[prop_name] = getattr(principal, attr_name)

        if data:
            self.ZCacheable_set(data, view_name=view_name)
            data.pop('id', None)
            sheet = MutablePropertySheet(self.id, **data)
            return sheet

    #
    # IMutablePropertiesPlugin implementation
    #

    def doSetProperty(self, principal, name, value):
        if name not in principal._properties:
            raise ValueError("Trying to set non-existing property")

        if isinstance(value, DateTime):
            value = datetime.datetime(
                value.year(), value.month(), value.day(),
                value.hour(), value.minute(), value.second())

        # if value is a string, make sure it does not exceed the limit
        # (truncate if necessary--this is better than breaking the
        # application)
        if isinstance(value, basestring):
            value = safedecode(value)
            cspec = getattr(principal.__table__.columns, name).type
            if isinstance(cspec, types.String):
                value = value[:cspec.length]
        setattr(principal, name, value)

    @graceful_recovery()
    def setPropertiesForUser(self, user, propertysheet):
        session = Session()
        principal = session.query(self.principal_class).\
                filter_by(zope_id=user.getId()).first()
        for name, value in propertysheet.propertyItems():
            self.doSetProperty(principal, name, value)

        view_name = createViewName('getPropertiesForUser', user) 
        self.ZCacheable_invalidate(view_name=view_name)

    #
    # IGroupsPlugin implementation
    #

    @graceful_recovery(())
    def getGroupsForPrincipal( self, principal, request=None ):
        """ principal -> ( group_1, ... group_N )

        o Return a sequence of group names to which the principal 
          (either a user or another group) belongs.

        o May assign groups based on values in the REQUEST object, if present
        """

        if isinstance(principal, basestring):
            principal_id = principal
        else:
            principal_id = principal.getId()

        session = Session()
        principal = session.query(self.principal_class)\
                .filter_by(zope_id=principal_id).first()
        if principal is None:
            return ()

        return [group.name for group in principal.groups]

    #
    # IGroupsEnumeration implementation
    #        

    @graceful_recovery(())
    def enumerateGroups( self, id=None
                       , exact_match=False
                       , sort_by=None
                       , max_results=None
                       , **kw
                       ):
        """ -> ( group_info_1, ... group_info_N )

        o Return mappings for groups matching the given criteria.

        o 'id' in combination with 'exact_match' true, will
          return at most one mapping per supplied ID ('id' and 'login'
          may be sequences).

        o If 'exact_match' is False, then 'id' may be treated by
          the plugin as "contains" searches (more complicated searches
          may be supported by some plugins using other keyword arguments).

        o If 'sort_by' is passed, the results will be sorted accordingly.
          known valid values are 'id' (some plugins may support others).

        o If 'max_results' is specified, it must be a positive integer,
          limiting the number of returned mappings.  If unspecified, the
          plugin should return mappings for all groups satisfying the
          criteria.

        o Minimal keys in the returned mappings:

          'id' -- (required) the group ID

          'pluginid' -- (required) the plugin ID (as returned by getId())

          'properties_url' -- (optional) the URL to a page for updating the
                              group's properties.

          'members_url' -- (optional) the URL to a page for updating the
                           principals who belong to the group.

        o Plugin *must* ignore unknown criteria.

        o Plugin may raise ValueError for invalid critera.

        o Insufficiently-specified criteria may have catastrophic
          scaling issues for some implementations.
        """

# XXX Fully integrate this with enumerateUsers
        session = Session()

        if id is None:
            clause = None
        elif isinstance(id, (list, tuple)) and exact_match:
            statements = []
            for i in id:
                statements.append(model.Group.name == i)
            clause = sql.or_( *statements )
        elif isinstance( id, (list, tuple)) and not exact_match:
            clause = sql.or_(*(map(model.Group.name.contains, id)))
        elif not exact_match:
            clause = sql.or_(
                model.Group.name.contains(id),
                model.Group.name.ilike(id))
        else:
            clause = model.Group.name.ilike(id)

        query = session.query(model.Group)

        if clause:
            query = query.filter(clause)
        if sort_by:
            assert sort_by in ('name',)
            column = getattr(model.Group, sort_by)
            query = query.order_by(column)

        if max_results is not None and isinstance(max_results, int):
            query = query.limit(max_results)

        return tuple(
            dict(id=r.name, plugin=self.id) for r in query.all())

    ####################
    # IGroupManagement 
    ####################

    @graceful_recovery(False)
    def addGroup(self, id, **kw):
        """
        Create a group with the supplied id, roles, and groups.
        return True if the operation suceeded
        """

        if self.enumerateGroups(id):
            raise KeyError, 'Duplicate group ID: %s' % id

        group = self.group_class(zope_id=id)
        Session().add(group)

        return True

    @graceful_recovery(False)
    def addPrincipalToGroup(self, principal_id, group_id):
        """
        Add a given principal to the group.
        return True on success
        """

        session = Session()
        group = session.query(self.group_class).filter_by(zope_id=group_id).first()
        if group is None:
            return False

        principal = session.query(self.principal_class)\
                .filter_by(zope_id=principal_id).first()

        if principal is None:
            return False

        group.members.append(principal)
        return True

    #
    #   IDeleteCapability implementation
    #
    @graceful_recovery(False)
    def allowDeletePrincipal(self, principal_id):
        """True if this plugin can delete a certain group."""

        return self.getPrincipal(principal_id) is not None

    #
    #   IGroupCapability implementation
    #

    @graceful_recovery(False)
    def allowGroupAdd(self, user_id, group_id):
        """True if this plugin will allow adding a certain user to a
        certain group."""

        session = Session()
        group = session.query(self.group_class).filter_by(zope_id=group_id).first()
        if group is None:
            return False

        if user_id in [member.zope_id for member in group.members]:
            return False

        return True


    @graceful_recovery(False)
    def allowGroupRemove(self, user_id, group_id):
        """True if this plugin will allow removing a certain user from
        a certain group."""

        present = self.enumerateGroups(id=group_id)

        # if we don't have a group, we can't do anything
        if not present:
            return False

        groups = self.getGroupsForPrincipal(user_id)
        if group_id in groups:
            return True

        return False


    @graceful_recovery(False)
    def removeGroup(self, group_id):
        """
        Remove the given group
        return True on success
        """

        session = Session()
        group = session.query(self.group_class).filter_by(zope_id=group_id).first()
        if group is not None:
            session.delete(group)
            return True

        return False

    @graceful_recovery(False)
    def removePrincipalFromGroup(self, principal_id, group_id):
        """
        Remove the given principal from the group; return True on success.
        """

        session = Session()

        group = session.query(self.group_class)\
                .filter_by(zope_id=group_id).first()
        user = session.query(self.principal_class)\
                .filter_by(zope_id=principal_id).first()

        if group is None or user is None:
            return False

        group.members.remove(user)
        return True

    ###########################
    # IGroupIntrospection
    ###########################

    @graceful_recovery(None)
    def getGroupById(self, group_id):
        """
        Returns the portal_groupdata-ish object for a group
        corresponding to this id.
        """

        if group_id and self.enumerateGroups(group_id):
            group = PloneGroup(group_id, None)
            plugins = self._getPAS()._getOb('plugins')
            propfinders = plugins.listPlugins(IPropertiesPlugin)
            for propfinder_id, propfinder in propfinders:

                data = propfinder.getPropertiesForUser(group, request=None)
                if data:
                    group.addPropertysheet(propfinder_id, data)

            groups = self._getPAS()._getGroupsForPrincipal(
                group, request=None, plugins=plugins)
            group._addGroups(groups)

            rolemakers = plugins.listPlugins(IRolesPlugin)

            for rolemaker_id, rolemaker in rolemakers:
                roles = rolemaker.getRolesForPrincipal(group, request=None)
                if roles:
                    group._addRoles(roles)

            group._addRoles(['Authenticated'])

            return group.__of__(self)
        else:
            return None

    #################################
    # these interface methods are suspect for scalability.
    #################################

    @graceful_recovery(())
    def getGroups( self ):
        """
        Returns an iteration of the available groups
        """

        session = Session()
        groups = session.query(self.group_class).all()
        return [PloneGroup(g.name).__of__(self) for g in groups]

    @graceful_recovery(())
    def getGroupIds( self ):
        """
        Returns a list of the available groups
        """

        session = Session()
        return [row[0] for row in session.query(self.group_class.zope_id.name).all()]

    @graceful_recovery(())
    def getGroupMembers(self, group_id):
        """
        Return the members of the given group
        """

        session = Session()
        group = session.query(self.group_class).filter_by(zope_id=group_id).first()
        if group is None:
            return []
        return [member.zope_id for member in group.membres]


    # PlonePAS expects plugins implementing IRoleAssignerPlugin to
    # implement addRole. (In addRole in pas).  The method is not
    # specified in the IRoleAssignerPlugin interface, so this is bad.

    security.declareProtected( ManageUsers, 'addRole' )
    def addRole( self, role_id, title='', description='' ):

        """ We do not manage roles.
        """
        raise AttributeError


classImplements(
    Plugin,
    IAuthenticationPlugin,
    IUserEnumerationPlugin,
    IUserAdderPlugin,
    IUserManagement,
    IDeleteCapability,
    IPasswordSetCapability,
    IRolesPlugin,
    IRoleAssignerPlugin,
    IAssignRoleCapability,
    IPropertiesPlugin,
    IMutablePropertiesPlugin,
    IGroupsPlugin,
    IGroupEnumerationPlugin,
    IGroupIntrospection,
    IGroupManagement)

InitializeClass(Plugin)
