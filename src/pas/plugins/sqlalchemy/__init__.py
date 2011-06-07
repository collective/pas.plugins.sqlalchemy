
# Used by UsersOverviewControlPanel.doSearch()
from Acquisition import aq_inner
from itertools import chain
from zope.component import getMultiAdapter
from Products.CMFPlone.utils import normalizeString
from Products.CMFCore.utils import getToolByName
from Products.PluggableAuthService.interfaces.plugins import IRolesPlugin

import logging
logger = logging.getLogger('pas.plugins.sqlalchemy')

plugins = set()

def initialize(context):
    from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
    from Products.PluggableAuthService.PluggableAuthService import MultiPlugins

    import plugin

    if plugin.Plugin.meta_type not in MultiPlugins:
        registerMultiPlugin(plugin.Plugin.meta_type)

    # Start monkeypatching UsersOverviewControlPanel.doSearch()
    try:
        from plone.app.controlpanel.usergroups import UsersOverviewControlPanel
        from pas.plugins.sqlalchemy.plugin import MAX_RESULTS
    except ImportError, e:
        logger.warn("could not monkeypatch UserOverviewControlPanel: %s" % e)
    else:

        # Just display a simple message if the number of
        # users == MAX_RESULTS
        def doSearch(self, searchString):
            acl = getToolByName(self, 'acl_users')
            rolemakers = acl.plugins.listPlugins(IRolesPlugin)

            mtool = getToolByName(self, 'portal_membership')

            searchView = getMultiAdapter((aq_inner(self.context), self.request), name='pas_search')

            # First, search for all inherited roles assigned to each group.
            # We push this in the request so that IRoles plugins are told provide
            # the roles inherited from the groups to which the principal belongs.
            self.request.set('__ignore_group_roles__', False)
            self.request.set('__ignore_direct_roles__', True)
            inheritance_enabled_users = searchView.merge(chain(*[searchView.searchUsers(**{field: searchString}) for field in ['login', 'fullname', 'email']]), 'userid')
            allInheritedRoles = {}
            for user_info in inheritance_enabled_users:
                userId = user_info['id']
                user = acl.getUserById(userId)
                # play safe, though this should never happen
                if user is None:
                    logger.warn('Skipped user without principal object: %s' % userId)
                    continue
                allAssignedRoles = []
                for rolemaker_id, rolemaker in rolemakers:
                    allAssignedRoles.extend(rolemaker.getRolesForPrincipal(user))
                allInheritedRoles[userId] = allAssignedRoles

            # We push this in the request such IRoles plugins don't provide
            # the roles from the groups the principal belongs.
            self.request.set('__ignore_group_roles__', True)
            self.request.set('__ignore_direct_roles__', False)
            explicit_users = searchView.merge(chain(*[searchView.searchUsers(**{field: searchString}) for field in ['login', 'fullname', 'email']]), 'userid')

            # Tack on some extra data, including whether each role is explicitly
            # assigned ('explicit'), inherited ('inherited'), or not assigned at all (None).
            results = []
            for user_info in explicit_users:
                userId = user_info['id']
                user = mtool.getMemberById(userId)
                # play safe, though this should never happen
                if user is None:
                    logger.warn('Skipped user without principal object: %s' % userId)
                    continue
                explicitlyAssignedRoles = []
                for rolemaker_id, rolemaker in rolemakers:
                    explicitlyAssignedRoles.extend(rolemaker.getRolesForPrincipal(user))

                roleList = {}
                for role in self.portal_roles:
                    roleList[role]={'canAssign': user.canAssignRole(role),
                                    'explicit': role in explicitlyAssignedRoles,
                                    'inherited': role in allInheritedRoles[userId]}

                user_info['roles'] = roleList
                user_info['fullname'] = user.getProperty('fullname', '')
                user_info['email'] = user.getProperty('email', '')
                user_info['can_delete'] = user.canDelete()
                user_info['can_set_email'] = user.canWriteProperty('email')
                user_info['can_set_password'] = user.canPasswordSet()
                results.append(user_info)

            # Sort the users by fullname
            results.sort(key=lambda x: x is not None and x['fullname'] is not None and normalizeString(x['fullname']) or '')

            # Reset the request variable, just in case.
            self.request.set('__ignore_group_roles__', False)

            # Display a message asking the user to refine the search
            # string.
            putils = getToolByName(self, 'plone_utils')
            if len(results) == MAX_RESULTS:
                putils.addPortalMessage(
                    "Limited results to %d. " % MAX_RESULTS +
                    "Please refine your search.",
                    'warning'
                )

            return results

        UsersOverviewControlPanel.doSearch = doSearch
        logger.info(
            "monkeypatched UsersOverviewControlPanel."
            " @@usergroup-userprefs shall now display a warning message if the"
            " number of results returned is equal to %d" % MAX_RESULTS
        )
