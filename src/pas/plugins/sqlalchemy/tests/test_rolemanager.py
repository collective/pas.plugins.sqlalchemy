
# tests from sqlpasplugin ( GPL v2 )

from pas.plugins.sqlalchemy.tests import basetestcase
from pas.plugins.sqlalchemy.setuphandlers import plugin_name

from Products.PluggableAuthService.utils import createViewName

_marker = []

class TestRoleManager(basetestcase.BaseTestCase):

    def afterSetUp(self):
        self.username = 'joe'
        self.password = 'password'
        self.plugin = self.getPAS()[plugin_name]

    def testDoAssignRoleToPrincipal(self):
        # add a user
        self.plugin.doAddUser(self.username, self.password)
        self.plugin.doAddUser("User1", self.password)
        self.plugin.doAddUser("User2", self.password)

        self.plugin.doAssignRoleToPrincipal(self.username, "Manager")

        result = self.plugin.getRolesForPrincipal("User1")
        self.assertEqual(len(result), 0)

        self.plugin.doAssignRoleToPrincipal('User1', 'First')
        result = self.plugin.getRolesForPrincipal("User1")
        self.assertEqual(len(result), 1)
        self.assertEqual(tuple(result), ('First',))

        self.plugin.doAssignRoleToPrincipal('User1', 'Second')
        result = self.plugin.getRolesForPrincipal("User1")
        self.assertEqual(len(result), 2)
        self.assertTrue('First' in result)
        self.assertTrue('Second' in result)

        self.plugin.doAssignRoleToPrincipal('User2', 'Third')
        result = self.plugin.getRolesForPrincipal("User1")
        self.assertEqual(len(result), 2)
        self.assertTrue('First' in result)
        self.assertTrue('Second' in result)

        result = self.plugin.getRolesForPrincipal("User2")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 'Third')

    def testGetRolesForPrincipal(self):
        self.plugin.doAddUser("User1", self.password)
        self.plugin.doAddUser("User2", self.password)

        roles = self.plugin.getRolesForPrincipal('User1')
        self.assertEqual(roles, ())

        self.plugin.assignRolesToPrincipal(('First',), 'User1')
        roles = self.plugin.getRolesForPrincipal('User1')
        self.assertEqual(roles, ('First',))

        self.plugin.assignRolesToPrincipal(('First', 'Second',), 'User1')
        roles = self.plugin.getRolesForPrincipal('User1')
        self.assertTrue('First' in roles)
        self.assertTrue('Second' in roles)

        self.plugin.assignRolesToPrincipal(('Third',), 'User2')
        roles = self.plugin.getRolesForPrincipal('User1')
        self.assertTrue('First' in roles)
        self.assertTrue('Second' in roles)
        roles = self.plugin.getRolesForPrincipal('User2')
        self.assertEqual(roles, ('Third',))

class TestRoleCaching(basetestcase.CacheTestCase):
    def afterSetUp(self):
        basetestcase.CacheTestCase.afterSetUp(self)
        self.plugin = self.getPAS()[plugin_name]
        self.plugin.ZCacheable_setManagerId(basetestcase.CACHE_MANAGER_ID)

    def testIsCacheEnabled(self):
        self.failUnless(self.plugin.ZCacheable_isCachingEnabled())

    def testCacheStartsEmpty(self):
        view_name = createViewName('getRolesForPrincipal', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)

        self.failUnless(user is _marker)

    def testSingleQuery(self):
        self.plugin.getRolesForPrincipal(self.username)
        view_name = createViewName('getRolesForPrincipal', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

    def testTwoQueres(self):
        self.plugin.getRolesForPrincipal(self.username)
        self.plugin.doAddUser("User1", self.password)
        self.plugin.getRolesForPrincipal('User1')

        view_name = createViewName('getRolesForPrincipal', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

        view_name = createViewName('getRolesForPrincipal', 'User1')
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

    def testAssignRoleZapsCache(self):
        self.plugin.getRolesForPrincipal(self.username)
        self.plugin.doAssignRoleToPrincipal(self.username, 'henchman')
        view_name = createViewName('getRolesForPrincipal', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is _marker)

    def testAssignRoleKeepsCacheIfToldSo(self):
        self.plugin.getRolesForPrincipal(self.username)
        self.plugin.doAssignRoleToPrincipal(self.username, 'henchman', True)
        view_name = createViewName('getRolesForPrincipal', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

    def testAssignRolesZapsCache(self):
        self.plugin.getRolesForPrincipal(self.username)
        self.plugin.assignRolesToPrincipal(('henchman',), self.username)
        view_name = createViewName('getRolesForPrincipal', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is _marker)

class TestRolesInheritedFromGroups(basetestcase.BaseTestCase):
    def afterSetUp(self):
        basetestcase.BaseTestCase.afterSetUp(self)
        self.plugin = self.getPAS()[plugin_name]
        # add a user and groups 
        self.plugin.doAddUser("User1", self.password)
        self.plugin.doAddUser("User2", self.password)
        self.plugin.addGroup("Group1")
        self.plugin.addGroup("Group2")
        
        # add users to groups
        self.plugin.addPrincipalToGroup("User1", "Group1")
        self.plugin.addPrincipalToGroup("User2", "Group2")

        # add roles to users and groups
        self.plugin.doAssignRoleToPrincipal("User1", "Manager")
        self.plugin.doAssignRoleToPrincipal("User2", "Owner")
        self.plugin.doAssignRoleToPrincipal("Group2", "Manager")
        self.plugin.doAssignRoleToPrincipal("Group1", "Owner")

    def testGetRolesForUsers(self):
        """Verify if getRolesForPrincial also return roles 
        inherited by group membership.
        """
        roles = self.plugin.getRolesForPrincipal("User1")
        self.assertEqual(len(roles), 2)
        self.assertEqual(roles, ('Owner','Manager'))

        roles = self.plugin.getRolesForPrincipal("User2")
        self.assertEqual(len(roles), 2)
        self.assertEqual(roles, ('Owner','Manager'))

    def testGetRolesForGroups(self):
        """Verify direct roles returned for groups
        """
        roles = self.plugin.getRolesForPrincipal("Group1")
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles, ('Owner',))

        roles = self.plugin.getRolesForPrincipal("Group2")
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles, ('Manager',))

    def testGetRolesOnlyFromUsers(self):
        """Change request object to inform getRolesForPrincipal to return
        only direct roles for a given user principal
        """
        request = dict(__ignore_group_roles__=True)

        roles = self.plugin.getRolesForPrincipal("User1", request)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles, ('Manager',))

        roles = self.plugin.getRolesForPrincipal("User2", request)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles, ('Owner',))

    def testGetRolesOnlyFromGroups(self):
        """Change request object to inform getRolesForPrincipal to return
        only roles inherited from groups for a given user principal
        """
        request = dict(__ignore_direct_roles__=True)

        roles = self.plugin.getRolesForPrincipal("User1", request)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles, ('Owner',))

        roles = self.plugin.getRolesForPrincipal("User2", request)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles, ('Manager',))
 
def test_suite():
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(TestRoleManager))
    suite.addTest(makeSuite(TestRoleCaching))
    suite.addTest(makeSuite(TestRolesInheritedFromGroups))
    return suite
