
# tests from sqlpasplugin ( GPL v2 )

from pas.plugins.sqlalchemy.tests import basetestcase
from pas.plugins.sqlalchemy.setuphandlers import plugin_name

from Products.PluggableAuthService.utils import createViewName

from pas.plugins.sqlalchemy.tests.basetestcase import TrivialUser

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
        self.assertTrue('First' in result)

        self.plugin.doAssignRoleToPrincipal('User1', 'Second')
        result = self.plugin.getRolesForPrincipal("User1")
        self.assertEqual(len(result), 2)
        # the order does not matter:
        self.assertTrue('First' in result)
        self.assertTrue('Second' in result)

        self.plugin.doAssignRoleToPrincipal('User2', 'Third')
        result = self.plugin.getRolesForPrincipal("User1")
        self.assertEqual(len(result), 2)
        self.assertTrue('First' in result)
        self.assertTrue('Second' in result)

        result = self.plugin.getRolesForPrincipal("User2")
        self.assertEqual(len(result), 1)
        self.assertTrue('Third' in result)

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

    def testDoRemoveRoleFromPrincipal(self):
        self.plugin.doAddUser("User1", self.password)
        self.plugin.doAddUser("User2", self.password)

        roles = self.plugin.getRolesForPrincipal('User1')
        self.assertEqual(roles, ())

        self.plugin.assignRolesToPrincipal(('First', 'Second',), 'User1')
        roles = self.plugin.getRolesForPrincipal('User1')
        self.assertTrue('First' in roles)
        self.assertTrue('Second' in roles)

        self.plugin.assignRolesToPrincipal(('First', 'Second',), 'User2')
        roles = self.plugin.getRolesForPrincipal('User2')
        self.assertTrue('First' in roles)
        self.assertTrue('Second' in roles)

        return_value = self.plugin.doRemoveRoleFromPrincipal('User1', 'First')
        self.assertTrue(return_value)
        
        roles = self.plugin.getRolesForPrincipal('User1')
        self.assertEqual(roles, ('Second',))
        roles = self.plugin.getRolesForPrincipal('User2')
        self.assertTrue('First' in roles)
        self.assertTrue('Second' in roles)
        
        return_value = self.plugin.doRemoveRoleFromPrincipal('User1', 'NotThere')
        self.assertTrue(not return_value)
        


class TestRoleCaching(basetestcase.CacheTestCase):
    def afterSetUp(self):
        basetestcase.CacheTestCase.afterSetUp(self)
        self.plugin = self.getPAS()[plugin_name]
        self.plugin.ZCacheable_setManagerId(basetestcase.CACHE_MANAGER_ID)

    def testIsCacheEnabled(self):
        self.failUnless(self.plugin.ZCacheable_isCachingEnabled())

    def testCacheStartsEmpty(self):
        view_name = createViewName('getRolesForPrincipal-IgnDirFalse-IgnGrpFalse', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)

        self.failUnless(user is _marker)

    def testSingleQuery(self):
        user=TrivialUser(self.username)
        self.plugin.getRolesForPrincipal(user)
        view_name = createViewName('getRolesForPrincipal-IgnDirFalse-IgnGrpFalse', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

    def testTwoQueres(self):
        user=TrivialUser(self.username)
        self.plugin.getRolesForPrincipal(user)
        self.plugin.doAddUser("User1", self.password)
        user1=TrivialUser("User1")
        self.plugin.getRolesForPrincipal(user1)

        view_name = createViewName('getRolesForPrincipal-IgnDirFalse-IgnGrpFalse', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

        view_name = createViewName('getRolesForPrincipal-IgnDirFalse-IgnGrpFalse', 'User1')
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

    def testAssignRoleZapsCache(self):
        user=TrivialUser(self.username)
        self.plugin.getRolesForPrincipal(user)
        self.plugin.doAssignRoleToPrincipal(self.username, 'henchman')
        view_name = createViewName('getRolesForPrincipal-IgnDirFalse-IgnGrpFalse', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is _marker)

    def testAssignRoleKeepsCacheIfToldSo(self):
        user=TrivialUser(self.username)
        self.plugin.getRolesForPrincipal(user)
        self.plugin.doAssignRoleToPrincipal(self.username, 'henchman', False)
        view_name = createViewName('getRolesForPrincipal-IgnDirFalse-IgnGrpFalse', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

    def testAssignRolesZapsCache(self):
        user=TrivialUser(self.username)
        self.plugin.getRolesForPrincipal(user)
        self.plugin.assignRolesToPrincipal(('henchman',), self.username)
        view_name = createViewName('getRolesForPrincipal-IgnDirFalse-IgnGrpFalse', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is _marker)

    def testDoRemoveRoleFromPrincipalZapsCache(self):
        self.plugin.doAddUser("User1", self.password)

        self.plugin.assignRolesToPrincipal(('First', 'Second',), 'User1')
        roles = self.plugin.getRolesForPrincipal('User1')
        self.assertTrue('First' in roles)
        self.assertTrue('Second' in roles)

        view_name = createViewName('getRolesForPrincipal-IgnDirFalse-IgnGrpFalse', 'User1')
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

        self.plugin.doRemoveRoleFromPrincipal('User1', 'First')
        
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is _marker)


def test_suite():
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(TestRoleManager))
    suite.addTest(makeSuite(TestRoleCaching))
    return suite
