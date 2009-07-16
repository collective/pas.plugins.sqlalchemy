
# tests from sqlpasplugin ( GPL v2 )

from pas.plugins.sqlalchemy.tests import basetestcase
from pas.plugins.sqlalchemy.setuphandlers import plugin_name

from Products.PluggableAuthService.utils import createViewName
from Products.PlonePAS.sheet import MutablePropertySheet

_marker = []

class TrivialUser:
    def __init__(self, id):
        self.id=id
    def getUserName(self):
        return self.id
    def isGroup(self):
        return False


class TestPropertyProvider(basetestcase.BaseTestCase):

    def afterSetUp(self):
        basetestcase.BaseTestCase.afterSetUp(self)
        self.source_users = self.getPAS()[plugin_name]
        self.source_properties = self.getPAS()[plugin_name]
        self.user=TrivialUser(self.username)
        self.source_users.doAddUser(self.username, self.password)

    def testPropertiesDetected(self):
        props = self.source_properties.getPropertiesForUser(self.user)
        propmap = dict([(p['id'], p) for p in props.propertyMap()])
        self.assertTrue(
            set(['firstname', 'lastname', 'email', 'date_created' ]).issubset(
                set(propmap)))

        self.assertEqual(propmap['date_created'],
                {'type': 'date', 'id': 'date_created', 'mode': ''})
        self.assertEqual(propmap['firstname'],
                {'type': 'string', 'id': 'firstname', 'mode': ''})
        self.assertEqual(propmap['lastname'],
                {'type': 'string', 'id': 'lastname', 'mode': ''})
        self.assertEqual(propmap['email'],
                {'type': 'string', 'id': 'email', 'mode': ''})

    def testUsernameAndPasswordNotExposed(self):
        props = self.source_properties.getPropertiesForUser(self.user)

        user_name_column = self.source_properties.getProperty('users_col_username')
        self.failIf(props.hasProperty(user_name_column))

        user_pass_column = self.source_properties.getProperty('users_col_password')
        self.failIf(props.hasProperty(user_pass_column))

    def testPropertyDefaultValue(self):
        props = self.source_properties.getPropertiesForUser(self.user)
        self.assertEqual(props.getProperty("firstname"), "")

    def testPropertyLoadedFromSQL(self):
        value = 'snakes in a train'
        self.source_properties.setPropertiesForUser(
            self.user, MutablePropertySheet("memberdata", firstname=value))
        props = self.source_properties.getPropertiesForUser(self.user)
        self.assertEqual(props.getProperty("firstname"), value)

    def testUpdateUserInfo(self):
        info = {
            'firstname': 'Joe',
            'lastname': 'Schmoe',
            'email': 'joe@localhost.localdomain'
        }
        self.source_properties.updateUserInfo(user=self.user,
                set_id=None, set_info=info)
        props = self.source_properties.getPropertiesForUser(self.user)
        for name, value in info.items():
            self.assertTrue(name in props.propertyIds())
            self.assertEqual(props.getProperty(name), value)

class TestPropertyCaching(basetestcase.CacheTestCase):
    def afterSetUp(self):
        basetestcase.CacheTestCase.afterSetUp(self)
        self.plugin.doAddUser('user_2', 'password')
        self.plugin = self.getPAS()[plugin_name]
        self.plugin.ZCacheable_setManagerId(basetestcase.CACHE_MANAGER_ID)
        self.user=TrivialUser(self.username)
        self.other_user=TrivialUser('user_2')

    def testIsCacheEnabled(self):
        self.failUnless(self.plugin.ZCacheable_isCachingEnabled())

    def testCacheStartsEmpty(self):
        view_name = createViewName('getPropertiesForUser', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                keywords=dict(auth=False),
                default=_marker)
        self.failUnless(user is _marker)

    def testCacheSingleQuery(self):
        props = self.plugin.getPropertiesForUser(self.user)
        view_name = createViewName('getPropertiesForUser', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

    def testCacheTwoQueries(self):
        props = self.plugin.getPropertiesForUser(self.user)
        props = self.plugin.getPropertiesForUser(self.other_user)

        view_name = createViewName('getPropertiesForUser', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

        view_name = createViewName('getPropertiesForUser', 'user_2')
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                default=_marker)
        self.failUnless(user is not _marker)

    def testUpdateZapsCache(self):
        props = self.plugin.getPropertiesForUser(self.user)
        self.plugin.updateUserInfo(self.user, set_id=None,
                set_info=dict(firstname='Jane'))

        view_name = createViewName('getPropertiesForUser', self.username)
        user = self.plugin.ZCacheable_get(
                view_name=view_name,
                keywords=dict(auth=False),
                default=_marker)
        self.failUnless(user is _marker)


def test_suite():
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(TestPropertyProvider))
    suite.addTest(makeSuite(TestPropertyCaching))
    return suite
