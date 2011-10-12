# -*- encoding: utf-8 -*-
# tests from sqlpasplugin ( GPL v2 )

from pas.plugins.sqlalchemy.tests import basetestcase
from pas.plugins.sqlalchemy.setuphandlers import plugin_name

from Products.PluggableAuthService.utils import createViewName
from Products.PlonePAS.sheet import MutablePropertySheet

_marker = []

from pas.plugins.sqlalchemy.tests.basetestcase import TrivialUser

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
            set(['fullname', 'email', 'login_time' ]).issubset(
                set(propmap)))

        self.assertEqual(propmap['login_time'],
                {'type': 'date', 'id': 'login_time', 'mode': ''})
        self.assertEqual(propmap['fullname'],
                {'type': 'string', 'id': 'fullname', 'mode': ''})
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
        self.assertEqual(props.getProperty("fullname"), "")

    def testPropertyLoadedFromSQL(self):
        value = 'snakes in a train'
        self.source_properties.setPropertiesForUser(
            self.user, MutablePropertySheet("memberdata", fullname=value))
        props = self.source_properties.getPropertiesForUser(self.user)
        self.assertEqual(props.getProperty("fullname"), value)

    def testSetPropertiesForUser(self):
        props = self.source_properties.getPropertiesForUser(self.user)
        self.assertEqual(props.getProperty('fullname'), u'')
        self.assertEqual(props.getProperty('email'), u'')
        # The plugin should (at least in plone 4) return what it is given - this is the behaviour
        # of the PlonePAS property plugin. If it is unicode, it will later be converted to utf-8.
        # (In PlonePAS/plugins/ufactory.py(220)getProperty())
        info = {
            'fullname': u'J\xfcrgen Schmoe',
            'email': 'joe@localhost.localdomain'
        }
        sheet = MutablePropertySheet("memberdata", **info)
        self.source_properties.setPropertiesForUser(self.user, sheet)
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
        info = {
            'fullname': u'Jane Doe',
        }
        sheet = MutablePropertySheet("memberdata", **info)
        self.plugin.setPropertiesForUser(self.user, sheet)

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
