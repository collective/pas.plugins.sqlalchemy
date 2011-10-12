# -*- coding: utf-8 -*-

from Testing import ZopeTestCase
from zope import component
from zope.component import testing

import transaction
import Products.Five

from Products.Five import zcml

#from Products.CMFPlone.tests import PloneTestCase
#from Products.PloneTestCase.layer import PloneSite


ZopeTestCase.installProduct('PlonePAS')
ZopeTestCase.installProduct('PluggableAuthService')
ZopeTestCase.installProduct('StandardCacheManagers')

from Products.PlonePAS.Extensions import Install as ppasinstall

import pas.plugins.sqlalchemy
from pas.plugins.sqlalchemy.setuphandlers import plugin_name

from z3c.saconfig import GloballyScopedSession
from z3c.saconfig.interfaces import IScopedSession
from z3c.saconfig import EngineFactory
from z3c.saconfig import named_scoped_session

Session = named_scoped_session("pas.plugins.sqlalchemy")

TEST_TWOPHASE = False
SANDBOX_ID = 'sandbox'
CACHE_MANAGER_ID = 'cm_test'

class TrivialUser:
    def __init__(self, id):
        self.id=id
    def getId(self):
        return self.id
    def getUserName(self):
        return self.id
    def isGroup(self):
        return False

class SQLLayer:
    @classmethod
    def setUp( cls ):
        from pas.plugins.sqlalchemy.model import Base

        testing.setUp()
        zcml.load_config('meta.zcml', Products.Five)
        zcml.load_config('configure.zcml', pas.plugins.sqlalchemy)

        app = ZopeTestCase.app()

        # Create our sandbox
        app.manage_addFolder(SANDBOX_ID)
        sandbox = app[SANDBOX_ID]

        # Add a cache manager
        factory = sandbox.manage_addProduct['StandardCacheManagers']
        factory.manage_addRAMCacheManager(CACHE_MANAGER_ID)

        # Setup the DB connection and PAS instances
        factory = EngineFactory('sqlite:///:memory:')
        engine = factory()
        Base.metadata.bind = engine
        Base.metadata.create_all(engine)
        cls.pas = cls.setupPAS(sandbox)

        utility = GloballyScopedSession(
                  bind=engine,
                  twophase=TEST_TWOPHASE)

        component.provideUtility(utility, provides=IScopedSession,
                name="pas.plugins.sqlalchemy")

        transaction.commit()
        ZopeTestCase.close(app)

    @classmethod
    def tearDown(cls):
        from pas.plugins.sqlalchemy.model import Base
        session = Session()
        Base.metadata.drop_all()
        testing.tearDown()
        app = ZopeTestCase.app()
        app.manage_delObjects(SANDBOX_ID)
        transaction.commit()
        ZopeTestCase.close(app)

    @classmethod
    def setupPAS(cls, container):
        factory = container.manage_addProduct['PluggableAuthService']
        factory.addPluggableAuthService(REQUEST=None)
        pas = container.acl_users
        ppasinstall.registerPluginTypes(pas)
        from pas.plugins.sqlalchemy import setuphandlers
        setuphandlers.install_pas_plugin( container )
        return pas

class BaseTestCase(ZopeTestCase.ZopeTestCase):
    layer = SQLLayer
    username = u'j\xfcrgen'
    password = 'passw0rd'

    def getPAS( self ):
        return self.layer.pas

    def beforeTearDown( self ):
        session = Session()
        session.close()

class CacheTestCase(BaseTestCase):
    def afterSetUp(self):
        BaseTestCase.afterSetUp(self)
        self.plugin = self.getPAS()[plugin_name]
        self.plugin.ZCacheable_setManagerId(CACHE_MANAGER_ID)
        self.plugin.doAddUser(self.username, self.password)

    def beforeTearDown(self):
        BaseTestCase.beforeTearDown(self)
        self.plugin.ZCacheable_setManagerId(None)


