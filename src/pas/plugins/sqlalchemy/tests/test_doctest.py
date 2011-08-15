import unittest
import doctest

from zope.testing import doctestunit
from zope.component import testing, eventtesting

from Testing import ZopeTestCase as ztc

from pas.plugins.sqlalchemy.tests import basetestcase

try: 
    # Plone 4 and higher 
    import plone.app.upgrade 
    HAS_PLONE4 = True
except ImportError: 
    HAS_PLONE4 = False

def test_suite():
    if not HAS_PLONE4:
        return unittest.TestSuite([])

    return unittest.TestSuite([
        ztc.ZopeDocFileSuite(
            'rolemanager.txt', package='pas.plugins.sqlalchemy',
            test_class=basetestcase.BaseFunctionalTestCase,
            optionflags=doctest.REPORT_ONLY_FIRST_FAILURE |
                    doctest.NORMALIZE_WHITESPACE | doctest.ELLIPSIS),
        ])
