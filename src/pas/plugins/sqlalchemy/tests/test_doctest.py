import unittest
import doctest

from zope.testing import doctestunit
from zope.component import testing, eventtesting

from Testing import ZopeTestCase as ztc

from pas.plugins.sqlalchemy.tests import basetestcase

def test_suite():
    return unittest.TestSuite([
        ztc.ZopeDocFileSuite(
            'rolemanager.txt', package='pas.plugins.sqlalchemy',
            test_class=basetestcase.BaseFunctionalTestCase,
            optionflags=doctest.REPORT_ONLY_FIRST_FAILURE |
                    doctest.NORMALIZE_WHITESPACE | doctest.ELLIPSIS),
        ])
