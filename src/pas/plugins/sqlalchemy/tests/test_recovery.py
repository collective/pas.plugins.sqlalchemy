import logging
import unittest

from pas.plugins.sqlalchemy.plugin import graceful_recovery
from pas.plugins.sqlalchemy.plugin import logger
from z3c.saconfig import named_scoped_session

from sqlalchemy import exc

Session = named_scoped_session("pas.plugins.sqlalchemy")

class TestRecovery(unittest.TestCase):
    def testGracefulRecovery(self):
        records = []
        class TestHandler(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = TestHandler()
        logger.addHandler(handler)

        @graceful_recovery(False)
        def raises_sql_exc(msg):
            raise exc.SQLAlchemyError(msg)

        @graceful_recovery(log_args=False)
        def raises_sql_exc_no_args(msg):
            raise exc.SQLAlchemyError(msg)

        value = raises_sql_exc("foo")

        self.assertEqual(value, False)
        self.assertEqual(len(records), 1)
        
        log_message = records[0].getMessage()
        self.assertTrue("raises_sql_exc" in log_message)
        self.assertTrue(repr("foo") in log_message)
        self.assertTrue("Traceback" in log_message)

        value = raises_sql_exc_no_args("bar")
        self.assertEqual(value, None)
        self.assertEqual(len(records), 2)
        
        log_message = records[1].getMessage()
        self.assertTrue("raises_sql_exc_no_args" in log_message)
        self.assertFalse(repr("bar") in log_message)
        self.assertTrue("Traceback" in log_message)

        logger.removeHandler(handler)

def test_suite( ):
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(TestRecovery))
    return suite

