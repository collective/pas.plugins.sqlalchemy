# -*- coding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup
import os


def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()

requires = [
    'DateTime>=2.11',
    'Plone',
    'setuptools',
    'SQLAlchemy',
    'z3c.saconfig',
    'zope.sqlalchemy',
    'Products.PlonePAS>=5.0.1',
    ]

tests_requires = requires + ['pysqlite', ]

setup(
    name='pas.plugins.sqlalchemy',
    version='0.5.dev0',
    description="Plone SQLAlchemy-based PAS user/group/prop store.",
    long_description=read("README.rst") + '\n\n' + read("CHANGES.rst"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Framework :: Zope2",
        "Framework :: Plone",
        "Framework :: Plone :: 4.3",
        "Framework :: Plone :: 5.0",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
    ],
    author='Malthe Borch and Stefan Eletzhofer',
    author_email="product-developers@lists.plone.org",
    url='https://github.com/collective/pas.plugins.sqlalchemy',
    license="GNU GPL v2",
    keywords='web pas plone',
    package_dir={'': 'src'},
    packages=find_packages("src"),
    include_package_data=True,
    namespace_packages=['pas', 'pas.plugins'],
    zip_safe=False,
    install_requires=requires,
    extras_require={
        'test': tests_requires,
    },
    tests_require=tests_requires,
    test_suite="pas.plugins.sqlalchemy",
    entry_points="""
    # -*- entry_points -*-
    [z3c.autoinclude.plugin]
    target = plone
    """
)
