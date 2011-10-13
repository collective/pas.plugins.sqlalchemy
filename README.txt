SQLAlchemy PAS plugin
=====================

This package provides a Zope 2 PAS plugin implementation (Pluggable
Authentication Service) based on the SQLAlchemy database abstraction
layer.

It allows you to store and query users and groups using a SQL
database.

This package replaces the `SQLPASPlugin
<http://plone.org/products/sqlpasplugin>`_ product and is technically
a fork of that codebase. Some tests have been rewritten but most are
preserved.

Although not currently provided in a stable release, it's used in
production (tested against the `pysqlite` and PostgreSQL databases
only).

Setup
-----

To configure the plugin with a database, use ``z3c.saconfig`` and
define a named scoped session "pas.plugins.sqlalchemy" in your
configure.zcml or in the "zcml-additional" parameter of the
plone.recipe.zope2instance recipe in your buildout.

Example::

  <configure xmlns="http://namespaces.zope.org/db">
    <include package="z3c.saconfig" file="meta.zcml"/>

    <engine name="pas" url="postgresql://localhost/pas" />
    <session name="pas.plugins.sqlalchemy" engine="pas" />

  </configure>

Install the plugin using the included GenericSetup-profile. Note that
tables will be created automatically on installation.

You can reinstall anytime to create non-existing tables. Note that
tables are preserved on uninstallation.

Configuration from Plone
-------------------------

As an alternative to specifying the database connection information in
zcml, you can use `collective.saconnect
<http://pypi.python.org/pypi/collective.saconnect>`_ to make your
connections configurable on the plone control panel.

Install the package by adding it to your buildout, then install the
add-on it in your plone site through Plone's control panel. You now
have a new control panel that allows you to create and edit database
connections.

To add connections with generic setup add a file "saconnections.xml"
to the generic setup profile of your site setup package, with the
following content::

  <?xml version="1.0"?>
  <connections>
       <connection
            name="pas.plugins.sqlalchemy"
            string="postgresql://USER:PASSWORD@localhost/DATABASE"
       />
  </connections>

More information is available in the package description.


Custom principal, user and group model
--------------------------------------

You can register your own SQLAlchemy-based model class for all three
categories.

The required class interfaces (required methods and attributes) are
described in the ``interfaces`` module. Note that you can simply
subclass from the default models which implement the required
interfaces.

The settings are accessible in the ZMI. You can also use a custom
setup handler.

Example::

    def setup_pas_plugin(self):
        pas = self.acl_users
        plugin = pas['sql']

        plugin.manage_changeProperties(
           user_model="my_package.model.User",
           principal_model="my_package.model.Principal",
           group_model="my_package.model.Group"
           )

You may need to make sure the plugins are prioritized higher than the
default ones (typically ZODB-based).


Wishlist
--------

These items are on the to-do list:

- Post-only security.

- Review of implemented interfaces - is the implementation complete?

- Handle groups title, description and email, to match newer versions
  of Plone.

- Tests for configuration of external model.


Credits
-------

Authors

  - Rocky Burt <rocky@serverzen.com> of ServerZen Software

  - Nate Aune <natea@jazkarta.com> of Jazkarta

  - Stefan Eletzhofer <stefan.eletzhofer@inquant.de> of InQuant

  - Malthe Borch <mborch@gmail.com>

Contributors

  - Ruda Porto Filgueiras <rudazz@gmail.com>

  - Daniel Nouri <daniel.nouri@gmail.com>

  - Dorneles Treméa <deo@jarn.com> of Jarn

  - Wichert Akkerman <wichert@wiggy.net> of Simplon

  - Riccardo Lemmi <riccardo@reflab.it> of Reflab Srl

  - Derek Broughton <auspex@pointerstop.ca>

  - Rigel Di Scala <zedr>

  - Sune Broendum Woeller <woeller@headnet.dk> of Headnet Aps

Sponsors

  - Thanks to ChemIndustry.com Inc. for financing the development of
    SQLPASPlugin

  - Thanks to Statens Byggeforskninginstitut (http://www.sbi.dk) for sponsoring
    the caching support.

  - Thanks to Gis & Web S.r.l. (http://www.gisweb.it) for sponsoring
    the groups management support.

  - Thanks to the Ocean Tracking Network
    (http://oceantrackingnetwork.org/) for adding Group Capabilities
    and migration of existing users.

License
-------

  GNU GPL v2 (see LICENCE.txt for details)
