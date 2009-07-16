SQLAlchemy PAS plugin
=====================

To configure the plugin with a database, use ``z3c.saconfig`` and
define a named scoped session "pas.plugins.sqlalchemy".

Install plugins using the included GenericSetup profile. Note that
tables will created automatically on installation.

Memberdata
----------

The users table has an extensive number of metadata fields; it's on
the to-do to figure out a nice way to make this pluggable.

History
-------

This package is a fork of the SQLPASPlugin. It uses SQLAlchemy as the
database abstraction layer; some tests have been rewritten but most
are preserved.

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

  - Wichert Akkerman <wichert@jarn.com> of Jarn

  - Riccardo Lemmi <riccardo@reflab.it> of Reflab Srl

Sponsors

  - Thanks to ChemIndustry.com Inc. for financing the development of
    SQLPASPlugin

  - Thanks to Statens Byggeforskninginstitut (http://www.sbi.dk) for sponsoring
    the caching support.

  - Thanks to Gis & Web S.r.l. (http://www.gisweb.it) for sponsoring
    the groups management support.

License
-------

  GNU GPL v2 (see LICENCE.txt for details)
