Changelog
=========

0.4 (unreleased)
------------------

- fix: ``getPropertiesForUser`` uses principals ``_properties`` mapping now
  to map to the column used for ``zope_id`` id this is needed.
  [jensens]

- do not expect a configured database connection on plugin install time in
  order to play nice with collective.saconnect. Also be less verbose if there
  is no connection configured.
  [jensens]

- fix: different custom setup un-/install marker for install and uninstall
  [jensens]

- Standardize name of installation profile to ``default``.
  [jensens]

- modernized: Pep8, Travis CI, ...
  [jensens]

- using _get_principal_by_id to get principal in doChangeUser,
  doDeleteUser, and allowPasswordSet methods
  [gborelli]

- using '__mapper__' instead of '__table__' to check Column type.
  It allows to customize user model in another class with
  polymorphic_identity
  [gborelli]

- fixed getPropertiesForUser, return None if principal doesn't exist
  [gborelli]

- check if principal exists before updating its properties
  [gborelli]

- Fixed methods ``doSetProperty`` and ``setPropertiesForUser`` such
  that they accept a generic principal and not necessarily an instance
  of the plugin's principal class.
  [malthe]

- Wrap user properties in an actually mutable user property sheet
  (which writes changes back to the plugin). Previously, a mutable
  property sheet was returned, but this is incorrect since changes
  aren't persisted.

  While the PAS interface specifies that a dict should be returned for
  an immutable result, we opt for a hybrid: a dict-aware user property
  sheet which does not promise mutability. The motivation is that the
  pluggable authentication service only supports a select list of
  property value types and not, for instance, Python's own date and
  time classes. By returning a property sheet, we can provide a schema
  explicitly and not force the authentication service to "guess"
  (infer) it.
  [malthe]

0.3 (2011-10-13)
----------------

- Fire `IPropertiesUpdated` (from PAS) event on `setPropertiesForUser`
  to allow components to take action when user properties are updated.
  [malthe]

- Merged SVN repository (select branches) into the existing Github
  repository to consolidate improvements.
  [malthe]

- Add title and description to groups.

  GetRolesForPrincipal needs to listen to __ignore_group_roles__ and
  __ignore_direct_roles__ from the request to work with plone 4.
  GetRolesForPrincipal needs to take group roles into account as
  default.
  [sunew]

- Merged many changes from the branches: wichert-flexible,
  wichert-flexible-pw-encryption, zedr-mysql-optimized, auspex.

  Version 0.3 is not compatible with the earlier versions, upgrading
  will require some migration (not included).
  [sunew]

- Seperate user_id and login - as in PAS. (Not complete?)
  [wichert]

- Refactor user, group, and principal classes to enable more sharing
  of functionality between groups and users.
  [wichert]

- Length of varchars to be compatible with MySQL
  [auspex, wichert, sunew, zedr]

- Cleaned up the properties - only the plone properties are in the
  model now. Override the model if you need more fields.
  [sunew]

- Password and salt readonly.
  [wichert, sunew]

- remove IUpdatePlugin related stuff. Not used.
  [wichert]

- Make models configurable via dotted path zmi properties.
  [wichert]

- Also make the Principal class configurable.
  [sunew]

- Add missing security declarations (match those for the same methods
  in PlonePAS and PluggableAuthService).
  [sunew]

- Fully implement IRoleAssignerPlugin: missed doRemoveRoleFromPrincipal.
  [sunew]

- More tests, tests pass for plone 4.0.7.
  [sunew]


0.2.1 (unreleased)
------------------------

- Fixed some tests. Now tests passes on plone 4.0.7.
  [sunew]

- Convert to and from UTF-8 and unicode. Plone uses UTF-8 internally
  and most Python deployments will coerce using the 'ascii' codec,
  resulting in unicode decode errors. [mborch]

0.2 (released 2009/7/17)
------------------------

- Changed the 'listed' and 'ext_editor' column type to 'Integer' match
  the Plone model. [seletz]

0.1 (released 2009/7/17)
------------------------

- Initial public release.
