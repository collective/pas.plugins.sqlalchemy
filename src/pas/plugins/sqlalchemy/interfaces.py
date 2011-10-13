from zope.interface import Interface
from zope.interface import Attribute


class IPasswordAware(Interface):
    def check_password(password):
        """Return ``True`` if password is correct."""

    def set_password(password):
        """Set password on model."""


class IEncryptedPasswordAware(IPasswordAware):
    def encrypt(password):
        """Return encrypted password."""

    def generate_salt():
        """Return a salt string."""


class IUser(Interface):
    zope_id = Attribute(
        """Principal id string."""
        )
