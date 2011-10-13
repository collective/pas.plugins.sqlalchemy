# -*- coding: utf-8 -*-
#
# File: model.py
#
# Copyright (c) InQuant GmbH
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import random
import string
import datetime

try:
    from hashlib import sha1 as sha
except:
    from sha import sha

from zope.interface import implements

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import functions
from sqlalchemy import Table, Column, Integer, String, Boolean, \
        DateTime
from sqlalchemy import Text, Float, ForeignKey, Sequence
from sqlalchemy.orm import relation
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.declarative import synonym_for

from pas.plugins.sqlalchemy.interfaces import IEncryptedPasswordAware
from pas.plugins.sqlalchemy.interfaces import IUser

Base = declarative_base()

group_member_table = Table('group_members', Base.metadata,
    Column('group_id', Integer, ForeignKey('groups.id'), primary_key=True),
    Column('principal_id', Integer, ForeignKey('principals.id'), primary_key=True),
)


class Principal(Base):
    __tablename__ = "principals"

    id = Column(Integer, Sequence("principals_id"), primary_key=True)
    type = Column(String(5), nullable=False, default="user")
    zope_id = Column(String(40), nullable=False, unique=True, index=True)

    __mapper_args__ = {'polymorphic_on': type}
    _properties = [("id", "zope_id")]


class RoleAssignment(Base):
    __tablename__ = "role_assignments"

    id = Column(Integer, Sequence("role_assignment_id"), primary_key=True)
    principal_id = Column(Integer, ForeignKey(Principal.id))
    name = Column(String(64))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return ("<RoleAssignment id=%s principal_id=%d name=%s>" % (
            str(self.id), self.principal_id, self.name)).encode('utf-8')


class User(Principal):
    implements(IUser, IEncryptedPasswordAware)

    __tablename__ = "users"
    __mapper_args__ = {'polymorphic_identity': 'user'}

    user_id = Column("id", Integer, ForeignKey(Principal.id),
            primary_key=True)

    login = Column(String(64), unique=True, index=True)
    #name = Column(String, unique=True) # is replaced by zope_id on the parent class/table, common for groups and users.
    _password = Column("password", String(64))
    _salt = Column("salt", String(12))
    enabled = Column(Boolean(), nullable=False, default=True, index=True)

    # roles
    _roles =  relation(
        RoleAssignment, collection_class=set, cascade="all, delete, delete-orphan")
    roles = association_proxy("_roles", "name")

    # memberdata property sheet
    email = Column(String(40), default=u"", index=True)
    portal_skin = Column(String(20), default=u"")
    listed = Column(Integer, default=1)
    login_time = Column(DateTime(), default=functions.now())
    last_login_time = Column(DateTime(), default=functions.now())
    fullname = Column(String(40), default=u"", index=True)
    error_log_update = Column(Float, default=0)
    home_page = Column(String(40), default=u"")
    location = Column(String(40), default=u"")
    description = Column(Text, default=u"")
    language = Column(String(20), default=u"")
    ext_editor = Column(Integer, default=0)
    wysiwyg_editor = Column(String(10), default="")
    visible_ids = Column(Integer, default=0)

    _properties = [ ("id", "zope_id" ),
                    ("login", "login" ),
                    ("email", "email" ),
                    ("portal_skin", "portal_skin" ),
                    ("listed", "listed" ),
                    ("login_time", "login_time" ),
                    ("last_login_time", "last_login_time" ),
                    ("fullname", "fullname" ),
                    ("error_log_update", "error_log_update" ),
                    ("home_page", "home_page" ),
                    ("location", "location" ),
                    ("description", "description" ),
                    ("language", "language" ),
                    ("ext_editor", "ext_editor" ),
                    ("wysiwyg_editor", "wysiwyg_editor" ),
                    ("visible_ids", "visible_ids" ),
                    ]

    # Make password read-only
    @synonym_for("_password")
    @property
    def password(self):
        return self._password

    @synonym_for("_salt")
    @property
    def salt(self):
        return self._salt

    def generate_salt(self):
        return ''.join(random.sample(string.letters, 12))

    def encrypt(self, password):
        return sha(password+self.salt).hexdigest()

    def set_password(self, password):
        self._salt = self.generate_salt()
        self._password = self.encrypt(password)

    def check_password(self, password):
        return self.encrypt(password) == self.password

    def __repr__(self):
        return ("<User id=%s login=%s name=%s>" % (
            str(self.id), self.login, self.zope_id)).encode('utf-8')

class Group(Principal):
    __tablename__ = "groups"
    __mapper_args__ = {"polymorphic_identity": "group"}

    group_id = Column("id", Integer(), ForeignKey(Principal.id),
            primary_key=True)
    title = Column(String(40), default=u"")
    description = Column(String(40), default=u"")
    email = Column(String(40), default=u"")

    members = relation(Principal, secondary=group_member_table, backref="groups")

    _roles =  relation(
        RoleAssignment, collection_class=set, cascade="all, delete, delete-orphan")
    roles = association_proxy("_roles", "name")

    _properties = [("id", "zope_id" ),
                   ("title", "title" ),
                   ("description", "description" ),
                   ("email", "email" ),
                   ]

    def __repr__(self):
        return ("<Group id=%d name=%s>" % (
            str(self.id), self.zope_id)).encode('utf-8')

