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

__author__    = """Stefan Eletzhofer <stefan.eletzhofer@inquant.de>"""
__docformat__ = 'plaintext'
__revision__  = "$Revision: 3823 $"
__version__   = '$Revision: 3823 $'[11:-2]

import random
import string
import sha
import datetime

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Table, Column, Integer, String, Boolean, DateTime, TIMESTAMP
from sqlalchemy import Text, Float, ForeignKey, Sequence
from sqlalchemy.orm import relation
from sqlalchemy.ext.associationproxy import association_proxy

Base = declarative_base()

user_groups = Table('user_groups', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('group_id', Integer, ForeignKey('groups.id'))
)

class Principal(Base):
    __tablename__ = "principals"

    id = Column(Integer, Sequence("principals_id"), primary_key=True)

class RoleAssignment(Base):
    __tablename__ = "role_assignments"

    id = Column(Integer, Sequence("role_assignment_id"), primary_key=True)
    principal_id = Column(Integer, ForeignKey(Principal.id))
    name = Column(String(64))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<RoleAssignment id=%s principal_id=%d name=%s>" % (
            self.id, self.principal_id, self.name)

class User(Principal):
    __tablename__ = "users"

    id = Column(
        Integer,
        ForeignKey(Principal.id),
        Sequence("principals_id"),
        primary_key=True)

    login = Column(String, unique=True)
    name = Column(String, unique=True)
    password = Column(String)
    salt = Column(String(12))
    enabled = Column(Boolean)

    # roles
    _roles =  relation(
        RoleAssignment, collection_class=set, cascade="all, delete, delete-orphan")
    roles = association_proxy("_roles", "name")

    # memberdata property sheet
    email = Column(String(40), default=u"")
    portal_skin = Column(String(20), default=u"")
    listed = Column(Integer, default=1)
    login_time = Column(DateTime)
    last_login_time = Column(DateTime)
    fullname = Column(String(40), default=u"")
    error_log_update = Column(Float)
    home_page = Column(String(40), default=u"")
    location = Column(String(40), default=u"")
    description = Column(Text, default=u"")
    language = Column(String(20), default=u"")
    ext_editor = Column(Integer, default=0)
    wysiwyg_editor = Column(String(10), default="")
    visible_ids = Column(Integer, default=0)
    firstname = Column(String(30), default=u"")
    lastname = Column(String(30), default=u"")
    join_time = Column(DateTime)
    gender = Column(String(10), default=u"")
    city = Column(String(20), default=u"")
    date_created = Column(DateTime, nullable=False)
    date_of_birth = Column(DateTime)
    date_updated = Column(TIMESTAMP, nullable=True)
    genres = Column(String(20), default=u"")
    street = Column(String(40), default=u"")
    house_number = Column(String(8), default=u"")
    zip_code = Column(String(5), default=u"")
    sport = Column(String(20), default=u"")
    car = Column(String(20), default=u"")
    income = Column(String(15), default=u"")
    family_status = Column(String(15), default=u"")
    education = Column(String(25), default=u"")
    flags = Column(Integer, default=0)
    country = Column(String(20), default=u"")
    cell_number = Column(String(15), default=u"")

    def __init__(self, login=None, name=None, password=None):
        self.name = name
        self.login = login
        self.password = password
        self.salt = self.generate_salt()
        self.date_created = datetime.datetime.now()

    def generate_salt(self):
        return ''.join(random.sample(string.letters, 12))

    def encrypt(self, password):
        return sha.sha(password+self.salt).hexdigest()

    def set_password(self, password):
        self.salt = self.generate_salt()
        self.password = self.encrypt(password)

    def check_password(self, password):
        return self.encrypt(password) == self.password

    def __repr__(self):
        return "<User id=%d login=%s name=%s>" % (
            self.id, self.login, self.name)

class Group(Principal):
    __tablename__ = "groups"

    id = Column(
        Integer,
        ForeignKey(Principal.id),
        Sequence("principals_id"),
        primary_key=True)

    name = Column(String, unique=True)
    users = relation(User, secondary=user_groups, backref="groups")

    _roles =  relation(
        RoleAssignment, collection_class=set, cascade="all, delete, delete-orphan")
    roles = association_proxy("_roles", "name")

    def __init__(self, name=None):
        self.name = name

    def __repr__(self):
        return "<Group id=%d name=%s>" % (self.id, self.name)

# vim: set ft=python ts=4 sw=4 expandtab :
