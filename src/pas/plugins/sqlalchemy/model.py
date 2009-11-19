# -*- coding: utf-8 -*-
#
# File: model.py
#
# Copyright (c) InQuant GmbH
# Copyright (c) 2009 Wichert Akkerman
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

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import orm
from sqlalchemy import schema
from sqlalchemy import types
from sqlalchemy import Table
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.declarative import synonym_for

BaseObject = declarative_base()


group_member_table = Table('group_member', BaseObject.metadata,
    schema.Column('group_id', types.Integer(), schema.ForeignKey('group.id'))
    schema.Column('principal_id', types.Integer(), schema.ForeignKey('principal.id')),
)


class Principal(BaseObject):
    __tablename__ = "principal"

    id = schema.Column(types.Integer(), types.Sequence("principals_id"), primary_key=True)
    type = schema.Column(types.String(5), nullable=False, default="user")
    zope_id = schema.Column(types.String(16), nullable=False, unique=True)

    __mapper_args__ = dict(polymorphic_on=type)
    _properties = [ ("zope_id", "id" )]
    


class RoleAssignment(BaseObject):
    __tablename__ = "role_assignment"

    id = schema.Column(types.Integer(), types.Sequence("role_assignment_id"), primary_key=True)
    principal_id = schema.Column(types.Integer(), schema.ForeignKey(Principal.id))
    name = schema.Column(types.String(64))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<RoleAssignment id=%s principal_id=%d name=%s>" % (
            self.id, self.principal_id, self.name)


class User(Principal):
    __tablename__ = "user"
    __mapper_args__ = dict(polymorphic_identity="user")

    user_id = schema.Column("id", types.Integer(), schema.ForeignKey(Principal.id),
            primary_key=True)

    login = schema.Column(types.String(64), unique=True)
    password = schema.Column("_password", types.String(64))
    enabled = schema.Column(types.Boolean())

    # roles
    _roles =  orm.relation(
        RoleAssignment, collection_class=set, cascade="all, delete, delete-orphan")
    roles = association_proxy("_roles", "name")

    # memberdata property sheet
    email = schema.Column(types.String(40), default=u"")
    portal_skin = schema.Column(types.String(20), default=u"")
    listed = schema.Column(types.Integer(), default=1)
    login_time = schema.Column(types.DateTime())
    last_login_time = schema.Column(types.DateTime())
    fullname = schema.Column(types.String(40), default=u"")
    error_log_update = schema.Column(types.Float())
    home_page = schema.Column(types.String(40), default=u"")
    location = schema.Column(types.String(40), default=u"")
    description = schema.Column(types.Text(), default=u"")
    language = schema.Column(types.String(20), default=u"")
    ext_editor = schema.Column(types.Integer(), default=0)
    wysiwyg_editor = schema.Column(types.String(10), default="")
    visible_ids = schema.Column(types.Integer(), default=0)

    _properties = [ ("zope_id", "id" ),
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
    def password:
        return self._password

    def set_password(self, password):
        self.password = password

    def authenticate(self, password):
        return password == self.password

    def __repr__(self):
        return "<User id=%d login=%s userid=%s>" % (
            self.id, self.login, self.userid)


class Group(Principal):
    __tablename__ = "group"
    __mapper_args__ = dict(polymorphic_identity="group")

    group_id = schema.Column(types.Integer(), schema.ForeignKey(Principal.id),
            primary_key=True)

    # XXX Should this be an association proxy so it only lists zope_ids?
    members = orm.relation(Principal, secondary=group_member_table, backref="groups")

    _roles =  orm.relation(
        RoleAssignment, collection_class=set, cascade="all, delete, delete-orphan")
    roles = association_proxy("_roles", "name")

    def __repr__(self):
        return "<Group id=%d groupid=%s>" % (self.id, self.groupid)

