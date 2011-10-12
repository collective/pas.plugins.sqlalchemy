
# tests from sqlpasplugin ( GPL v2 )

from pas.plugins.sqlalchemy.tests import basetestcase
from pas.plugins.sqlalchemy.setuphandlers import plugin_name
from Products.PlonePAS.plugins.group import PloneGroup

class TestGroupManager( basetestcase.BaseTestCase ):
    def afterSetUp(self):
        self.group_name = u'gr\xfcppe'
        self.groupname = self.group_name
        self.source_groups = self.getPAS()[plugin_name]
        self.source_users  = self.getPAS()[plugin_name]

    def testAddGroup(self):
        self.source_groups.addGroup( self.group_name )
        ret = self.source_groups.enumerateGroups( id=self.group_name, exact_match=True )
        self.assertEqual( len(ret), 1 )
        self.source_groups.removeGroup( self.group_name )

    def testRemoveGroup( self ):
        # Is it empty?
        ret = self.source_groups.enumerateGroups(id=self.group_name, exact_match=True)
        self.assertEqual(len(ret), 0)

        # allowRemove
        ret = self.source_groups.allowDeletePrincipal(self.group_name)
        self.assertEqual(ret, False)

        # Add one
        self.source_groups.addGroup(self.group_name)
        ret = self.source_groups.enumerateGroups(id=self.group_name, exact_match=True)
        self.assertEqual(len(ret), 1)

        # allowRemove
        ret = self.source_groups.allowDeletePrincipal(self.group_name)
        self.assertEqual(ret, True)

        # Delete one
        self.source_groups.removeGroup(self.group_name)
        ret = self.source_groups.enumerateGroups(id=self.group_name, exact_match=True)
        self.assertEqual(len(ret), 0)

    def testMembershipLifecycle(self):
        # Create Group
        self.source_groups.addGroup(self.groupname)
        ret = self.source_groups.enumerateGroups(id=self.groupname, exact_match=True)
        self.assertEqual(len(ret), 1)

        # Create User
        self.source_users.doAddUser(self.username, self.password)
        ret = self.source_users.enumerateUsers(id=self.username, exact_match=True)
        self.assertEqual(len(ret), 1)

        # User should have no memberships
        ret = self.source_groups.getGroupsForPrincipal(self.username)
        self.assertEqual(len(ret), 0, "Database seems unclean")

        # Add the user to the group
        self.source_groups.addPrincipalToGroup(self.username, self.groupname)
        ret = self.source_groups.getGroupsForPrincipal(self.username)
        self.assertEqual(len(ret), 1, "Failed to add user to group")
        self.assertEqual(ret[0], self.groupname)

        # Remove the user from the group
        self.source_groups.removePrincipalFromGroup(self.username,
                                                    self.groupname)
        ret = self.source_groups.getGroupsForPrincipal(self.username)
        self.assertEqual(len(ret), 0, "Failed to remove user from group")

        # Cleanup
        self.source_users.removeUser(self.username)
        self.source_groups.removeGroup(self.groupname)


    def testEnumerateGroups(self):
        "groupmanager.enumerateGroups()"
        ret = self.source_groups.enumerateGroups()
        self.assertEqual(len(ret), 0)
        count = 10
        for x in range(count):
            groupname = 'group_%i' % x
            self.source_groups.addGroup(groupname)
        ret = self.source_groups.enumerateGroups()
        self.assertEqual(len(ret), count,
                         "Number added didn't equal the number in the db.")

        ret = self.source_groups.enumerateGroups(id='group_1', exact_match=True)
        self.assertEqual(len(ret), 1)

        ret = self.source_groups.enumerateGroups(max_results=5)
        self.assertEqual(len(ret), 5)

        ret = self.source_groups.enumerateGroups(max_results=20)
        self.assertEqual(len(ret), count)

        for x in range(count):
            groupname = 'group_%i' % x
            self.source_groups.removeGroup(groupname)

    def testEnumerateGroupSearching(self):
        ret = self.source_groups.enumerateGroups()
        self.assertEqual(len(ret), 0)
        count = 10
        for x in range(count):
            groupname = 'group_%i' % x
            self.source_groups.addGroup(groupname)
        ret = self.source_groups.enumerateGroups()
        self.assertEqual(len(ret), count,
                         "Number added didn't equal the number in the db.")

        # Exact match Multiple Group Test
        ret = self.source_groups.enumerateGroups(
            id=['group_2','group_3'], exact_match=True)
        self.assertEqual(len(ret), 2,
                         "Failed multi-fetch")

        # Fuzzy Match Test
        ret = self.source_groups.enumerateGroups(
            id=['group_%'])
        self.assertEqual(len(ret), 10,
                         "Failed the fuzzy match on 'id' test")

        # Exact Match test
        ret = self.source_groups.enumerateGroups(
            id=['group_1','group_1'], exact_match=1)
        self.assertEqual(len(ret), 1)


        ret = self.source_groups.enumerateGroups(max_results=5)
        self.assertEqual(len(ret), 5)

        ret = self.source_groups.enumerateGroups(max_results=20)
        self.assertEqual(len(ret), count)

        for x in range(count):
            groupname = 'group_%i' % x
            self.source_groups.removeGroup(groupname)


    def testIGroupIntrospection_getGroupById_getGroups(self):

        group = self.source_groups.getGroupById(self.groupname)
        self.failUnless(group is None)

        # add group
        self.source_groups.addGroup(self.groupname)

        group = self.source_groups.getGroupById(self.groupname)
        self.failIf(group is None)
        self.failUnless(isinstance(group, PloneGroup))

        # add another group
        self.source_groups.addGroup(self.groupname+'1')

        groups = self.source_groups.getGroups()
        self.assertEqual(len(groups),2)
        self.failUnless(isinstance(groups[0], PloneGroup))
        self.failUnless(isinstance(groups[1], PloneGroup))

        # Cleanup
        self.source_groups.removeGroup(self.groupname)

    def testIGroupIntrospection_getGroupIds(self):
        ret = self.source_groups.getGroupIds()
        self.assertEqual(len(ret), 0)

        # add one group
        self.source_groups.addGroup(self.groupname)

        ret = self.source_groups.getGroupIds()
        self.assertEqual(len(ret), 1)

        # add another group
        self.source_groups.addGroup(self.groupname+'1')

        ret = self.source_groups.getGroupIds()
        self.assertEqual(len(ret), 2)

        # add one user
        self.source_users.doAddUser(self.username, self.password)
        self.source_groups.addPrincipalToGroup(self.username, self.groupname)

        ret = self.source_groups.getGroupIds()
        self.assertEqual(len(ret), 2)

        # Cleanup
        self.source_users.removeUser(self.username)
        self.source_groups.removeGroup(self.groupname)
        self.source_groups.removeGroup(self.groupname+'1')

    def testIGroupIntrospection_getGroupMembers(self):
        # add group
        self.source_groups.addGroup(self.groupname)

        ret = self.source_groups.getGroupMembers(self.groupname)
        self.assertEqual(len(ret), 0)

        # add users
        users_number = 3
        for i in range(users_number):
            username = '%s_%s'%(self.username,i)
            self.source_users.doAddUser(username, self.password)
            self.source_groups.addPrincipalToGroup(username, self.groupname)

        ret = self.source_groups.getGroupMembers(self.groupname)
        self.assertEqual(len(ret), 3)

        # Cleanup
        for i in range(users_number):
            username = '%s_%s'%(self.username,i)
            self.source_users.removeUser(username)
        self.source_groups.removeGroup(self.groupname)


    def testIGroupCapability(self):
        ret = self.source_groups.allowGroupAdd(self.username, self.groupname)
        self.assertEqual(ret, False)

        ret = self.source_groups.allowGroupRemove(self.username, self.groupname)
        self.assertEqual(ret, False)

        # add group
        self.source_groups.addGroup(self.groupname)

        ret = self.source_groups.allowGroupAdd(self.username, self.groupname)
        self.assertEqual(ret, True)

        ret = self.source_groups.allowGroupRemove(self.username, self.groupname)
        self.assertEqual(ret, False)

        # add user
        self.source_users.doAddUser(self.username, self.password)

        ret = self.source_groups.allowGroupAdd(self.username, self.groupname)
        self.assertEqual(ret, True)

        ret = self.source_groups.allowGroupRemove(self.username, self.groupname)
        self.assertEqual(ret, False)

        self.source_groups.addPrincipalToGroup(self.username, self.groupname)

        ret = self.source_groups.allowGroupAdd(self.username, self.groupname)
        self.assertEqual(ret, False)

        ret = self.source_groups.allowGroupRemove(self.username, self.groupname)
        self.assertEqual(ret, True)

        # Cleanup
        self.source_users.removeUser(self.username)
        self.source_groups.removeGroup(self.groupname)



def test_suite( ):
    from unittest import TestSuite, makeSuite
    suite = TestSuite()
    suite.addTest(makeSuite(TestGroupManager))
    return suite

