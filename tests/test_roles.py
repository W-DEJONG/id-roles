import pytest

from id_roles.roles import Roles, split_role, join_role

ROLE_1_STR = 'role_1:sub-role_1'
ROLE_2_STR = 'role_2'
ROLE_3_STR = 'role_3'
ROLES_STR = 'role_1:sub-role_1[v1,v2] role_2[*] role_3'


@pytest.fixture()
def roles_obj():
    return Roles(ROLES_STR)


def test_split_role():
    # full role description with values
    name, values = split_role('role[a,b,c]')
    assert name == 'role'
    assert len(values) == 3
    assert 'a' in values
    assert 'b' in values
    assert 'c' in values

    with pytest.raises(ValueError):
        name, values = split_role('role[a ,b ,c ]')

    with pytest.raises(ValueError):
        name, values = split_role('role[a,b,c] fail')

    # no values
    name, values = split_role('role')
    assert name == 'role'
    assert len(values) == 0

    name, values = split_role('role[]')
    assert name == 'role'
    assert len(values) == 0

    with pytest.raises(ValueError):
        name, values = split_role('role fail')

    # Single * value
    name, values = split_role('role[*]')
    assert name == 'role'
    assert len(values) == 1
    assert '*' in values

    with pytest.raises(ValueError):
        name, values = split_role('role[a,b,c,*]')


def test_join_role():
    # full role with values
    role_str = join_role('role', ['a', 'b', 'c'])
    assert role_str == 'role[a,b,c]'

    role_str = join_role('role', ['*'])
    assert role_str == 'role[*]'

    # no values
    role_str = join_role('role', [])
    assert role_str == 'role'

    # Valid role names
    role_str = join_role('r_o-le:Role0123456789AzaZ', [])
    assert role_str == 'r_o-le:Role0123456789AzaZ'

    with pytest.raises(ValueError):
        role_str = join_role('role fail', [])

    with pytest.raises(ValueError):
        role_str = join_role('role$', [])

    with pytest.raises(ValueError):
        role_str = join_role(' role', [])

    with pytest.raises(ValueError):
        role_str = join_role('role ', [])

    # Single * value
    role_str = join_role('role', '*')
    assert role_str == 'role[*]'

    with pytest.raises(ValueError):
        role_str = join_role('role', ['a', '*'])


class TestRoles:
    def test_init(self):
        roles = Roles(ROLES_STR)
        assert ROLE_1_STR in roles
        assert ROLE_2_STR in roles
        assert ROLE_3_STR in roles
        assert 'fail' not in roles

    def test_repr(self, roles_obj):
        assert str(roles_obj) == ROLES_STR
        assert repr(roles_obj) == '<Roles:"' + ROLES_STR + '">'

    def test_set_roles_str(self, roles_obj):
        assert ROLE_1_STR in roles_obj
        assert ROLE_2_STR in roles_obj
        assert ROLE_3_STR in roles_obj
        assert 'fail' not in roles_obj
        assert roles_obj.get_role_values(ROLE_1_STR) == {'v1', 'v2'}
        assert roles_obj.get_role_values(ROLE_2_STR) == {'*'}
        assert roles_obj.get_role_values(ROLE_3_STR) == set()

    def test_get_roles_str(self, roles_obj):
        roles_str = roles_obj.get_roles_str()
        assert roles_str == ROLES_STR

    def test_has_role(self, roles_obj):
        assert roles_obj.has_role(ROLE_1_STR)
        assert roles_obj.has_role(ROLE_2_STR)
        assert roles_obj.has_role(ROLE_3_STR)
        assert not roles_obj.has_role('fail')

    def test_get_roles(self, roles_obj):
        keys = roles_obj.get_roles()
        assert ROLE_1_STR in keys
        assert ROLE_2_STR in keys
        assert ROLE_3_STR in keys
        assert 'fail' not in keys

    def test_add_role(self, roles_obj):
        roles_obj.add_role('role4[a,b]')
        assert 'role4' in roles_obj
        assert roles_obj.get_role_values('role4') == {'a', 'b'}

        roles_obj.add_role('role5[*]')
        assert 'role5' in roles_obj
        assert roles_obj.get_role_values('role5') == {'*'}

        with pytest.raises(ValueError):
            roles_obj.add_role('ro$le4[a,b]')

        with pytest.raises(ValueError):
            roles_obj.add_role('role4[a ,b]')

    def test_del_role(self, roles_obj):
        roles_obj.del_role(ROLE_2_STR)
        assert ROLE_1_STR in roles_obj
        assert ROLE_2_STR not in roles_obj
        assert ROLE_3_STR in roles_obj

    def test_get_role_values(self, roles_obj):
        values = roles_obj.get_role_values(ROLE_1_STR)
        assert values == {'v1', 'v2'}
        values = roles_obj.get_role_values(ROLE_2_STR)
        assert values == {'*'}
        values = roles_obj.get_role_values(ROLE_3_STR)
        assert values == set()
        with pytest.raises(KeyError):
            values = roles_obj.get_role_values('fail')

    def test_has_role_values(self, roles_obj):
        assert roles_obj.has_role_value(ROLE_1_STR, 'v1')
        assert roles_obj.has_role_value(ROLE_1_STR, 'v2')
        assert not roles_obj.has_role_value(ROLE_1_STR, 'v3')
        assert not roles_obj.has_role_value(ROLE_1_STR, '*')
        assert roles_obj.has_role_value(ROLE_2_STR, '*')
        assert not roles_obj.has_role_value(ROLE_3_STR, '')
        with pytest.raises(KeyError):
            assert roles_obj.has_role_value('fail', '*')

    def test_add_role_value(self, roles_obj):
        roles_obj.add_role_value(ROLE_1_STR, 'v3')
        assert roles_obj.get_role_values(ROLE_1_STR) == {'v1', 'v2', 'v3'}
        roles_obj.add_role_value(ROLE_1_STR, 'v1')
        assert roles_obj.get_role_values(ROLE_1_STR) == {'v1', 'v2', 'v3'}
        roles_obj.add_role_value(ROLE_1_STR, '*')
        assert roles_obj.get_role_values(ROLE_1_STR) == {'*'}
        with pytest.raises(ValueError):
            roles_obj.add_role_value(ROLE_1_STR, 'v1')
        with pytest.raises(KeyError):
            roles_obj.add_role_value('fail', 'v1')

    def test_del_role_value(self, roles_obj):
        roles_obj.del_role_value(ROLE_1_STR, 'v2')
        assert roles_obj.get_role_values(ROLE_1_STR) == {'v1'}
        assert roles_obj.get_role_values(ROLE_1_STR) == {'v1'}
        roles_obj.del_role_value(ROLE_1_STR, '*')
        assert roles_obj.get_role_values(ROLE_1_STR) == set()
        roles_obj.del_role_value(ROLE_2_STR, '*')
        assert roles_obj.get_role_values(ROLE_2_STR) == set()
        with pytest.raises(KeyError):
            roles_obj.del_role_value('fail', '*')

    def test_merge_roles(self):
        roles = Roles('r1 r2[*] r3[a,b] r4')
        roles.merge_roles(Roles('r2[disappears] r3[b,c] r4[v1,v2] r5'))
        assert str(roles) == 'r1 r2[*] r3[a,b,c] r4[v1,v2] r5'
        roles.merge_roles(Roles('r3[*] r1[a]'))
        assert str(roles) == 'r1[a] r2[*] r3[*] r4[v1,v2] r5'
        with pytest.raises(TypeError):
            roles.merge_roles('r3[*] r1[a]')

    def test_remove_roles(self):
        roles = Roles('r1 r2[*] r3[a,b] r4[v1,v2] r5 r6[d,e] r7 r8[y,z] r9[*]')
        roles.remove_roles(Roles('r2[disappears] r3[b,c] r4[v1] r5 r6 r8[*] r9'))
        assert str(roles) == 'r1 r2[*] r3[a] r4[v2] r7 r8'
        with pytest.raises(TypeError):
            roles.remove_roles('r3[*] r1[a]')

    def test_validate_roles(self, roles_obj):
        assert roles_obj.validate_roles(roles_obj)
        assert roles_obj.validate_roles(Roles(''))
        assert roles_obj.validate_roles(Roles('role_2'))
        assert not roles_obj.validate_roles(Roles('role_2 fail'))
        assert roles_obj.validate_roles(Roles('role_2 fail'), match_all=False)
        assert roles_obj.validate_roles(Roles('role_1:sub-role_1[v1]'))
        assert not roles_obj.validate_roles(Roles('role_1:sub-role_1[v3]'))
        assert not roles_obj.validate_roles(Roles('role_1:sub-role_1[*]'))
        assert roles_obj.validate_roles(Roles('role_1:sub-role_1[*] role_3'), match_all=False)
        assert not roles_obj.validate_roles(Roles('role_1:sub-role_1[*] role_3'), match_all=True)
        assert roles_obj.validate_roles(Roles('role_2[value]'))
        assert roles_obj.validate_roles(Roles('role_2[*] role_3'))
