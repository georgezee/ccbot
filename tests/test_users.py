import pytest
import boto3
import os
from moto import mock_dynamodb2

USERS_TABLE = os.environ['USERS_TABLE']


@mock_dynamodb2
def test_get_user():
    import app

    # Todo: Move this into common util functions.
    from test_command_clear import mock_setup_users
    mock_setup_users()

    user = app.get_user("U0LPPP5RT")
    assert user["userId"] == "U0LPPP5RT"


@pytest.mark.parametrize(
    "text,value",
    [
        ('basic <@U0LPPP5RT|Joe>', 'OK'),
        ('admin <@U0LPPP5RT|Joe>', 'OK'),
        ('none <@U0LPPP5RT|Joe>', 'ERR'),
        ('basic invalid-user', 'ERR'),
        ('random-text', 'ERR')
    ]
)
@mock_dynamodb2
def test_command_add_role(text, value):

    import app

    from test_command_clear import mock_setup_users
    mock_setup_users()

    app.dynamo_resource = None
    boto3.setup_default_session()

    def ack():
        pass

    def respond(someString):
        pass

    command = {
        'user_id': 'U0LPPPADM',
        'user_name': 'Mike',
        'command': '/cc-add-role',
        'text': text,
    }

    response = app.command_add_role(ack, respond, command)
    assert response == value


@pytest.mark.parametrize(
    "user_id,role,value",
    [
        ('U0LPPP5RT', 'basic', True),
        ('U0LPPP5RT', 'admin', False),
        ('U0LPPP5RT', 'random', 'ERR'),
    ]
)
@mock_dynamodb2
def test_has_role(user_id, role, value):

    import app

    from test_command_clear import mock_setup_users
    mock_setup_users()

    app.dynamo_resource = None
    boto3.setup_default_session()

    mocked_user = {
        'userId': user_id,
        'name': 'Joey',
        'roles': {'basic'}
    }

    response = app.has_role(mocked_user, role)
    assert response == value


@pytest.mark.parametrize(
    "text,value",
    [
        ('basic <@U0LPPP5RT|Joe>', 'OK'),
        ('admin <@U0LPPP5RT|Joe>', 'ERR'),
        ('none <@U0LPPP5RT|Joe>', 'ERR'),
        ('basic invalid-user', 'ERR'),
        ('random-text', 'ERR')
    ]
)
@mock_dynamodb2
def test_command_remove_role(text, value):

    import app

    from test_command_clear import mock_setup_users
    mock_setup_users()

    app.dynamo_resource = None
    boto3.setup_default_session()

    def ack():
        pass

    def respond(someString):
        pass

    command = {
        'user_id': 'U0LPPPADM',
        'user_name': 'Mike',
        'command': '/cc-remove-role',
        'text': text,
    }

    response = app.command_remove_role(ack, respond, command)
    assert response == value


@mock_dynamodb2
def test_add_role():

    import app

    from test_command_clear import mock_setup_users
    mock_setup_users()
    app.dynamo_resource = None
    boto3.setup_default_session()

    # Testing for a 'basic' user upgrading to 'admin'.
    # Confirm the role is not present before adding.
    before_user = app.get_user('U0LPPP5RT')
    assert "admin" not in before_user["roles"]
    # Add the role.
    app.add_role(before_user, 'admin')
    # Confirm the role is now present.
    after_user = app.get_user('U0LPPP5RT')
    assert "admin" in after_user["roles"]

    # Testing for a new user upgrading to 'basic'.
    # Confirm the role is not present before adding.
    before_user = app.get_user('U0LPPPNEW')
    assert "basic" not in before_user["roles"]
    # Add the role.
    app.add_role(before_user, 'basic')
    # Confirm the role is now present.
    after_user = app.get_user('U0LPPPNEW')
    assert "basic" in after_user["roles"]


@mock_dynamodb2
def test_remove_role():

    import app

    from test_command_clear import mock_setup_users
    mock_setup_users()
    app.dynamo_resource = None
    boto3.setup_default_session()

    # Confirm the role is present before removing.
    before_user = app.get_user('U0LPPP5RT')
    assert "basic" in before_user["roles"]

    # Remove the role.
    app.remove_role(before_user, 'basic')

    # Confirm the role is no longer present.
    after_user = app.get_user('U0LPPP5RT')
    assert "basic" not in after_user["roles"]


@pytest.mark.parametrize(
    "text,value",
    [
        ('<@U0LPPP5RT|Joe> rainfallnet.com', 'OK'),
        ('<@U0LPPP5RT|Joe> www.rainfallnet.com', 'OK'),
        ('<@U0LPPP5RT|Joe> example.com', 'ERR'),
        ('<@U0LPPP5RT|Joe>', 'ERR'),
        ('invalid-user rainfallnet.com', 'ERR'),
        ('random-text', 'ERR')
    ]
)
@mock_dynamodb2
def test_command_allow_zone(text, value):

    import app

    from test_command_clear import mock_setup_users
    mock_setup_users()

    app.dynamo_resource = None
    boto3.setup_default_session()

    def ack():
        pass

    def respond(someString):
        pass

    command = {
        'user_id': 'U0LPPPADM',
        'user_name': 'Mike',
        'command': '/cc-allow-zone',
        'text': text,
    }

    response = app.command_allow_zone(ack, respond, command)
    assert response == value


@pytest.mark.parametrize(
    "user_id,zone,value",
    [
        ('U0LPPP5RT', '057e772b6bdc6df38b97c595485b0bc5', True),
        ('U0LPPP5RT', 'random', False),
    ]
)
@mock_dynamodb2
def test_allowed_zone(user_id, zone, value):

    import app

    from test_command_clear import mock_setup_users
    mock_setup_users()

    app.dynamo_resource = None
    boto3.setup_default_session()

    mocked_user = {
        'userId': user_id,
        'name': 'Joey',
        'roles': {'basic'},
        'zones': {'057e772b6bdc6df38b97c595485b0bc5'}
    }

    response = app.allowed_zone(mocked_user, zone)
    assert response == value


@pytest.mark.parametrize(
    "text,value",
    [
        ('<@U0LPPP5RT|Joe> rainfallnet.com', 'OK'),
        ('<@U0LPPP5RT|Joe> https://www.rainfallnet.com', 'OK'),
        ('<@U0LPPP5RT|Joe> https://www.example.com', 'ERR'),
        ('invalid-user', 'ERR'),
        ('random-text', 'ERR')
    ]
)
@mock_dynamodb2
def test_command_disallow_zone(text, value):

    import app

    from test_command_clear import mock_setup_users
    mock_setup_users()

    app.dynamo_resource = None
    boto3.setup_default_session()

    def ack():
        pass

    def respond(someString):
        pass

    command = {
        'user_id': 'U0LPPPADM',
        'user_name': 'Mike',
        'command': '/cc-disallow-zone',
        'text': text,
    }

    response = app.command_disallow_zone(ack, respond, command)
    assert response == value


@mock_dynamodb2
def test_disallow_zone():

    import app

    from test_command_clear import mock_setup_users
    mock_setup_users()
    app.dynamo_resource = None
    boto3.setup_default_session()

    # Confirm the zone is present before removing.
    before_user = app.get_user('U0LPPP5RT')
    assert "057e772b6bdc6df38b97c595485b0bc5" in before_user["zones"]

    # Remove the role.
    app.disallow_zone(before_user, '057e772b6bdc6df38b97c595485b0bc5')

    # Confirm the zone is no longer present.
    after_user = app.get_user('U0LPPP5RT')
    assert "057e772b6bdc6df38b97c595485b0bc5" not in after_user["zones"]