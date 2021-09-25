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
        'user_id': 'U0LPPP5RT',
        'user_name': 'Joe',
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

    response = app.has_role(user_id, role)
    assert response == value


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
        'user_id': 'U0LPPP5RT',
        'user_name': 'Joe',
        'text': text,
    }

    app.dynamo_resource = None
    boto3.setup_default_session()
    mock_setup_users()

    response = app.command_remove_role(ack, respond, command)
    assert response == value
