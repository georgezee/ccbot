import os
import pytest
from moto import mock_dynamodb2
import boto3

# Set the users table variable for testing that is defined in serverless.yml
os.environ["USERS_TABLE"] = "test_users_table"


def test_message_foo():

    import app

    def ack():
        pass

    def respond(someString):
        pass

    app.foo(ack, respond, None)
    assert True


def test_command_clear_x():

    import app

    command = {
        'user_id': 'U0LPPP5RT',
        'user_name': 'Joe',
        'command': '/clear',
        'text': 'https://www.example.com',
    }

    def ack():
        pass

    def respond(someString):
        pass

    app.command_clear(ack, respond, command)
    assert True


@mock_dynamodb2
def mock_setup_users():
    USERS_TABLE = os.environ['USERS_TABLE']
    user_basic = {
        'userId': 'U0LPPP5RT',
        'name': 'Joey',
        'roles': {'basic'}
    }
    user_admin = {
        'userId': 'U0LPPPADM',
        'name': 'Mike',
        'roles': {'admin'}
    }

    dynamodb = boto3.resource('dynamodb')
    dynamodb.create_table(
        TableName=USERS_TABLE,
        KeySchema=[
            {"AttributeName": "userId", "KeyType": "HASH"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "userId", "AttributeType": "S"},
        ]
    )
    table = dynamodb.Table(USERS_TABLE)
    # Create a basic user
    table.put_item(
        Item=user_basic
    )
    # Create an admin user
    table.put_item(
        Item=user_admin
    )


@pytest.mark.parametrize(
    "text,value",
    [
        ('https://www.example.com/some-url.htm', 'ERR'),
        ('https://www.rainfallnet.com/favicon.ico?v=2', 'OK'),
        ('https://rainfallnet.com/favicon.ico?v=2 https://rainfallnet.com/static/css/main.7ecd61a4.chunk.css', 'OK'),
        ('https://www.rainfallnet.com/favicon.ico?v=2 https://www.example.com/other', 'PARTIAL')
    ]
)
@mock_dynamodb2
def test_command_clear_url(text, value):

    import app

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

    response = app.command_clear_url(ack, respond, command)
    assert response == value


@pytest.mark.parametrize(
    "domain,value",
    [
        ('https://www.example.com/some-url.htm', 'example.com'),
        ('https://www.example.co.za/some-url.htm', 'example.co.za'),
        ('https://www.example.ch/some-url.htm', 'example.ch'),
        ('https://subdomain.example.ch/some-url.htm', 'example.ch'),
        ('http://www.example.com/without-https', 'example.com'),
        ('https://www.example.com/', 'example.com'),
        ('https://www.example.com', 'example.com'),
        ('HtTps://www.example.com', 'example.com'),
        ('HtTps://subdomain.example.com', 'example.com'),
        ('https://example.com', 'example.com'),
        ('www.example.com', 'example.com'),
        ('example.com', 'example.com')
    ]
)
def test_command_get_domain(domain, value):

    import app

    response = app.get_domain(domain)
    assert response == value


@pytest.mark.parametrize(
    "domain,value",
    [
        ('https://www.rainfallnet.com/some-url.htm', '057e772b6bdc6df38b97c595485b0bc5'),
        ('https://www.example.com/some-url.htm', None)
    ]
)
def test_command_get_zone(domain, value):

    import app

    response = app.get_zone_id(domain)
    assert response == value
