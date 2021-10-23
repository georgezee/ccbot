import os
import pytest
from moto import mock_dynamodb2, mock_sns
import boto3

# Set the users table variable for testing that is defined in serverless.yml
os.environ["USERS_TABLE"] = "test_users_table"
os.environ["PURGE_TOPIC"] = ""  # Will be replaced by mocked name once created.


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
        'roles': ['basic'],
        'zones': ['057e772b6bdc6df38b97c595485b0bc5']
    }
    user_new = {
        'userId': 'U0LPPPNEW',
        'name': 'Newbie'
    }
    user_admin = {
        'userId': 'U0LPPPADM',
        'name': 'Mike',
        'roles': ['admin']
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
    # Create a new user
    table.put_item(
        Item=user_new
    )
    # Create an admin user
    table.put_item(
        Item=user_admin
    )


@mock_sns
def mock_setup_topics():
    sns = boto3.client("sns", region_name="us-east-1")
    topic_name = "test_purge_topic"
    mock_topic = sns.create_topic(Name=topic_name)

    # Set the environment variable to the mocked Topic Arn, for use by the app.
    os.environ['PURGE_TOPIC'] = mock_topic['TopicArn']


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
        'team_id': 'T0LPM5M44',
        'channel_id': 'C5LTXMLCS',
        'channel_name': 'unleash',
        'user_id': 'U0LPPP5RT',
        'user_name': 'Joe',
        'command': '/clear-url',
        'text': text,
    }

    app.dynamo_resource = None
    boto3.setup_default_session()
    mock_setup_users()

    response = app.command_clear_url(ack, respond, command)
    assert response == value


@pytest.mark.parametrize(
    "text,value",
    [
        ('https://www.example.com/some-url.htm', 'ERR'),
        ('https://rainfallnet.com/favicon.ico?v=2', 'OK')
    ]
)
@mock_dynamodb2
@mock_sns
def test_command_clear_url_translations(text, value):

    import app

    mock_setup_topics()

    def ack():
        pass

    def respond(someString):
        pass

    command = {
        'team_id': 'T0LPM5M44',
        'channel_id': 'C5LTXMLCS',
        'channel_name': 'unleash',
        'user_id': 'U0LPPP5RT',
        'user_name': 'Joe',
        'command': '/clear-url',
        'text': text,
    }

    app.dynamo_resource = None
    boto3.setup_default_session()
    mock_setup_users()

    response = app.command_clear_url_translations(ack, respond, command)
    assert response == value


@pytest.mark.parametrize(
    "domain,value",
    [
        ('<http://example.com|example.com>', 'example.com'),
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


@pytest.mark.parametrize(
    "user_id,command,zone,value",
    [
        ('U0LPPP5RT', '/clear-url', None, True),
        ('U0LPPP5RT', '/cc-add-role', None, False),
        ('U0LPPP5RT', '/cc-remove-role', None, False),
        ('U0LPPPADM', '/clear-url', None, True),
        ('U0LPPPADM', '/cc-add-role', None, True),
        ('U0LPPPADM', '/cc-remove-role', None, True),
        ('UNUSED', '/cc-remove-role', None, False)
    ]
)
@mock_dynamodb2
def test_check_permissions(user_id, command, zone, value):

    import app
    mock_setup_users()

    app.dynamo_resource = None
    boto3.setup_default_session()

    response = app.check_permission(user_id, command, zone)
    assert response == value


@pytest.mark.parametrize(
    "url,value",
    [
        ('https://www.bbc.com/news', 'https://www.bbc.co.uk/news'),
        ('https://weblate.org/en/', 'https://weblate.org/de/')
    ]
)
def test_get_hreflang(url, value):
    """ Fetches the hreflang tags from a particular url."""

    import app

    response = app.get_hreflang_from_url(url)
    assert value in response


def test_sns_dequeue_message():
    import app

    context = None
    message = """{'data': ['https://rainfallnet.com/favicon.ico?v=2',
    'https://rainfallnet.com/static/css/main.7ecd61a4.chunk.css'],
    'context': {'channel_id': 'C5LTXMLCS',
    'team_id': 'T0LPM5M44',
    'user_id': 'U0LPPP5RT',
    'user_name': 'george',
    'command': '/clear-translations',
    'text': 'https://rainfallnet.com/favicon.ico?v=2 https://rainfallnet.com/static/css/main.7ecd61a4.chunk.css'}}"""

    event = {
        'Records': [{
            'EventSource': 'aws:sns',
            'Sns': {
                'Type': 'Notification',
                'MessageId': '4a092386-fd3c-5bed-9a5e-7a65b2983c2a',
                'Subject': None,
                'Message': message,
            }
        }]
    }

    response = app.dequeue_clear_url(event, context)
    assert response == "OK"


@mock_sns
def test_sns_send():
    import app
    mock_setup_topics()

    app.sns_client = None
    boto3.setup_default_session()

    url_list = {"https://www.rainfallnet.com"}
    context = {
        'team_id': 'T0LPM5M44',
        'channel_id': 'C5LTXMLCS',
        'channel_name': 'unleash',
        'user_id': 'U0LPPP5RT',
        'user_name': 'george',
        'command': '/clear',
        'text': 'https://www.example.com'
    }

    response = app.enqueue_clear_url(url_list, context)
    assert response == "OK"


@pytest.mark.skip(reason="Still working on how to mock handler")
def test_app():
    class Object(object):
        pass

    # event = {'resource': '/slack/events', 'path': '/slack/events', 'httpMethod': 'POST', 'headers': {'Accept': 'application/json,*/*', 'Accept-Encoding': 'gzip,deflate', 'CloudFront-Forwarded-Proto': 'https', 'CloudFront-Is-Desktop-Viewer': 'true', 'CloudFront-Is-Mobile-Viewer': 'false', 'CloudFront-Is-SmartTV-Viewer': 'false', 'CloudFront-Is-Tablet-Viewer': 'false', 'CloudFront-Viewer-Country': 'US', 'Content-Type': 'application/x-www-form-urlencoded', 'Host': 'r4e5er36ic.execute-api.us-east-1.amazonaws.com', 'User-Agent': 'Slackbot 1.0 (+https://api.slack.com/robots)', 'Via': '1.1 c37f72766931ae9c3f146ffa54018d1c.cloudfront.net (CloudFront)', 'X-Amz-Cf-Id': 'C15-IhK8m05xkAXJfqqBp1abu5OcPxd50QE9mwz3cbpMIW5ljzdk9A==', 'X-Amzn-Trace-Id': 'Root=1-613b76c8-16adc5270355409f0d3a0f11', 'X-Forwarded-For': '3.91.205.26, 70.132.60.79', 'X-Forwarded-Port': '443', 'X-Forwarded-Proto': 'https', 'X-Slack-Request-Timestamp': '1631286984', 'X-Slack-Signature': 'v0=255f3e0e7b818752b462f4e74ba67de4439a1790d95fc3d96d2cc62542979201'}, 'multiValueHeaders': {'Accept': ['application/json,*/*'], 'Accept-Encoding': ['gzip,deflate'], 'CloudFront-Forwarded-Proto': ['https'], 'CloudFront-Is-Desktop-Viewer': ['true'], 'CloudFront-Is-Mobile-Viewer': ['false'], 'CloudFront-Is-SmartTV-Viewer': ['false'], 'CloudFront-Is-Tablet-Viewer': ['false'], 'CloudFront-Viewer-Country': ['US'], 'Content-Type': ['application/x-www-form-urlencoded'], 'Host': ['r4e5er36ic.execute-api.us-east-1.amazonaws.com'], 'User-Agent': ['Slackbot 1.0 (+https://api.slack.com/robots)'], 'Via': ['1.1 c37f72766931ae9c3f146ffa54018d1c.cloudfront.net (CloudFront)'], 'X-Amz-Cf-Id': ['C15-IhK8m05xkAXJfqqBp1abu5OcPxd50QE9mwz3cbpMIW5ljzdk9A=='], 'X-Amzn-Trace-Id': ['Root=1-613b76c8-16adc5270355409f0d3a0f11'], 'X-Forwarded-For': ['3.91.205.26, 70.132.60.79'], 'X-Forwarded-Port': ['443'], 'X-Forwarded-Proto': ['https'], 'X-Slack-Request-Timestamp': ['1631286984'], 'X-Slack-Signature': ['v0=255f3e0e7b818752b462f4e74ba67de4439a1790d95fc3d96d2cc62542979201']}, 'queryStringParameters': None, 'multiValueQueryStringParameters': None, 'pathParameters': None, 'stageVariables': None, 'requestContext': {'resourceId': 'p5qrl6', 'resourcePath': '/slack/events', 'httpMethod': 'POST', 'extendedRequestId': 'Fc9_VH7CoAMFdaQ=', 'requestTime': '10/Sep/2021:15:16:24 +0000',
    # 'path': '/dev/slack/events', 'accountId': '234815085025', 'protocol': 'HTTP/1.1', 'stage': 'dev', 'domainPrefix': 'r4e5er36ic', 'requestTimeEpoch': 1631286984364, 'requestId': '4fe3f7a4-b567-4945-bd75-e32b416c1a9f', 'identity': {'cognitoIdentityPoolId': None, 'accountId': None, 'cognitoIdentityId': None, 'caller': None, 'sourceIp': '3.91.205.26', 'principalOrgId': None, 'accessKey': None, 'cognitoAuthenticationType': None, 'cognitoAuthenticationProvider': None, 'userArn': None, 'userAgent': 'Slackbot 1.0 (+https://api.slack.com/robots)', 'user': None}, 'domainName': 'r4e5er36ic.execute-api.us-east-1.amazonaws.com', 'apiId': 'r4e5er36ic'},
    # 'body': 'token=t1a4HBUMvKQjkuv3uENNBiDN&team_id=T0LPM5M44&team_domain=springfisher&channel_id=C5LTXMLCS&channel_name=unleash&user_id=U0LPPP5RT&user_name=george&command=%2Fclear&text=https%3A%2F%2Fwww.abc.com&api_app_id=A02BU03PZLG&is_enterprise_install=false&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT0LPM5M44%2F2475061134341%2FCQ2VtwLii2eWD5J6P3dwJK9s&trigger_id=2490694709857.20803191140.7969a97526260405b033d9ac96fcb118', 'isBase64Encoded': False}
    event = {}
    context = Object()
    context.function_name = "test_function"

    import app
    response = app.handler(event, context)
    print(response)
    assert response["statusCode"] != 401
