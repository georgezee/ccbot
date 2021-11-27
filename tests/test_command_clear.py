import os
import pytest
from moto import mock_dynamodb2, mock_sns
import boto3

# Set the users table variable for testing that is defined in serverless.yml
os.environ["USERS_TABLE"] = "test_users_table"
os.environ["PURGE_TOPIC"] = ""  # Will be replaced by mocked name once created.



@mock_dynamodb2
def mock_setup_users():
    USERS_TABLE = os.environ['USERS_TABLE']
    user_basic = {
        'userId': 'U0LPPP5RT',
        'name': 'Joey',
        'roles': ['basic'],
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
    "user_id,command,value",
    [
        ('U0LPPP5RT', '/clear-url', True),
        ('U0LPPP5RT', '/cc-add-role', False),
        ('U0LPPP5RT', '/cc-remove-role', False),
        ('U0LPPPADM', '/clear-url', True),
        ('U0LPPPADM', '/cc-add-role', True),
        ('U0LPPPADM', '/cc-remove-role', True),
        ('UNUSED', '/cc-remove-role', False)
    ]
)
@mock_dynamodb2
def test_check_permissions(user_id, command, value):

    import app
    mock_setup_users()

    app.dynamo_resource = None
    boto3.setup_default_session()

    response = app.check_permission(user_id, command)
    assert response == value


@mock_dynamodb2
def test_sns_dequeue_message():
    import app
    mock_setup_users()

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

    response = app.dequeue_task(event, context)
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

    response = app.enqueue_task(url_list, context)
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
