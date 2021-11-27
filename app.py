import os
import boto3
import logging
from slack_bolt import App
from slack_bolt.adapter.aws_lambda import SlackRequestHandler
from slack_bolt.adapter.aws_lambda.lambda_s3_oauth_flow import LambdaS3OAuthFlow
import tldextract

logging.basicConfig(level=logging.DEBUG)

USERS_TABLE = os.environ['USERS_TABLE']
dynamo_resource = None
sns_client = None


def init_dynamo():
    global dynamo_resource
    if dynamo_resource is None:
        dynamo_resource = boto3.resource("dynamodb")


def init_sns():
    global sns_client
    if sns_client is None:
        sns_client = boto3.client("sns", region_name="us-east-1")


# Initializes your app using OAuth.
app = App(
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET"),
    process_before_response=True,
    oauth_flow=LambdaS3OAuthFlow(),
)


# Listens to incoming messages that contain "hello"
# To learn available listener arguments, visit:
# https://slack.dev/bolt-python/api-docs/slack_bolt/kwargs_injection/args.html
@app.message("hello")
def message_hello(message, say):
    init_dynamo()
    say(f"Hey there <@{message['user']}>! :wave:")
    resp = dynamo_resource.put_item(
        TableName=USERS_TABLE,
        Item={
            'userId': {'S': 'fred01'},
            'name': {'S': 'Fred D'}
        }
    )
    say(f"{resp}")


@app.message("whois")
def message_whois(message, say):
    # name = get_user('fred01')
    name = 'Bob'
    say(f"Name is {name}")


@app.command("/clear-translations")
def command_sample_command(ack, respond, command):
    """ Slack command to clear the cache for a url and its translations. """

    ack()
    respond(" . .. ...")

    pathParam = command["text"]
    pathDict = pathParam.split(" ")

    user_id = command["user_id"]

    context = {
        'channel_id': command["channel_id"],
        'team_id': command["team_id"],
        'user_id': command["user_id"],
        'user_name': command["user_name"],
        'command': command["command"],
        'text': command["text"]
    }

    if not check_permission(user_id, command["command"]):
        respond("No permission to do this")
        return "ERR"

    logging.info(f"Clearing for translated paths: {pathParam}")
    response = "OK" # Some action to be performed here.

    if (response == "OK"):
        respond(f"Cache cleared (with translations) for {pathParam} ! :broom:")
    else:
        respond("Invalid command. :cry:")

    return response


def user_parse_string(user_string):
    """
    Parses user info from the Slack encoded form.
    >>> user_parse_string("<@U0LPPP5RT|Joe>")
    ('U0LPPP5RT', 'Joe')
    """
    user_id = None
    user_name = None

    # Strip all the extra bits that pad the info we're looking for.
    user_string = user_string.lstrip("<")
    user_string = user_string.lstrip("@")
    user_string = user_string.rstrip(">")
    user_parts = user_string.split("|")

    if (len(user_parts) != 2):
        return "ERR", "ERR"

    user_id = user_parts[0]
    user_name = user_parts[1]

    return user_id, user_name


def link_parse_string(url_string):
    """
    Parses link info from the Slack encoded form.
    >>> link_parse_string("<http://example.com|example.com>")
    'http://example.com'
    """
    url_link = None
    url_text = None

    # Strip all the extra bits that pad the info we're looking for.
    url_string = url_string.lstrip("<")
    url_string = url_string.lstrip("@")
    url_string = url_string.rstrip(">")
    url_parts = url_string.split("|")

    if (len(url_parts) != 2):
        return "ERR", "ERR"

    url_link = url_parts[0]
    # If needed: url_text = url_parts[1]

    return url_link


def is_valid_role(role):
    # Todo: Move to enum, centrally defined.
    role_list = ("basic", "admin")
    if role in role_list:
        return True
    else:
        return False


@app.command("/cc-add-role")
def command_add_role(ack, respond, command):
    """ Slack command to add a role to a user . """

    ack()
    respond(" ... ... .")

    executing_user_id = command['user_id']
    # Ensure the user has permissions to do this.
    if not check_permission(executing_user_id, command["command"]):
        respond("No permission to do this")
        return "ERR"

    params = command["text"].split(" ")
    if (len(params) < 2):
        respond("Invalid command. :cry: (#481)")
        response = "ERR"
        return response
    role = params[0]
    target_user = params[1]
    user_id, user_name = user_parse_string(target_user)

    if (user_id == "ERR"):
        respond("Invalid username. :cry: (#482)")
        response = "ERR"
        return response

    if not is_valid_role(role):
        respond("Invalid role. :cry: (#483)")
        response = "ERR"
        return response

    user = get_user(user_id)
    logging.info(f"Adding role: {command['text']}")
    response = add_role(user, role)

    if (response == "OK"):
        respond(f"{role} added for {user_name} ! :medal:")
    else:
        respond("Invalid command. :cry:")

    return response


@app.command("/cc-remove-role")
def command_remove_role(ack, respond, command):
    """ Slack command to remove a role from a user . """

    ack()
    respond(" .. .... .")
    logging.info("#482")
    logging.info(str(command))

    executing_user_id = command['user_id']
    # Ensure the user has permissions to do this.
    if not check_permission(executing_user_id, command["command"]):
        respond("No permission to do this")
        return "ERR"

    params = command["text"].split(" ")
    if (len(params) < 2):
        respond("Invalid command. :cry: (#481)")
        response = "ERR"
        return response
    role = params[0]
    target_user_string = params[1]
    user_id, user_name = user_parse_string(target_user_string)

    if (user_id == "ERR"):
        respond("Invalid username. :cry: (#482)")
        response = "ERR"
        return response

    # Load the user object.
    user = get_user(user_id)

    if user == "ERR":
        return "ERR"

    # Check the role requested to be removed is valid.
    if not is_valid_role(role):
        respond("Invalid role. :cry: (#483)")
        response = "ERR"
        return response

    # Check that the role is present on the user.
    if has_role(user, role):
        logging.info(f"Removing role: {command['text']}")
        response = remove_role(user, role)
    else:
        respond("No matching user + role found. :cry: (#484)")
        response = "ERR"
        return response

    if (response == "OK"):
        respond(f"{role} removed for {user_name} ! :medal:")
    else:
        respond("Invalid command. :cry:")

    return response


@app.command("/cc-user-info")
def command_user_info(ack, respond, command):
    """ Slack command to retrieve the information for a specific user. """

    ack()
    respond(" ... .. .")
    logging.info("#489")
    logging.info(str(command))
    params = command["text"].split(" ")
    if (len(params) > 1):
        respond("Invalid command. Use /cc-user-info @user-name  :cry: (#487)")
        response = "ERR"
        return response
    user_string = params[0]
    user_id, user_name = user_parse_string(user_string)

    if (user_id == "ERR"):
        respond("Invalid username. :cry: (#482)")
        response = "ERR"
        return response

    # Load the user object.
    user = get_user(user_id)

    if user == "ERR":
        return "ERR"

    user_info_string = f"*Profile for: {user['name']}* \n "
    if 'roles' in user:
        user_info_string += f"Roles: {' '.join(user['roles'])} \n"
    else:
        user_info_string += "Roles: none \n"
    # user_info_string += "Last used:  \n"
    response = "OK"

    if (response == "OK"):
        respond(user_info_string)
    else:
        respond("Invalid command. :cry:")

    return response


def get_domain(url):
    """ Gets the domain part of a url
    >>> get_domain("https://www.example.com/some-url")
    'example.com'
    """

    # Check if a url has been encoded, and if so, parse accordingly.
    if url[0] == "<":
        url = link_parse_string(url)

    urlObj = tldextract.extract(url)
    return f"{urlObj.domain}.{urlObj.suffix}"



def enqueue_task(url_list, context=None):

    init_sns()
    topic_arn = os.environ.get("PURGE_TOPIC")

    message = {
        'data': url_list,
        'context': context
    }

    print(f"Enqueueing items {url_list}")

    response = sns_client.publish(TopicArn=topic_arn, Message=f"{message}")
    logging.debug(f"SNS Publish Response: {response}")

    if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
        return "OK"
    else:
        return "ERR"


def dequeue_task(event, context):
    import ast

    logging.info(f"Item dequeued {event}")

    message = event['Records'][0]['Sns']['Message']
    message_object = ast.literal_eval(message)
    # Separate the received message into the data and context components.
    path_list = message_object["data"]
    context = message_object["context"]

    # Pass the tasks information on to the relevant function.
    # clear_url(path_list, context=context)
    return "OK"


def message_channel(text, context):
    channel_id = context["channel_id"]
    team_id = context["team_id"]
    # Fetch the auth token from the installation store.
    bot = app.installation_store.find_bot(enterprise_id=None, team_id=team_id)
    app.client.chat_postMessage(
        token=bot.bot_token,
        channel=channel_id,
        text=text
    )


def message_user(text, context):
    channel_id = context["user_id"]
    team_id = context["team_id"]
    # Fetch the auth token from the installation store.
    bot = app.installation_store.find_bot(enterprise_id=None, team_id=team_id)
    app.client.chat_postMessage(
        token=bot.bot_token,
        channel=channel_id,
        text=text
    )


def get_user(user_id):
    init_dynamo()
    table = dynamo_resource.Table(USERS_TABLE)

    resp = table.get_item(
        Key={
            'userId': user_id
        }
    )
    item = resp.get('Item')
    if not item:
        return "ERR"

    # Check and initialize additional properties if not present.
    if 'roles' not in item:
        item['roles'] = list()

    return item


def get_roles(user):
    if 'roles' not in user:
        user['roles'] = list()

    return user['roles']


def add_role(user, role):
    """ Add a specified role to a user """
    roles = get_roles(user)
    if role not in roles:
        roles.append(role)
    # Lists are unhashable, convert to tuple.
    roles = tuple(roles)

    response = save_user(user)
    return response


def save_user(user):
    """
    Persist the user to the DB.
    """
    init_dynamo()
    table = dynamo_resource.Table(USERS_TABLE)
    result = table.put_item(
        Item=user
    )
    if result:
        return "OK"
    else:
        return "ERR"


def remove_role(user, role):
    """
    Remove a specified role from the user object.
    """
    roles_list = list(user["roles"])
    if role in roles_list:
        roles_list.remove(role)
    # Convert back to a tuple so it is hashable.
    user["roles"] = tuple(roles_list)
    # Save the user.
    response = save_user(user)
    return response


def has_role(user, role):
    """
    Returns whether or not a user has a specified role..
    """

    if not is_valid_role(role):
        return "ERR"

    if "roles" not in user:
        return False

    roles = user["roles"]

    if role in roles:
        return True
    else:
        return False


def check_permission(user_id, command):
    """
    Check if a particular user has permission to run a particular command.
    """
    # Load the user object.
    user = get_user(user_id)

    if user == "ERR":
        return False

    if has_role(user, 'admin'):
        return True

    # For the command to clear specific urls, 'basic' role is sufficient.
    if command == "/clear-url":
        if has_role(user, 'basic'):
            # Check that the user has access to this site.
            return True

    # If we've reached this point without granting access, access is denied.
    return False


def is_sns_event(event):
    # A bit ugly, but prefer this to throw/catch, and can improve later.
    if 'Records' in event:
        if 'Sns' in event['Records'][0]:
            return True
    return False


def handler(event, context):
    logging.debug("App handler called: {event} | {context}")

    # If this request came via SNS Purge topic, direct to appropriate dequeueing function.
    if is_sns_event(event):
        return dequeue_task(event, context)

    # Otherwise this is a request via the API (from a Slack message received).
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)
