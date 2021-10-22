import os
import CloudFlare
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
    say(f"Hey there <@{message['user']}>!! :wave:")
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




@app.command("/clear")
def command_clear(ack, respond, command):
    ack()
    # Clear the cache for the whole site.
    cloudflare_key = os.environ.get("CF_API_KEY")
    cf = CloudFlare.CloudFlare(token=cloudflare_key)
    zones = cf.zones.get(params={'per_page': 50})
    for zone in zones:
        zone_name = zone['name']
        zone_id = zone['id']
        print(zone_id, zone_name)
        cf.zones.purge_cache.post(
            zone_id,
            data={'purge_everything': True})
    # Inform the user.
    respond("Cache being cleared.!! :broom:")


@app.command("/clear-url")
def command_clear_url(ack, respond, command):
    """ Slack command to clear the cache for a particular url . """

    ack()
    respond(" ... . ..")

    pathParam = command["text"]
    pathDict = pathParam.split(" ")

    context = {
        'channel_id': command["channel_id"],
        'team_id': command["team_id"],
        'user_id': command["user_id"],
        'user_name': command["user_name"],
        'command': command["command"],
        'text': command["text"]
    }

    user_id = command["user_id"]

    print("" + user_id + "|-|" + str(command))

    if not check_permission(user_id, command["command"]):
        respond("No permission to do this")
        return "ERR"

    logging.info(f"Clearing for paths: {pathParam}")
    response = clear_url(pathDict, context=context)

    if (response == "OK"):
        respond(f"Cache cleared for {pathParam} ! :broom:")
    else:
        respond("Invalid command. :cry:")

    return response


@app.command("/clear-translations")
def command_clear_url_translations(ack, respond, command):
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
    response = clear_url(pathDict, clear_translations=True, context=context)

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

    logging.info(f"Adding role: {command['text']}")
    response = add_role(user_id, role)

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
    user_info_string += f"Roles: {' '.join(user['roles'])} \n"
    # user_info_string += "Last used:  \n"
    response = "OK"

    if (response == "OK"):
        respond(user_info_string)
    else:
        respond("Invalid command. :cry:")

    return response


def get_user_by_name(name):
    init_dynamo()
    result = None
    user_id = "U0LPPP5RT"
    try:
        # Call the users.info method using the WebClient
        result = dynamo_resource.users_info(
            user=user_id
        )
        logging.info(result)

    except Error as e:
        logging.error("Error fetching conversations: {}".format(e))

    return result


def get_domain(url):
    """ Gets the domain part of a url
    >>> get_domain("https://www.example.com/some-url")
    'example.com'
    """

    urlObj = tldextract.extract(url)
    return f"{urlObj.domain}.{urlObj.suffix}"


def get_zone_id(path):
    """ Returns the matching Zone ID for a URL"""
    domain = get_domain(path)

    # Todo: Cache zone list for future calls.
    cloudflare_key = os.environ.get("CF_API_KEY")
    cf = CloudFlare.CloudFlare(token=cloudflare_key)
    zones = cf.zones.get(params={'per_page': 50})
    for zone in zones:
        logging.debug(f"available zone: {zone['id']}:{zone['name']}")
        if domain == zone['name']:
            return zone['id']
    return None


def validate_paths(pathList):

    """
    Validate a list of paths that has been passed.
    Separates invalid items.

    """

    newList = []
    invalidList = []

    # Checks that the domain of all urls match the first one.
    urlObj = tldextract.extract(pathList[0])
    firstDomain = f"{urlObj.domain}.{urlObj.suffix}"

    for path in pathList:
        urlObj = tldextract.extract(path)
        domain = f"{urlObj.domain}.{urlObj.suffix}"
        if domain == firstDomain:
            newList.append(path)
        else:
            invalidList.append(path)

    return newList, invalidList


def enqueue_clear_url(url_list, context=None):

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


def dequeue_clear_url(event, context):
    import ast

    logging.info(f"Item dequeued {event}")

    message = event['Records'][0]['Sns']['Message']
    message_object = ast.literal_eval(message)
    # Separate the received message into the data and context components.
    path_list = message_object["data"]
    context = message_object["context"]

    clear_url(path_list, context=context)
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


def clear_url(pathList, clear_translations=False, context=None):

    path = pathList[0]
    zone_id = get_zone_id(path)

    # If requested, we also enqueue the linked translations of the page.
    if clear_translations:
        for path in pathList:
            lang_list = get_hreflang_from_url(path)
            if len(lang_list) > 0:
                enqueue_clear_url(lang_list, context)

    # Check the paths are valid before proceeding to purge the cache.
    pathList, errorList = validate_paths(pathList)
    if zone_id and (len(pathList) > 0):
        cloudflare_key = os.environ.get("CF_API_KEY")
        cf = CloudFlare.CloudFlare(token=cloudflare_key)
        cf.zones.purge_cache.post(
            zone_id,
            data={'files': pathList})
        # Inform the user.
        if (len(errorList) > 0):
            message_channel(f"Partial urls cleared: {pathList}", context)
            return "PARTIAL"
        else:
            message_channel(f"Urls cleared: {pathList}", context)
            return "OK"
    else:
        message_channel("Couldn't clear urls", context)
        message_user("Couldn't clear urls", context)
        return "ERR"


SlackRequestHandler.clear_all_log_handlers()
logging.basicConfig(format="%(asctime)s %(message)s", level=logging.DEBUG)
logging.getLogger().addHandler(logging.StreamHandler())


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
    return item


def get_roles(user):
    if user['roles']:
        return user['roles']
    else:
        return list()


def add_role(user_id, role):
    """ Add a specified role to a user """
    init_dynamo()

    user = get_user(user_id)
    if user == "ERR":
        return "ERR"

    roles = get_roles(user)
    if role not in roles:
        roles.append(role)
    # Lists are unhashable, convert to tuple.
    roles = tuple(roles)
    table = dynamo_resource.Table(USERS_TABLE)
    result = table.put_item(
        Item=user
    )
    if result:
        return "OK"
    else:
        return "ERR"


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

    roles = user["roles"]

    if role in roles:
        return True
    else:
        return False


def check_permission(user_id, command, zone=None):
    """
    Check if a particular user has permission to run a particular command.
    """
    # Load the user object.
    user = get_user(user_id)

    if user == "ERR":
        return False

    if has_role(user, 'admin'):
        return True

    # Todo - Check that the user has access to this site.

    # For the command to clear specific urls, 'basic' role is sufficient.
    if command == "/clear-url":
        if has_role(user, 'basic'):
            return True

    # If we've reached this point without granting access, access is denied.
    return False


def get_hreflang_from_url(url):
    """ Fetches the hreflang tags from a particular url."""

    import requests
    from requests_html import HTMLSession

    hrefs = list()

    try:
        session = HTMLSession()
        response = session.get(url)
        # Look for specific tags, returning the href portion.
        hrefs = response.html.xpath("//link[@rel='alternate']/@href")
    except requests.exceptions.RequestException as e:
        logging.info(f"Error #822: {e}")
        return hrefs

    # If the urls are relative, then append the base url as per the original.
    for index, href in enumerate(hrefs):
        if "http" not in href:
            # Get base url
            from urllib.parse import urlparse
            parsed_uri = urlparse(url)
            domain = '{uri.scheme}://{uri.netloc}'.format(uri=parsed_uri)
            hrefs[index] = domain + href

    return hrefs


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
        return dequeue_clear_url(event, context)

    # Otherwise this is a request via the API (from a Slack message received).
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)
