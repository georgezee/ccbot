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


def init_dynamo():
    global dynamo_resource
    if dynamo_resource is None:
        dynamo_resource = boto3.resource("dynamodb")

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

    user_id = command["user_id"]

    print("" + user_id + "|-|" + str(command))

    if not check_permission(user_id, command):
        respond("No permission to do this")
        return "ERR"

    logging.info(f"Clearing for paths: {pathParam}")
    response = clear_url(pathDict)

    if (response == "OK"):
        respond(f"Cache cleared for {pathParam} ! :broom:")
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
    params = command["text"].split(" ")
    if (len(params) < 2):
        respond("Invalid command. :cry: (#481)")
        response = "ERR"
        return response
    role = params[0]
    user = params[1]
    user_id, user_name = user_parse_string(user)

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
    params = command["text"].split(" ")
    if (len(params) < 2):
        respond("Invalid command. :cry: (#481)")
        response = "ERR"
        return response
    role = params[0]
    user_string = params[1]
    user_id, user_name = user_parse_string(user_string)

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


def clear_url(pathList):

    path = pathList[0]

    zone_id = get_zone_id(path)

    pathList, errorList = validate_paths(pathList)
    if zone_id and (len(pathList) > 0):
        cloudflare_key = os.environ.get("CF_API_KEY")
        cf = CloudFlare.CloudFlare(token=cloudflare_key)
        cf.zones.purge_cache.post(
            zone_id,
            data={'files': pathList})
        # Inform the user.
        if (len(errorList) > 0):
            return "PARTIAL"
        else:
            return "OK"
    else:
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


def get_roles(user_id):
    # Placeholder function.
    return []


def add_role(user_id, user_name, role):
    # Todo: User should be able to have multiple roles.
    init_dynamo()
    print(user_id + "|||" + user_name + "{{{{" + role)
    roles = get_roles(user_id)
    if role not in roles:
        roles.append(role)
    # Lists are unhashable, convert to tuple.
    roles = tuple(roles)
    table = dynamo_resource.Table(USERS_TABLE)
    result = table.put_item(
        Item={
            'userId': user_id,
            'name': user_name,
            'roles': (roles)
        }
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

    # Initially we just get if a user exists in the DB or not.
    result = get_user(user_id)

    # Todo - Check that the user has access to this site.

    # Todo - Check that the user has access to this command.

    if result == "ERR":
        return False
    else:
        return True


def handler(event, context):
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)
