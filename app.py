import os
import CloudFlare
import boto3
import logging
from slack_bolt import App
from slack_bolt.adapter.aws_lambda import SlackRequestHandler

logging.basicConfig(level=logging.DEBUG)


USERS_TABLE = os.environ['USERS_TABLE']
IS_OFFLINE = os.environ.get('IS_OFFLINE')

# Run DynamoDB either locally or via AWS.
if IS_OFFLINE:
    client = boto3.client(
        'dynamodb',
        region_name='localhost',
        endpoint_url='http://localhost:8000'
    )
else:
    client = boto3.client('dynamodb')


# Initializes your app with your bot token
app = App(
    token=os.environ.get("SLACK_BOT_TOKEN"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET"),
    process_before_response=True
)


# Listens to incoming messages that contain "hello"
# To learn available listener arguments, visit:
# https://slack.dev/bolt-python/api-docs/slack_bolt/kwargs_injection/args.html
@app.message("hello")
def message_hello(message, say):
    say(f"Hey there <@{message['user']}>!! :wave:")
    resp = client.put_item(
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
def message_clear(ack, respond, command):
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

    logging.info(f"Clearing for paths: {pathParam}")
    response = clear_url(pathDict)

    if (response == "OK"):
        respond(f"Cache cleared for {pathParam} ! :broom:")
    else:
        respond("Invalid command. :sad:")

    return response


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
    resp = client.get_item(
        TableName=USERS_TABLE,
        Key={
            'userId': {'S': user_id}
        }
    )
    item = resp.get('Item')
    if not item:
        return {'error': 'User does not exist', 'name': 'Error'}
    return item


def handler(event, context):
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)
