import os
import CloudFlare
import logging
logging.basicConfig(level=logging.DEBUG)

from CloudFlare.api_v4 import api_v4
from slack_bolt import App
from slack_bolt.adapter.aws_lambda import SlackRequestHandler


# Initializes your app with your bot token and socket mode handler
app = App(
    token=os.environ.get("SLACK_BOT_TOKEN"),
    signing_secret=os.environ.get("SLACK_SIGNING_SECRET"),
    process_before_response=True
)

# Listens to incoming messages that contain "hello"
# To learn available listener arguments,
# visit https://slack.dev/bolt-python/api-docs/slack_bolt/kwargs_injection/args.html
@app.message("hello")
def message_hello(message, say):
    say(f"Hey there <@{message['user']}>!")

@app.message("clear")
def message_clear(message, say):
    # Clear the cache for the whole site.
    cf = CloudFlare.CloudFlare()
    zones = cf.zones.get(params={'per_page':50})
    for zone in zones:
        zone_name = zone['name']
        zone_id = zone['id']
        print(zone_id, zone_name)
        cf.zones.purge_cache.post(
            zone_id,
            data={'purge_everything':True})
    # Inform the user.
    say(f"Cache being cleared ...")

SlackRequestHandler.clear_all_log_handlers()
logging.basicConfig(format="%(asctime)s %(message)s", level=logging.DEBUG)

def handler(event, context):
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)
