# CC Bot
Python serverless chatbot framework used for CDN cache clearing.

This chat bot receives commands from users and issues associated requests
to a CDN to purge the relevant items from the cache.

## Tech Stack:
- Slack (for interacting with the bot)
- Python (the back end programming language)
- Bolt (the Slack framework for creating bots)
- AWS API Gateway (for receiving requests as the bot)
- AWS Lambda (for hosting the code without managed servers)
- Serverless Framework (for organising the associated pieces)

## Requirements:

### Accounts
1. Slack Bot
2. Amazon AWS

### Packages
- Serverless framework
- Python 3.x
- Node
- Docker
- AWS CLI

## Setup Steps:
1. Setup Slack Bot and get Bot token and Signing secret.
2. Retrieve AWS Access key and Secret key.
3. Install the relevant packages.
4. Set relevant Environment variables:
- SLACK_SIGNING_SECRET
- SLACK_BOT_TOKEN
5. Deploy serverless app.
6. Copy API endpoint to Slack Bot endpoints.

