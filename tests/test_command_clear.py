import os

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
