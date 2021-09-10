import os
import pytest

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
@pytest.mark.parametrize(
    "domain,value",
    [
        ('https://www.example.com/some-url.htm', 'example.co'),
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
        ('https://www.rainfall.com/some-url.htm', None),
        ('https://www.example.com/some-url.htm', None)
    ]
)
def test_command_get_zone(domain, value):

    import app

    response = app.get_zone_id(domain)
    assert response == value
