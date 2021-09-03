"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""
"""
Status Codes:
i)  The 'HTTP 200' OK success status response code indicates that the request has succeeded.
    A 200 response is cacheable by default. The meaning of a success depends on the HTTP request method:
    GET : The resource has been fetched and is transmitted in the message body

ii) The HyperText Transfer Protocol (HTTP) 405 Method Not Allowed response status code indicates that
    the request method is known by the server but is not supported by the target resource.
"""


def test_home_page_get(test_client):
    """
    GIVEN a Flask application configured for testing
    WHEN the '/' page is requested (GET)
    THEN check that the response is valid (i.e status_code = 200(OK))
    """
    response = test_client.get('/')
    assert response.status_code == 200
    assert b'Machine-Learning, Cryptography and Web-Development' in response.data
    response = test_client.get('/blogindex')
    assert response.status_code == 200
    assert b'CitadelBlog - A blog for everything software' in response.data
    response = test_client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data


def test_home_page_post(test_client):
    """
    GIVEN a Flask application
    WHEN the '/' page is is posted to (POST)
    THEN check that a '405' status code is returned
    """
    response = test_client.post('/')
    assert response.status_code == 405
    assert b"Citadel: Coding" not in response.data
