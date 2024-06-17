from flask import Flask, request, jsonify, send_file
from google.cloud import datastore
from google.cloud import storage
import io

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

COURSES = "courses"
USERS = "users"
AVATAR_BUCKET = "hw6_avatar_dixonbre"

# Update the values of the following 3 variables
CLIENT_ID = ''
CLIENT_SECRET = ''
DOMAIN = ''
# For example
# DOMAIN = 'xxxxxxxxx.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

ERROR_400 = {"Error": "The request body is invalid"}
ERROR_401 = {"Error": "Unauthorized"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {"Error": "Not found"}


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError(ERROR_401, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError(ERROR_401, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError(ERROR_401, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Welcome to the API"


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if 'username' not in content:
        return ERROR_400, 400
    if 'password' not in content:
        return ERROR_400, 400
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    if r.status_code == 403:
        return ERROR_401, 401
    if r.status_code == 429:
        return ERROR_401, 401
    j = r.json()
    ret = {"token": j["id_token"]}
    if r.status_code == 403:
        return ERROR_401, 401
    return ret, 200  # {'Content-Type': 'application/json'}


@app.route('/users', methods=['GET'])
def get_all_users():
    if request.method == 'GET':
        payload = verify_jwt(request)
        users_admin_query = client.query(kind=USERS)
        users_admin_query.add_filter('role', '=', 'admin')
        users_admin_query_results = users_admin_query.fetch()
        for i in users_admin_query_results:
            print(i['sub'])
            if payload['sub'] != i['sub']:
                return ERROR_403, 403

        users_query = client.query(kind=USERS)
        users_query_results = list(users_query.fetch())
        if not users_query_results:
            return ERROR_403, 403
        else:
            rtn = []
            for result in users_query_results:
                ent = {'id': result.key.id, 'sub': result['sub'], 'role': result['role']}
                rtn.append(ent)
                ent = {}
            return rtn, 200


@app.route('/users/<int:id>', methods=['GET'])
def get_a_user(id):
    payload = verify_jwt(request)
    users_c_query = client.query(kind=USERS)
    users_c_query.add_filter('sub', '=', payload['sub'])
    users_admin_query_results = users_c_query.fetch()
    user_role = None
    for i in users_admin_query_results:
        print([i])
        user_role = i['role']
        if id != i.key.id:
            return ERROR_403, 403

    if user_role == 'admin':
        users_key = client.key(USERS, id)
        user = client.get(key=users_key)
        if not user:
            return ERROR_403, 403
        else:
            user['id'] = user.key.id
            if 'avatar' in user:
                user['avatar_url'] = request.url_root + 'users' + '/' + str(id) + '/avatar'
            return user, 200

    elif user_role == 'instructor':
        users_key = client.key(USERS, id)
        user = client.get(key=users_key)
        if not user:
            return ERROR_403, 403
        else:
            courses_q = client.query(kind=COURSES)
            courses_q.add_filter('instructor_id', '=', id)
            courses = list(courses_q.fetch())
            c = []
            for i in courses:
                print(i.key.id)
                c.append(i.key.id)
            user['id'] = user.key.id
            user['courses'] = c
            if 'avatar' in user:
                user['avatar_url'] = request.url_root + 'users' + '/' + str(id) + '/avatar'

            return user, 200

    elif user_role == 'student':
        users_key = client.key(USERS, id)
        user = client.get(key=users_key)
        if not user:
            return ERROR_403, 403
        else:
            s_courses = []
            courses_q = client.query(kind=COURSES)
            courses = list(courses_q.fetch())
            for i in courses:
                if id in i['students']:
                    s_courses.append(i.key.id)
                print(i)
            user['courses'] = s_courses
            user['id'] = user.key.id
            if 'avatar' in user:
                user['avatar_url'] = request.url_root + 'users' + '/' + str(id) + '/avatar'
                ret = dict(user)
                ret.pop('avatar')
                return ret, 200
            else:
                return user, 200


@app.route('/users/<int:id>/avatar', methods=['POST'])
def create_update_user_avatar(id):
    if 'file' not in request.files:
        return ERROR_400, 400
    payload = verify_jwt(request)
    file_obj = request.files['file']
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob = bucket.blob(file_obj.filename)
    file_obj.seek(0)
    blob.upload_from_file(file_obj)
    users_key = client.key(USERS, id)
    user = client.get(key=users_key)
    if not user:
        return ERROR_403, 403
    if payload['sub'] != user['sub']:
        return ERROR_403, 403
    else:
        user['avatar'] = file_obj.filename
        client.put(user)
        ret = {'avatar_url': request.url_root + 'users' + '/' + str(id) + '/avatar'}
        return ret, 200


@app.route('/users/<int:id>/avatar', methods=['GET'])
def get_user_avatar(id):
    payload = verify_jwt(request)
    users_key = client.key(USERS, id)
    user = client.get(key=users_key)
    if not user:
        return ERROR_403, 403
    if payload['sub'] != user['sub']:
        return ERROR_403, 403
    else:
        if 'avatar' not in user:
            return ERROR_404, 404
        file_name = user['avatar']
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        blob = bucket.blob(file_name)
        file_obj = io.BytesIO()
        blob.download_to_file(file_obj)
        file_obj.seek(0)
        return send_file(file_obj, mimetype='image/x-png', download_name=file_name), 200


@app.route('/users/<int:id>/avatar', methods=['DELETE'])
def delete_user_avatar(id):
    payload = verify_jwt(request)
    users_key = client.key(USERS, id)
    user = client.get(key=users_key)
    if not user:
        return ERROR_403, 403
    if payload['sub'] != user['sub']:
        return ERROR_403, 403
    else:
        if 'avatar' not in user:
            return ERROR_404, 404
        file_name = user['avatar']
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        blob = bucket.blob(file_name)
        check = blob.exists(storage_client)
        if check:
            blob.delete()
            del user['avatar']
            client.put(user)
            return '', 204
        else:
            return ERROR_404, 404


def verify_term_json(tj):
    req = ["subject", "number", "title", "term", "instructor_id"]
    for i in req:
        if i not in tj:
            return False
    else:
        return True


@app.route('/courses', methods=['POST'])
def create_course():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        if not verify_term_json(content):
            return ERROR_400, 400
        users_c_query = client.query(kind=USERS)
        users_c_query.add_filter('sub', '=', payload['sub'])
        users_admin_query_results = users_c_query.fetch()
        user_role = None
        for i in users_admin_query_results:
            user_role = i['role']
            print(i)
        uid = content['instructor_id']
        users_key = client.key(USERS, uid)
        users = client.get(key=users_key)
        if users['role'] != 'instructor':
            return ERROR_400, 400

        if user_role != 'admin':
            return ERROR_403, 403

        if user_role == 'admin':
            new_course = datastore.Entity(key=client.key(COURSES))
            new_course.update({
                "subject": content['subject'],
                "number": content['number'],
                "title": content['title'],
                "term": content['term'],
                "instructor_id": content['instructor_id'],
                "students": [],
            })
            client.put(new_course)
            content['id'] = new_course.key.id
            content['self'] = request.url_root + 'courses/' + str(new_course.key.id)
            return content, 201
        else:
            return ERROR_403, 403


@app.route('/courses', methods=['GET'])
def get_all_courses():
    if request.method == 'GET':
        courses_query = client.query(kind=COURSES)
        courses_query.order = ['subject']
        courses_query_results = courses_query.fetch(limit=3, offset=0)
        pages = courses_query_results.pages
        results = list(next(pages))
        ret = {'courses': [], 'next': None}
        limit = 3
        offset = 0
        for result in results:
            result['id'] = result.key.id
            result['self'] = request.url_root + 'courses/' + str(result.key.id)
            ret['courses'].append(result)
            offset += 1
        ret['next'] = request.url_root + 'courses' + '?' + 'limit=' + str(limit) + '&' + 'offset=' + str(offset)
        return ret, 200


@app.route('/courses/<int:id>', methods=['GET'])
def get_a_course(id):
    course_key = client.key(COURSES, id)
    course = client.get(course_key)
    print(course)
    if course:
        course['id'] = course.key.id
        course['self'] = request.url_root + 'courses/' + str(id)
        return course, 200
    else:
        return ERROR_404, 404


@app.route('/courses/<int:id>', methods=['PATCH'])
def update_a_course(id):
    payload = verify_jwt(request)
    content = request.get_json()

    user_q = client.query(kind=USERS)
    user_q.add_filter('sub', '=', payload['sub'])
    users_q_results = user_q.fetch()

    for i in users_q_results:
        if i['role'] != 'admin':
            return ERROR_403, 403
        if 'instructor_id' in content:
            user_q2 = client.query(kind=USERS)
            user_q2.add_filter('role', '=', 'instructor')
            users_q2_results = user_q2.fetch()
            instructor_ids = []
            for j in users_q2_results:
                instructor_ids.append(j.key.id)
            if content['instructor_id'] not in instructor_ids:
                return ERROR_400, 400
    course_key = client.key(COURSES, id)
    course = client.get(course_key)
    if course:
        for i in content.keys():
            course.update({
                i: content[i]
            })
            client.put(course)
        return course, 200
    else:
        return ERROR_404, 404


@app.route('/courses/<int:id>', methods=['DELETE'])
def delete_a_course(id):
    payload = verify_jwt(request)
    user_q = client.query(kind=USERS)
    user_q.add_filter('sub', '=', payload['sub'])
    users_q_results = user_q.fetch()
    for i in users_q_results:
        if i['role'] != 'admin':
            return ERROR_403, 403
    course_key = client.key(COURSES, id)
    course = client.get(course_key)
    print(course)
    if course:
        client.delete(course)
        return '', 204
    else:
        return ERROR_404, 404


def verify_enrollment_json(e_json):
    adds = e_json['add']
    removes = e_json['remove']
    cl = adds + removes
    cls = set(cl)
    if len(cls) < len(cl):
        return False
    user_q = client.query(kind=USERS)
    users_q_results = list(user_q.fetch())
    user_q.add_filter('role', '=', 'student')
    vsids = []
    for result in users_q_results:
        vsids.append(result.key.id)
    for i in cl:
        if i not in vsids:
            return False

    return True


@app.route('/courses/<int:id>/students', methods=['PATCH'])
def update_enrollment(id):
    payload = verify_jwt(request)
    content = request.get_json()

    user_q = client.query(kind=USERS)
    user_q.add_filter('sub', '=', payload['sub'])
    users_q_results = user_q.fetch()

    for i in users_q_results:
        if i['role'] == 'student':
            print(i['role'])
            return ERROR_403, 403
        if i['role'] == 'instructor':
            user_q2 = client.query(kind=COURSES)
            user_q2.add_filter('instructor_id', '=', id)
            users_q2_results = user_q2.fetch()
            if not users_q2_results:
                return ERROR_403, 403

    if not verify_enrollment_json(content):
        return {"Error": "Enrollment data is invalid"}, 409

    course_key = client.key(COURSES, id)
    course = client.get(course_key)
    if course:
        print(course['students'])
        for i in content['add']:
            if i not in course['students']:
                course['students'].append(i)
        for i in content['remove']:
            if i in course['students']:
                course['students'].remove(i)
        client.put(course)
        return "", 200
    else:
        return ERROR_404, 404


@app.route('/courses/<int:id>/students', methods=['GET'])
def get_enrollment(id):
    payload = verify_jwt(request)
    user_q = client.query(kind=USERS)
    user_q.add_filter('sub', '=', payload['sub'])
    users_q_results = user_q.fetch()

    for i in users_q_results:
        if i['role'] == 'student':
            return ERROR_403, 403
        if i['role'] == 'instructor':
            q2 = client.query(kind=COURSES)
            q2.add_filter('instructor_id', '=', id)
            q2_results = q2.fetch()
            if not q2_results:
                return ERROR_403, 403

    course_key = client.key(COURSES, id)
    course = client.get(course_key)
    if course:
        ret = course['students']
        return ret, 200
    else:
        return ERROR_404, 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
