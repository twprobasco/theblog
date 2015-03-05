import webapp2
import os
import jinja2
import re
import random
import string
import hashlib

from google.appengine.ext import db

# specify path for html templates and jinja envornment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

### Database objects

## Users - stores registered users information. Inherits from db.Model
##  - username: username provided by user at registration. Required and unique
##  - pw_hash: the hashed version of the password provided by the user
##             at registration and salt. Required
##  - salt: automatically generated salt value by funtion generate_salt(). Required
##  - email: email provided by user at registration. Not required
##  - joined: auto generated datetime when the user account was created
class Users(db.Model):
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    joined = db.DateTimeProperty(auto_now_add = True)

## Posts - stores posts and associated information. Inherits from db.Model
##  - title: the title of the post. Required
##  - content: the content of the post. Required
##  - user_id: the user_id of the owner of the post. id property from Users
##             used for this field. Required
##  - created: auto generated datetime when the post was created
class Posts(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    user_id = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    # render() - helper function to format the posts for a browser window
    #            by replacing all newlines/carriage-returns \n with html
    #            line breaks <br>
    def render(self):
        self._render_test = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)

### Event Handlers

## Handler - Superclass for all handlers in this program. Provides convenience
##           functions. Inherits from webapp2.RequestHandler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

## MainHandler - Handler for '/'
class MainHandler(Handler):
    # get() - if the user navigates to '/', redirect them to '/login'
    def get(self):
        self.redirect('/login')

## LoginHandler - Handler for '/login'
class LoginHandler(Handler):
    # render_login() - render login.html with the forms populated with
    #                  passed in data or default to blank
    #   - username - 
    def render_login(self, username = '', password = '', login_error = ''):
        self.render('login.html',
                    username = username,
                    password = password,
                    login_error = login_error)

    def post(self):
        # get data from form fields of the html form
        username = self.request.get('username')
        password = self.request.get('password')

        # login_error defaults to blank, essentially assuming no error
        login_error = ''

        # check username and password validity against regular expressions
        username_valid = valid_username(username)
        password_valid = valid_password(password)

        # if both username and password were submitted and they were valid
        if username and password and username_valid and password_valid:
            # attempt to create a new user object on the username in the Users db
            user = Users.gql('WHERE username=:1', username).get()
            # if the creation of user was successful, the user exists in the db
            if user:
                # create a hash of the password from the form and the salt from
                # the db. The hash returns in the form of <pw_hash>|<salt>
                # so split the returned string and take the first element, which
                # is just the hashed password
                h = hash_pw(password, user.salt).split('|')[0]
                # compare the hashed password with the hash in the db. If they
                # match, we have a valid login attempt
                if h == user.pw_hash:
                    # get the id from the db and store in user_id as a string
                    user_id = str(user.key().id())
                    # create and set the user_id cookie in the format:
                    #   user_id=<user_id>|<pw_hash>
                    self.response.headers['Content-Type'] = 'text/plain'
                    cookie = str('user_id=%s|%s' % (user_id, h))
                    self.response.headers.add_header('Set-Cookie', cookie)
                    # redirect to the front page of the blog /front
                    self.redirect('/front')
                # if the hashed password and the hash in the db don't match,
                # we have an invalid login attempt. Inform the user.
                else:
                    login_error = 'Username or password incorrect'
            # if the creation of the user was not successful, then no such user
            # exists in the db. Inform the user.
            else:
                login_error = 'Username or password incorrect'
        # if we are missing either the username or password, or if either
        # contatins invalid characters, we cannot proceed with the login.
        # Inform the user.
        else:
            login_error = 'Please enter a valid username and password'

        # reaching this point means we had an error at some point in the
        # login attempt. Render the login page with any errors. Keep the
        # user supplied username, but clear the password field.
        self.render_login(username = username, login_error = login_error)
    
    def get(self):
        self.render_login()

class SignupHandler(Handler):
    def render_signup(self, username = '', password = '',
                      password_verify = '', email = '',
                      username_error = '', pw_error = '', pw_v_error = '',
                      email_error = ''):
        self.render('signup.html', username = username,
                    password = password,
                    password_verify = password_verify,
                    email = email,
                    username_error = username_error,
                    pw_error = pw_error,
                    pw_v_error = pw_v_error,
                    email_error = email_error)

    def post(self):
        # get data from form fields in the html form
        username = self.request.get('username')
        password = self.request.get('password')
        password_verify = self.request.get('password_verify')
        email = self.request.get('email')

        # default error strings to blank, assuming no errors at this point
        username_error = ''
        pw_error = ''
        pw_v_error = ''
        email_error = ''

        # check validity of all form submitted 
        username_valid = valid_username(username)
        password_valid = valid_password(password)
        matching_passwords = password_match(password, password_verify)
        username_available = available_username(username)

        # set email_valid to false to avoid runtime errors
        email_valid = False;

        # email entry is optional. check to see if the email was given. If so, the next
        # check can be run. If not, skip this part
        if email:
            # if an email was entered check it's validity
            email_valid = valid_email(email)
        # if we received a username, password, and password_verify from the form, we can proceed
        if username and password and password_verify:
            # if the username and password were valid, the password and password_verify match, and the username is available, we can proceed
            if username_valid and password_valid and matching_passwords and username_available:
                # if an email was entered, but it was not valid, set the email_error value appropriately
                if email and not email_valid:
                    email_error = "Email invalid"
                # if there was no email, or if the email was given and it was valid, we can proceed
                else:
                    # create a hash of the password from the form
                    h = hash_pw(password)
                    # create a new user for the Users db with the given username, pw_hash and salt. The hash_pw return from the previous step
                    # gave a string of format <hash>|<salt>, so split the two to get the appropriate portions to their respective variables
                    new_user = Users(username = username,
                                     pw_hash = h.split('|')[0],
                                     salt = h.split('|')[1])
                    # store the newly created user in the Users db
                    new_user.put()
                    # if there was an email given and it was valid, store the email in the db
                    if email and email_valid:
                        new_user.email = email
                    # get the autogenerated id for the new user in the db. Store it as a string
                    user_id = str(new_user.key().id())
                    # create and set the user_id cookie in the format:
                    #   user_id=<user_id>|<pw_hash>
                    self.response.headers['Content-Type'] = 'text/plain'
                    self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s'
                                                     % (user_id, h.split('|')[0]))
                    # redirect the user to the newly created front page
                    self.redirect('/front')
            # if either the username or the password were invalid, or both, or if the username was unavailable, or if the passwords do not
            # match, set the errors as appropriate.
            else:
                if not username_valid:
                    username_error = "Invalid username"
                if not password_valid:
                    pw_error = "Invalid password"
                if not username_available:
                    username_error = "Username unavailable"
                if not matching_passwords:
                    pw_v_error = "Passwords do not match"
        # if we did not receive a username, password, or password vrification, set the errors as appropriate
        else:
            if not username:
                username_error = "Enter username"
            if not password:
                pw_error = "Enter password"
            if not password_verify:
                pw_v_error = "Enter password"

        # if we got to this point something went wrong with the registration process. Clear the password and password verification
        # and render the signup page with errors
        password = ''
        password_verify = ''
        self.render_signup(username, password, password_verify, email,
                                    username_error, pw_error, pw_v_error,
                                    email_error)
    
    def get(self):
        self.render_signup()

class LogoutHandler(Handler):
    def get(self):
        # set the expiration date of the user_id cookie in the past, effectively deleting it from the browser. Unless the
        # user has their computer date and time set to before Jan 1 1970. In which case they have problems

        ###### Consider another way to do this.
        self.response.headers['Content-Type'] = 'text/plain'
        cookie = str('user_id=;Expires=Thu, 01-Jan-1970 00:00:10 GMT')
        self.response.headers.add_header('Set-Cookie', cookie)
        self.redirect('/login')

class FrontHandler(Handler):
    def render_front(self):
        # get the user_id cookie from the browser
        cookie = self.request.cookies.get('user_id')
        if cookie:
            # if there was a user_id cookie, get both the listed user_id and the password hash. Store them separately
            user_id = cookie.split('|')[0]
            hash_cookie = cookie.split('|')[1]
            # get the User object from the db associated with the user_id
            user = Users.get_by_id(int(user_id))
            hash_db = ''
            if user:
                # if user_id exists in the db, get the hash stored in the db
                hash_db = user.pw_hash
            if hash_match(hash_cookie, hash_db):
                # if the hash from the db and the hash from the browser match, get all posts associated with the user from the db
                blogposts = db.GqlQuery("SELECT * "
                                        "FROM Posts "
                                        "WHERE user_id=:1 "
                                        "ORDER BY created DESC "
                                        "LIMIT 10",
                                        user_id)
                # render front.html with the posts
                self.render('front.html', username = user.username, blogposts = blogposts)
            else:
                # if the hash didn't match, redirect to logout
                self.redirect('/logout')
        else:
            # if there was no cookie called "user_id" redirect to logout
            self.redirect('/logout')

    def get(self):
        self.render_front()

class NewpostHandler(Handler):
    def render_newpost(self, title='', content='', error=''):
        cookie = self.request.cookies.get('user_id')
        if cookie:
            user_id = cookie.split('|')[0]
            hash_cookie = cookie.split('|')[1]
            user = Users.get_by_id(int(user_id))
            hash_db = ''
            if user:
                hash_db = user.pw_hash
            if hash_match(hash_cookie, hash_db):
                self.render('newpost.html',
                            title = title,
                            content = content,
                            error = error)
            else:
                self.redirect('/logout')
        else:
            self.redirect('/logout')

    def post(self):
        title = self.request.get("title")
        content = self.request.get("content")

        cookie = self.request.cookies.get('user_id')

        if cookie:
            user_id = cookie.split('|')[0]
            hash_cookie = cookie.split('|')[1]
            user = Users.get_by_id(int(user_id))
            hash_db = ''
            if user:
                hash_db = user.pw_hash
            if hash_match(hash_cookie, hash_db):
                if title and content:
                    newpost = Posts(title = title,
                                    content = content,
                                    user_id = user_id)
                    newpost.put()
                    permalink = str(newpost.key().id())
                    self.redirect('/%s' %permalink)
                else:
                    error = "Please enter a title and some content"
                    self.render_newpost(title, content, error)
        else:
            self.redirect('/logout')
    
    def get(self):
        self.render_newpost()

class PostHandler(Handler):
    def get(self, post_id):
        post = Posts.get_by_id(int(post_id))
        if post:
            self.render_post(post)

    def render_post(self, post):
        self.render("permalink.html",
                    title = post.title,
                    content = post.content,
                    created = post.created)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile("^.{3,20}$")
def valid_password(password):
    return PASS_RE.match(password)

EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)

def hash_pw(password, salt = None):
    if not salt:
        salt = generate_salt(5)
    h = hashlib.sha256(password + salt).hexdigest()
    return "%s|%s" % (h, salt)

def generate_salt(salt_length):
    return ''.join(random.choice(string.letters) for x in xrange(salt_length))

def password_match(pw, pw_verify):
    return pw == pw_verify

def hash_match(hash1, hash2):
    return hash1 == hash2

def available_username(username):
    available = True
    user = Users.gql("Where username=:1", username).get()
    if user:
        available = False

    return available

app = webapp2.WSGIApplication([('/', MainHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/front', FrontHandler),
                               ('/signup', SignupHandler),
                               ('/newpost', NewpostHandler),
                               ('/([0-9]+)', PostHandler)
                               ], debug=True)
