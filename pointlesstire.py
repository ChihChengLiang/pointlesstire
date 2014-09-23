#!/usr/bin/python
# -*- coding: utf-8 -*-

import webapp2
import os
from google.appengine.ext.webapp import template
import cgi
import string
import re
from jinja2 import Environment, FileSystemLoader
from google.appengine.ext import db
import hmac
import random
import hashlib
import json
from xml.dom import minidom
from datetime import datetime, timedelta
from google.appengine.api import memcache

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile(r"^.{3,20}$")
EML_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

alphabet_list = list(string.lowercase)

secret_key = '17FG&T8T6;-zCi:_&eLJ8gJf?.B;wy'


def make_hash(val):
    return '%s|%s' % (val, hmac.new(secret_key, val).hexdigest())


def check_hash(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_hash(val):
        return val


class BaseHandler(webapp2.RequestHandler):

    def write(self, filename, **template_values):
        path = os.path.join(os.path.dirname(__file__), filename)
        self.response.out.write(template.render(path, template_values))

    def render(self, filename, **template_values):
        jinja_env = Environment(loader=FileSystemLoader('templates'))
        template = jinja_env.get_template(filename)
        self.response.out.write(template.render(template_values))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = \
            'application/json; charset=UTF-8'
        self.response.out.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_hash(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s ; path=/'
                % (str(name), str(cookie_val)))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_hash(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie',
                'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainHandler(webapp2.RequestHandler):

    def get(self):
        template_values = {'name': 'World'}

        path = os.path.join(os.path.dirname(__file__), 'index.html')
        self.response.out.write(template.render(path, template_values))


class ROT13(webapp2.RequestHandler):

    def get(self):
        template_values = {'default_text': ''}
        path = os.path.join(os.path.dirname(__file__), 'ROT13.html')
        self.response.out.write(template.render(path, template_values))

    def post(self):
        text = self.request.get('text')
        output = ''
        for t in text:
            if t.isalpha():
                s = alphabet_list[(alphabet_list.index(t.lower()) + 13)
                                  % 26]
                if t.isupper():
                    s = s.upper()
                output += s
            else:
                output += t
        template_values = {'default_text': cgi.escape(output,
                           quote=True)}
        path = os.path.join(os.path.dirname(__file__), 'ROT13.html')
        self.response.out.write(template.render(path, template_values))


class SignUp(webapp2.RequestHandler):

    def get(self):
        template_values = {
            'user_error': '',
            'pwd_error': '',
            'vrypwd_error': '',
            'email_error': '',
            }
        path = os.path.join(os.path.dirname(__file__), 'signup.html')
        self.response.out.write(template.render(path, template_values))

    def post(self):
        username = self.request.get('username')

        user_correct = USER_RE.match(username)
        pwd_correct = PWD_RE.match(self.request.get('password'))
        vrypwd_correct = self.request.get('password') \
            == self.request.get('verify')
        email_correct = EML_RE.match(self.request.get('email'))
        error_msg = {
            'user_error': "That's not a valid username.",
            'pwd_error': "That wasn't a valid password.",
            'vrypwd_error': "Your passwords didn't match.",
            'email_error': "That's not a valid email.",
            }
        if user_correct and pwd_correct and vrypwd_correct \
            and email_correct:

            self.redirect('/welcome?username=' + cgi.escape(username,
                          quote=True))
        else:
            if user_correct:
                error_msg['user_error'] = ''
            if pwd_correct:
                error_msg['pwd_error'] = ''
            if vrypwd_correct:
                error_msg['vrypwd_error'] = ''
            if email_correct:
                error_msg['email_error'] = ''
            path = os.path.join(os.path.dirname(__file__), 'signup.html'
                                )
            self.response.out.write(template.render(path, error_msg))
        pass


class Welcome(webapp2.RequestHandler):

    def get(self):
        self.response.out.write('<h1>Welcom,'
                                + self.request.get('username')
                                + '!</h1>')


class FizzBuzz(webapp2.RequestHandler):

    def get(self):
        n = self.request.get('n')
        n = n and int(n)
        jinja_env = Environment(loader=FileSystemLoader('templates'))
        template = jinja_env.get_template('FizzBuzz.html')
        self.response.out.write(template.render(n=n))


    # self.response.out.write("<h1>Python code work fine!n=%d</h1>" % n)

## The blog #########################

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class BlogModel(db.Model):

    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Blog(BaseHandler):

    def queryPost(self):
        return db.GqlQuery('select * from BlogModel order by created desc limit 10'
                           )

    def get(self):
        posts = self.queryPost()

        self.render('blog_main.html', posts=posts)


class BlogNewPost(BaseHandler):

    def get(self):
        self.render('blog_newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            a = BlogModel(parent=blog_key(), subject=subject,
                          content=content)
            a.put()
            self.redirect('/blog/%s' % str(a.key().id()))
        else:
            self.render('blog_newpost.html', error=True)


class PostPage(BaseHandler):

    def getkey(self, post_id):
        key = db.Key.from_path('BlogModel', int(post_id),
                               parent=blog_key())
        return db.get(key)

    def get(self, post_id):
        post_key = 'POST_' + post_id
        (post, age) = age_get(post_key)
        if not post:
            post = self.getkey(post_id)
            age_set(post_key, post)
            age = 0

        if not post:
            self.render('custom404.html')
            return
        self.render('blog_permalink.html', post=post, age=age_str(age))


# Unit 4

class SignUpUnit4(BaseHandler):

    def get(self):
        template_values = {
            'user_error': '',
            'pwd_error': '',
            'vrypwd_error': '',
            'email_error': '',
            }
        path = os.path.join(os.path.dirname(__file__), 'signup.html')
        self.response.out.write(template.render(path, template_values))

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.email = self.request.get('email')
        user_correct = USER_RE.match(self.username)
        pwd_correct = PWD_RE.match(self.password)
        vrypwd_correct = self.password == self.request.get('verify')
        email_correct = True  # EML_RE.match(self.request.get('email'))
        error_msg = {
            'user_error': "That's not a valid username.",
            'pwd_error': "That wasn't a valid password.",
            'vrypwd_error': "Your passwords didn't match.",
            'email_error': "That's not a valid email.",
            }
        if user_correct and pwd_correct and vrypwd_correct \
            and email_correct:
            self.done()
        else:

            if user_correct:
                error_msg['user_error'] = ''
            if pwd_correct:
                error_msg['pwd_error'] = ''
            if vrypwd_correct:
                error_msg['vrypwd_error'] = ''
            if email_correct:
                error_msg['email_error'] = ''
            self.write('signup.html', **error_msg)

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(SignUpUnit4):

    def done(self):

        # make sure the user not exist

        u = User.by_name(self.username)
        if u:
            msg = 'The user already exists.'
            self.write('signup.html', user_error=msg)
        else:
            u = User.register(self.username, self.password, self.email)
        u.put()

        self.login(u)
        self.redirect('/welcome')


class WelcomeUnit4(BaseHandler):

    def get(self):
        if self.user:
            self.response.out.write('<h1>Welcom,%s!</h1>'
                                    % self.user.name)
        else:
            self.redirect('/blog/signup')


class Login(BaseHandler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)

        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'invalid login'
            self.render('login.html', error=msg)


def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in
                   xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):

    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(
        cls,
        name,
        pw,
        email=None,
        ):

        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Logout(BaseHandler):

    def get(self):
        self.logout()
        self.redirect('/blog/signup')


# Unit5

def db_instance_to_dict(instance):
    x = minidom.parseString(instance.to_xml())
    property_dict = {}

    # here's how xml looks like. use x.toprettyxml() to view it
    # <?xml version="1.0" ?>
    # <entity key="ahFkZXZ-cG9pbnRsZXNzdGlyZXIoCxIFYmxvZ3MiB2RlZmF1bHQMCxIJQmxvZ01vZGVsGICAgICAgIAKDA" kind="BlogModel">
    # ....
    # ....<key>tag:dev~pointlesstire.gmail.com,2014-09-20:BlogModel[ahFkZXZ-cG9pbnRsZXNzdGlyZXIoCxIFYmxvZ3MiB2RlZmF1bHQMCxIJQmxvZ01vZGVsGICAgICAgIAKDA]</key>
    # ....<property name="content" type="text">blablablab</property>
    # ....<property name="created" type="gd:when">2014-09-20 11:57:30.466419</property>
    #   <property name="subject" type="string">bla</property>

    for d in x.getElementsByTagName('property'):
        k = d.attributes['name'].value
        v = d.childNodes[0].nodeValue
        property_dict[k] = v
    return property_dict


class FrontJSON(Blog):

    def get(self):
        posts = self.queryPost()
        posts_list = []
        for post in posts:
            posts_list.append(db_instance_to_dict(post))
        self.render_json(posts_list)


class PostPageJSON(PostPage):

    def get(self, post_id):

        post = self.getkey(post_id)
        if not post:
            self.render('custom404.html')
            return
        self.render_json(db_instance_to_dict(post))


# Unit 6

def age_set(key, val):
    save_time = datetime.utcnow()
    memcache.set(key, (val, save_time))


def age_get(key):
    r = memcache.get(key)
    if r:
        (val, save_time) = r
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        (val, age) = (None, 0)
    return (val, age)


def add_post(ip, post):
    post.put()
    get_posts(update=True)
    return str(post.key().id())


def get_posts(update=False):
    q = BlogModel.all().order('-created').fetch(limit=10)
    mc_key = 'BLOGS'

    (posts, age) = age_get(mc_key)
    if update or posts is None:
        posts = list(q)
        age_set(mc_key, posts)

    return (posts, age)


def age_str(age):
    s = 'Queried %s seconds ago'
    age = int(age)
    if age == 1:
        s = s.replace('seconds', 'second')
    return s % age


class BlogFront(Blog):

    def get(self):
        (posts, age) = get_posts()
        self.render('blog_main.html', posts=posts, age=age_str(age))


class Flush(BaseHandler):

    def get(self):
        memcache.flush_all()
        self.redirect('/blog')


app = webapp2.WSGIApplication([  # These two Unit2 implementation is depreciated
                                 #    ('/signup', SignUp),
                                 #    ('/welcome', Welcome),
    ('/', MainHandler),
    ('/ROT13', ROT13),
    ('/FizzBuzz', FizzBuzz),
    ('/blog/?', BlogFront),
    ('/blog/newpost', BlogNewPost),
    ('/blog/(\d+)', PostPage),
    ('/blog/signup', Register),
    ('/welcome', WelcomeUnit4),
    ('/login', Login),
    ('/logout', Logout),
    ('/.json', FrontJSON),
    ('/blog/(\d+).json', PostPageJSON),
    ('/blog/flush', Flush),
    ], debug=True)
