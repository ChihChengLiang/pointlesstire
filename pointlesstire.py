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

    def set_secure_cookie(self, name, val):
        cookie_val = make_hash(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s ; path=/'
                % (str(name), str(cookie_val)))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_hash(cookie_val)


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

    def get(self):
        posts = \
            db.GqlQuery('select * from BlogModel order by created desc limit 10'
                        )
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

    def get(self, post_id):
        key = db.Key.from_path('BlogModel', int(post_id),
                               parent=blog_key())
        post = db.get(key)
        if not post:
            self.render('custom404.html')
            return
        self.render('blog_permalink.html', post=post)


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
        username = self.request.get('username')
        password = self.request.get('password')
        user_correct = USER_RE.match(username)
        pwd_correct = PWD_RE.match(password)
        vrypwd_correct = password == self.request.get('verify')
        email_correct = EML_RE.match(self.request.get('email'))
        error_msg = {
            'user_error': "That's not a valid username.",
            'pwd_error': "That wasn't a valid password.",
            'vrypwd_error': "Your passwords didn't match.",
            'email_error': "That's not a valid email.",
            }
        if user_correct and pwd_correct and vrypwd_correct \
            and email_correct:
            self.set_secure_cookie('username', username)
            self.redirect('/welcomeUnit4')
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


class WelcomeUnit4(BaseHandler):

    def get(self):
        username = self.read_secure_cookie('username')
        if username:
            self.response.out.write('<h1>Welcom,%s!</h1>'
                                    % username.split('|')[0])
        else:
            self.redirect('/signupUnit4')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/ROT13', ROT13),
    ('/signup', SignUp),
    ('/welcome', Welcome),
    ('/FizzBuzz', FizzBuzz),
    ('/blog/?', Blog),
    ('/blog/newpost', BlogNewPost),
    ('/blog/(\d+)', PostPage),
    ('/signupUnit4', SignUpUnit4),
    ('/welcomeUnit4', WelcomeUnit4),
    ], debug=True)
