import webapp2
import os
from google.appengine.ext.webapp import template
import cgi
import string
import re
from jinja2 import Environment, FileSystemLoader
from google.appengine.ext import db

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE  = re.compile(r"^.{3,20}$")
EML_RE  = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

alphabet_list=list(string.lowercase)

class BaseHandler(webapp2.RequestHandler):
  
  def write(self, filename, **template_values):
    path = os.path.join(os.path.dirname(__file__), filename)
    self.response.out.write(template.render(path, template_values))
    
  def render(self, filename,**template_values):
    jinja_env= Environment(loader=FileSystemLoader('templates'))
    template = jinja_env.get_template(filename)
    self.response.out.write(template.render(template_values))
  
class MainHandler(webapp2.RequestHandler):
  def get(self):
    template_values = {
      'name': "World",
    }

    path = os.path.join(os.path.dirname(__file__), 'index.html')
    self.response.out.write(template.render(path, template_values))

class ROT13(webapp2.RequestHandler):
  def get(self):
    template_values = {
      "default_text":"",
      }
    path = os.path.join(os.path.dirname(__file__), 'ROT13.html')
    self.response.out.write(template.render(path, template_values))
  def post(self):
    text=self.request.get("text")
    output=""
    for t in text:
      if t.isalpha():
        s=alphabet_list[(alphabet_list.index(t.lower())+13) %26]
        if t.isupper(): 
          s=s.upper()
        output+=s
      else:
        output+=t
    template_values = {
      "default_text":cgi.escape(output,quote=True),
      }
    path = os.path.join(os.path.dirname(__file__), 'ROT13.html')
    self.response.out.write(template.render(path, template_values))

class SignUp(webapp2.RequestHandler):
  def get(self):
    template_values = {
      "user_error":"",
      "pwd_error":"",
      "vrypwd_error":"",
      "email_error":""
      }
    path = os.path.join(os.path.dirname(__file__), 'signup.html')
    self.response.out.write(template.render(path, template_values))
  def post(self):
    username=self.request.get("username")
    
    user_correct  = USER_RE.match(username)
    pwd_correct   = PWD_RE.match(self.request.get("password"))
    vrypwd_correct= self.request.get("password")==self.request.get("verify")
    email_correct = EML_RE.match(self.request.get("email"))
    error_msg={
      "user_error":"That's not a valid username.",
      "pwd_error":"That wasn't a valid password.",
      "vrypwd_error":"Your passwords didn't match.",
      "email_error":"That's not a valid email."
      }
    if user_correct and pwd_correct and vrypwd_correct and email_correct:
      self.redirect("/welcome?username="+cgi.escape(username,quote=True))
    else:
      if user_correct: error_msg["user_error"]=""
      if pwd_correct: error_msg["pwd_error"]=""
      if vrypwd_correct: error_msg["vrypwd_error"]=""
      if email_correct: error_msg["email_error"]=""
      path = os.path.join(os.path.dirname(__file__), 'signup.html')
      self.response.out.write(template.render(path, error_msg))
    pass
class Welcome(webapp2.RequestHandler):
  def get(self):
    self.response.out.write("<h1>Welcom,"+self.request.get("username")+"!</h1>")

class FizzBuzz(webapp2.RequestHandler):
  def get(self):
    n=self.request.get("n")
    n= n and int(n)
    jinja_env= Environment(loader=FileSystemLoader('templates'))
    template = jinja_env.get_template('FizzBuzz.html')
    self.response.out.write(template.render(n=n))
    #self.response.out.write("<h1>Python code work fine!n=%d</h1>" % n)

class BlogModel(db.Model):
  title = db.StringProperty(required=True)
  content = db.TextProperty(required=True)
  created = db.DateTimeProperty(auto_now_add=True)
  
class Blog(BaseHandler):
  def get(self):
    self.render('blog_main.html')
    
class BlogNewPost(BaseHandler):
  def get(self):
    self.render('blog_newpost.html')
  def post(self):
    pass

app = webapp2.WSGIApplication([
  ('/', MainHandler),
  ('/ROT13',ROT13),
  ('/signup',SignUp),
  ('/welcome',Welcome),
  ('/FizzBuzz',FizzBuzz),
  webapp2.Route('/blog',handler=Blog),
  webapp2.Route('/blog/newpost',handler=BlogNewPost)
], debug=True)