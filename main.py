import os
import re
import random
import hashlib
import hmac
from string import letters
import time
import jinja2
import webapp2

from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), "templates")


JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               extensions=["jinja2.ext.autoescape"],
                               autoescape=True)

SECRET = 'hkjgrtmnh'


def render_str(template, **params):
    """Takes in a template and a dictionary of parameters"""
    t = JINJA_ENV.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    """Handler for all web requests"""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        """Prints out a template"""
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# User stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


class User(db.Model):
    """A main model for representing an individual user entry"""
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    liked_posts = db.ListProperty(int, default=None)
    user_posts = db.ListProperty(int, default=None)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    """A main model for representing an individual blog entry"""
    book_author = db.StringProperty(required=True)
    book_title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    contributor = db.StringProperty(required=True)
    date = db.DateTimeProperty(auto_now_add=True)
    last_mod = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)

    def render(self):
        """Replaces new lines with line break tags for proper html rendering"""
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comment(db.Model):
    """Database model for comments"""
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    date = db.DateTimeProperty(auto_now_add=True)
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty()

    def render(self):
        """Replaces new lines with line break tags for proper html rendering"""
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("com.html", c=self)


class BlogCover(BlogHandler):
    def get(self):
        self.render("cover.html")


class BlogFront(BlogHandler):
    """Read-only page"""
    def get(self):
        posts = db.GqlQuery('select * from Post order by date desc limit 10')
        self.render("front.html", posts=posts)


class BlogMain(BlogHandler):
    def get(self):
        if not self.user:
            welcm_msg = "Welcome! Login or Register above to post, leave comments and like your favorite book quotes. Enjoy!"
            self.render("main.html", welcm_msg=welcm_msg)
        else:
            posts = db.GqlQuery('select * from Post order by date desc limit 10')
            self.render("main.html", posts=posts)

    def post(self):
        pid = self.request.get('post_id')
        pid_remove = self.request.get('remove')
        pid_edit = self.request.get('edit')
        posts = db.GqlQuery('select * from Post order by date desc limit 10')

        if pid:
            post = Post.get_by_id(int(pid))
            # Check if user has already liked this post
            if int(pid) in self.user.liked_posts:
                self.render("main.html", posts=posts,
                            error="You cannot like the same post twice")
            # Check if user created this post
            elif int(pid) in self.user.user_posts:
                self.render("main.html", posts=posts,
                            error="You cannot like your own post")
            else:
                post.likes = post.likes + 1
                post.put()
                self.user.liked_posts.append(int(pid))
                self.user.put()
                self.redirect('/main')

        if pid_remove:
            # Check if user created this post
            if int(pid_remove) in self.user.user_posts:
                post = Post.get_by_id(int(pid_remove))
                post.delete()
                self.user.user_posts.remove(int(pid_remove))
                #Wait for the database to update so the main page is dispayed without the deleted post
                time.sleep(.5)
                self.redirect('/main')
            else:
                self.render("main.html", posts=posts,
                            error="You can't delete the post you didn't create")

        if pid_edit:
            if int(pid_edit) in self.user.user_posts:
                self.redirect('/post/%s/edit' % str(pid_edit))
            else:
                self.render("main.html", posts=posts,
                            error="You can't edit the post you didn't create")


class EditPostPage(BlogHandler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        if not post:
            self.error(404)
            return

        if int(post_id) in self.user.user_posts:
            self.render("edit.html", contributor=self.user.name,
                        book_title=post.book_title,
                        book_author=post.book_author,
                        content=post.content)
        else:
            posts = db.GqlQuery('select * from Post order by date desc limit 10')
            self.render("main.html", posts=posts,
                        error="You cannot edit the post you didn't create")

    def post(self, post_id):
        if self.user:
            post = Post.get_by_id(int(post_id))
            if not post:
                self.error(404)
                return

            if int(post_id) in self.user.user_posts:
                book_author = self.request.get('book_author')
                book_title = self.request.get('book_title')
                content = self.request.get('content')

                if book_author and book_title and content:
                    post.book_author = book_author
                    post.book_title = book_title
                    post.content = content
                    post.put()
                    time.sleep(.5)
                    self.redirect('/main')
                else:
                    error = "Please add missing info"
                    self.render("edit.html", book_author=book_author,
                                book_title=book_title,
                                content=content,
                                error=error)
            else:
                posts = db.GqlQuery('select * from Post order by date desc limit 10')
                self.render("main.html", posts=posts,
                            error="You cannot edit the post you didn't create")
        else:
            welcm_msg = "Welcome! Login or Register above to post, leave comments and like your favorite book quotes. Enjoy!"
            self.render("main.html", welcm_msg=welcm_msg)


class CommentPage(BlogHandler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        comments = db.GqlQuery('select * from Comment where post_id = {0} order by date desc limit 10'.format(post_id))
        if comments:
            self.render("comment.html", post=post,
                        comments=comments)
        else:
            self.render("comment.html", post=post)

    def post(self, post_id):
        if self.user:
            content = self.request.get('content')
            edit_comment = self.request.get('edit_comment')
            if content:
                c = Comment(content=content, author=self.user.name,
                            post_id=int(post_id),
                            user_id=int(self.user.key().id()))
                c.put()
                post = Post.get_by_id(int(post_id))
                time.sleep(.5)
                self.redirect('/post/%s/comment' % str(post.key().id()))
            if edit_comment:
                comment = Comment.get_by_id(int(edit_comment))
                if comment.user_id == int(self.user.key().id()):
                    self.redirect('/comment/%s/edit' % str(edit_comment))
                else:
                    post = Post.get_by_id(int(post_id))
                    comments = db.GqlQuery('select * from Comment where post_id = {0} order by date desc limit 10'.format(post_id))
                    self.render("comment.html", post=post, comments=comments,
                                error="You cannot edit comment you didn't create")


class EditCommentPage(BlogHandler):
    def get(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if not comment:
            self.error(404)
            return

        if comment.user_id == int(self.user.key().id()):
            self.render("comment_edit.html", content=comment.content)
        else:
            post = Post.get_by_id(int(comment.post_id))
            comments = db.GqlQuery('select * from Comment where post_id = {0} order by date desc limit 10'.format(post_id))
            self.render("comment.html", post=post,
                        comments=comments,
                        error="You cannot edit comment you didn't create")

    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if not comment:
            self.error(404)
            return

        if comment.user_id == int(self.user.key().id()):
            content = self.request.get('content')
            if content:
                comment.content = content
                comment.put()
                time.sleep(.5)
                self.redirect('/post/%s/comment' % str(comment.post_id))
        else:
            post = Post.get_by_id(int(comment.post_id))
            comments = db.GqlQuery('select * from Comment where post_id = {0} order by date desc limit 10'.format(post_id))
            self.render("comment.html", post=post, comments=comments,
                        error="You cannot edit comment you didn't create")


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html", contributor=self.user.name)
        else:
            welcm_msg = "Welcome! Login or Register above to post, leave comments and like your favorite book quotes. Enjoy!"
            self.render("main.html", welcm_msg=welcm_msg)

    def post(self):
        if not self.user:
            return self.redirect('/main')

        book_author = self.request.get('book_author')
        book_title = self.request.get('book_title')
        content = self.request.get('content')

        if book_author and book_title and content:
            p = Post(book_author=book_author,
                     book_title=book_title,
                     content=content,
                     contributor=self.user.name)
            p.put()
            self.user.user_posts.append(int(p.key().id()))
            self.user.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            self.render("newpost.html", book_author=book_author,
                        book_title=book_title,
                        content=content,
                        error="Please add missing info")


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password"
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match"
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email"
            have_error = True

        if have_error:
            self.render("signup-form.html", **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        """Makes sure the user doesn't already exist"""
        u = User.by_name(self.username)
        if u:
            msg = "This user already exists"
            self.render("signup-form.html", error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class Login(BlogHandler):
    def get(self):
        self.render("login-form.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            self.render("login-form.html", error="Invalid login")


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render("welcome.html", contributor=self.user.name)
        else:
            welcm_msg = "Welcome! Login or Register above to post, leave comments and like your favorite book quotes. Enjoy!"
            self.render("main.html", welcm_msg=welcm_msg)


app = webapp2.WSGIApplication([('/', BlogCover),
                               ('/front', BlogFront),
                               ('/main', BlogMain),
                               ('/post/([0-9]+)/edit', EditPostPage),
                               ('/post/([0-9]+)/comment', CommentPage),
                               ('/comment/([0-9]+)/edit', EditCommentPage),
                               ('/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
