import os
from flask import Flask, url_for, redirect, render_template, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user
from flask_security.utils import encrypt_password
import flask_admin
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers
from flask_admin.contrib.sqla import ModelView
from sqlalchemy import func, ForeignKey, Enum, Integer
import enum
from flask_security.signals import user_registered
import datetime

# Create Flask application


app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)

# Define models
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

department_users = db.Table(
    'department_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('department_id', db.Integer(), db.ForeignKey('department.id'))
)


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

    #    description = db.Column(db.String(255))

    def __str__(self):
        return self.name


class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department_name = db.Column(db.String, unique=True)

    def __str__(self):
        return self.department_name


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    days = db.Column(db.Integer)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    department_id = db.Column(db.Integer, ForeignKey("department.id"))
    department = db.relationship("Department")
    requests = db.relationship("Request")
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    @property
    def days_left(self):
        total = 0
        for r in self.requests:
            total = total+(r.end_date-r.start_date).days
        if self.days:
            return self.days - total
        else:
            return 0

    def __str__(self):
        return self.email


class RequestStatus(enum.Enum):
    Pending = 1
    Approved = 2
    Rejected = 3


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey("user.id"))
    user = db.relationship("User")
    department_id = db.Column(db.Integer, ForeignKey("department.id"))
    department = db.relationship("Department")
    reason = db.Column(db.String)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    status = db.Column(db.Enum(RequestStatus), default=RequestStatus.Pending)


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# admin = Admin(app)
# admin.add_view(ModelView(User, db.session))
# admin.add_view(ModelView(Request, db.session))


# Create customized model view class
class RoleModelView(sqla.ModelView):
    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('superuser')
                )

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))


class UserModelView(sqla.ModelView):
    column_list = ('first_name', 'last_name', 'email', 'days', 'days_left', 'department', 'roles', 'active')

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('superuser')
                )

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))


class RequestModelView(sqla.ModelView):
    column_list = ('user', 'department', 'reason', 'start_date', 'end_date', 'status')

    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('employee') or
                current_user.has_role('superuser') or
                current_user.has_role('manager')
                )

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))

        if current_user.has_role('manager'):
            self.can_delete = False
            self.can_edit = True
            self.can_create = True
            self.form_widget_args = {
                'department': {'disabled': True},
                'user': {'disabled': True},
                'reason': {'disabled': True},
                'start_date': {'disabled': True},
                'end_date': {'disabled': True},
                'status': {'disabled': False},
                'days_left': {'disabled': True}
            }

        if current_user.has_role('employee'):
            self.can_delete = False
            self.can_edit = False
            self.can_create = True

        if current_user.has_role('superuser'):
            self.can_delete = True
            self.can_edit = False
            self.can_create = False

        self.can_create = current_user.days_left >= 0

    def create_form(self, obj=None):
        form = super().create_form(obj)
        form.user.data = current_user
        form.department.data = current_user.department
        if current_user.has_role('manager'):
            if form.user.data == current_user:
                self.form_widget_args = {
                    'department': {'disabled': True},
                    'user': {'disabled': True},
                    'reason': {'disabled': False},
                    'start_date': {'disabled': False},
                    'end_date': {'disabled': False},
                    'status': {'disabled': False},
                    'days_left': {'disabled': True}
                }
        if current_user.has_role('employee'):
            if form.user.data == current_user:
                self.form_widget_args = {
                    'department': {'disabled': True},
                    'user': {'disabled': True},
                    'reason': {'disabled': False},
                    'start_date': {'disabled': False},
                    'end_date': {'disabled': False},
                    'status': {'disabled': True},
                    'days_left': {'disabled': True}
                }
        return form

    def get_query(self):
        if current_user.has_role('employee'):
            return (self.session.query(self.model)
                    .filter(self.model.user == current_user))
        if current_user.has_role('manager'):
            return self.session.query(self.model).filter(self.model.department == current_user.department)
        if current_user.has_role('superuser'):
            return self.session.query(self.model)

    def get_count_query(self):
        if current_user.has_role('employee'):
            return (self.session.query(func.count('*'))
                    .filter(self.model.user == current_user))
        if current_user.has_role('manager'):
            return self.session.query(func.count('*')).filter(self.model.department == current_user.department)
        if current_user.has_role('superuser'):
            return self.session.query(func.count('*'))


class DepartmentModelView(sqla.ModelView):
    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('superuser')
                )


# Flask views
#   @app.route('/')
#   def index():
#   return render_template('registration/home.html')


@app.route('/')
def index():
    return render_template('index.html')


# Create admin
admin = flask_admin.Admin(
    app,
    "[Company Name]'s LMS",
    base_template='my_master.html',
    template_mode='bootstrap3',
)

# Add model views
admin.add_view(RoleModelView(Role, db.session))
admin.add_view(DepartmentModelView(Department, db.session))
admin.add_view(UserModelView(User, db.session))
admin.add_view(RequestModelView(Request, db.session))


# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for
    )


def build_sample_db():
    """
    Populate a small db with some example entries.
    """

    import string
    import random

    db.drop_all()
    db.create_all()

    with app.app_context():
        user_role = Role(name='employee')
        user_manager = Role(name='manager')
        super_user_role = Role(name='superuser')
        db.session.add(super_user_role)
        db.session.add(user_manager)
        db.session.add(user_role)
        db.session.commit()

        test_user = user_datastore.create_user(
            first_name='Admin',
            email='admin',
            password=encrypt_password('admin'),
            roles=[super_user_role]
        )
        test_user = user_datastore.create_user(
            first_name='Manager',
            email='manager@test',
            password=encrypt_password('test'),
            roles=[user_manager]
        )
        test_user = user_datastore.create_user(
            first_name='Employee',
            email='employee@test',
            password=encrypt_password('test'),
            roles=[user_role]
        )

        db.session.commit()
    return


@user_registered.connect_via(app)
def user_registered_sighandler(app, user, confirm_token):
    default_role = user_datastore.find_role("employee")
    user_datastore.add_role_to_user(user, default_role)
    db.session.commit()


if __name__ == '__main__':

    # Build a sample db on the fly, if one does not exist yet.
    app_dir = os.path.realpath(os.path.dirname(__file__))
    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    if not os.path.exists(database_path):
        build_sample_db()

    # Start app
    app.run(debug=True)
