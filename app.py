# Import necessary modules
from flask import Flask, render_template, redirect, url_for, flash, session, request, abort
from flask_wtf import FlaskForm
from flask_debugtoolbar import DebugToolbarExtension
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from models import User, Feedback, db, bcrypt, connect_db
from forms import RegistrationForm, LoginForm, FeedbackForm

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'oh_so_secret'

app.app_context().push()

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///feedback_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"

connect_db(app)
db.create_all()

toolbar = DebugToolbarExtension(app)

# Routes for registration, login, and secret page
@app.route('/')
def homepage():
    """Show homepage with links to site areas."""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a user."""
    if 'username' in session:
        flash('You are already logged in', 'info')
        return redirect(url_for('user_profile', username=session['username']))
    
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        is_admin = form.is_admin.data

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        # Create new user
        user = User.register(username, password, email, first_name, last_name, is_admin)
        db.session.add(user)
        db.session.commit()

        # Store username in session
        session['username'] = username
        flash('User created successfully', 'success')
        
        # Redirect to user profile page after successful registration
        return redirect(url_for('user_profile', username=username))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login a user."""
    if 'username' in session:
        flash('You are already logged in', 'info')
        return redirect(url_for('user_profile', username=session['username']))
    
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)

        if user:
            # Store username in session
            session['username'] = username
            flash('Login successful', 'success')
            
            # Redirect to user profile page after successful login
            return redirect(url_for('user_profile', username=username))
        else:
            form.username.errors = ['Invalid username/password']

    return render_template('login.html', form=form)

@app.route('/users/<username>')
def user_profile(username):
    """Display user profile."""
    # Check if user is logged in
    if 'username' not in session:
        flash('You must be logged in to access this page', 'danger')
        return redirect(url_for('login'))

    # Check if the logged-in user matches the requested username
    if session['username'] != username:
        flash('You are not authorized to access this page', 'danger')
        return redirect(url_for('homepage'))

    # Get user information from the database
    user = User.query.filter_by(username=username).first_or_404()

    if user:
        # Get feedback for the user
        feedback = Feedback.query.filter_by(username=username).all()

        # Render user profile template with user and feedback data
        return render_template('user_profile.html', user=user, feedback=feedback)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('homepage'))

def is_admin(username):
    user = User.query.get(username)
    return user.is_admin if user else False
    
@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    """Delete user account."""
    if 'username' not in session:
        flash('You must be logged in to access this page', 'danger')
        return redirect(url_for('login'))

    if session['username'] != username:
        flash('You are not authorized to delete this account', 'danger')
        return redirect(url_for('homepage'))

    user = User.query.filter_by(username=username).first()

    if user:
        db.session.delete(user)
        db.session.commit()

        session.pop('username', None)
        flash('User account deleted successfully', 'success')
        
        return redirect(url_for('homepage'))
    else:
        flash('User not found', 'danger')
        return redirect(url_for('homepage'))
    

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    """Add new feedback."""
    if 'username' not in session:
        flash('You must be logged in to access this page', 'danger')
        return redirect(url_for('login'))

    if session['username'] != username:
        flash('You are not authorized to add feedback for this user', 'danger')
        return redirect(url_for('homepage'))

    form = FeedbackForm()

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        
        user = User.query.filter_by(username=username).first_or_404()
        feedback = Feedback(title=title, content=content, username=username)
        db.session.add(feedback)
        db.session.commit()

        flash('Feedback added successfully', 'success')
        return redirect(url_for('user_profile', username=username))
    
    return render_template('add_feedback.html', form=form)

@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    """Update feedback."""
    if 'username' not in session:
        flash('You must be logged in to access this page', 'danger')
        return redirect(url_for('login'))

    feedback = Feedback.query.get_or_404(feedback_id)
    
    if not is_admin(session['username']) and session['username'] != feedback.username:
        flash('You are not authorized to update this feedback', 'danger')
        return redirect(url_for('homepage'))

    # Create a form and populate it with the current feedback data
    form = FeedbackForm()
    if request.method == 'GET':
        form.title.data = feedback.title
        form.content.data = feedback.content

    if form.validate_on_submit():
        # Update the feedback with the edited data
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()

        flash('Feedback updated successfully', 'success')
        return redirect(url_for('user_profile', username=session['username']))

    return render_template('update_feedback.html', form=form)

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    """Delete feedback."""
    if 'username' not in session:
        flash('You must be logged in to access this page', 'danger')
        return redirect(url_for('login'))

    feedback = Feedback.query.get_or_404(feedback_id)

    if not is_admin(session['username']) and session['username'] != feedback.username:
        flash('You are not authorized to delete this feedback', 'danger')
        return redirect(url_for('homepage'))
    
    db.session.delete(feedback)
    db.session.commit()

    flash('Feedback deleted successfully', 'success')
    return redirect(url_for('user_profile', username=feedback.username))
    
@app.route('/logout')
def logout():
    """Logout a user."""
    # Clear session
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect("/")  # Redirect to desired page after logout

@app.errorhandler(404)
def not_found_error(error):
    """Render a 404 error page."""
    return render_template('404.html'), 404

@app.errorhandler(401)
def unauthorized_error(error):
    """Render a 401 error page."""
    return render_template('401.html'), 401

# Run the app
if __name__ == '__main__':
    app.debug = True
    app.run()
