# -*- coding: utf-8 -*-

# ======================= IMPORTS =======================
# Define logging levels, set to INFO or ERROR in production
import logging
logging.basicConfig(level=logging.DEBUG,
                    format=' %(asctime)s - %(levelname)s - %(message)s')

# Import @wraps for @decorators
from functools import wraps

# Imports for Flask bass
from flask import Flask, request, render_template, url_for, redirect
from flask import flash, make_response, Response, abort

# Import database (setup) and CRUD functionality
import database_setup as dbs
import crud

# Imports for base authentication
from flask import session as login_session
import random
import string

# Imports needed for OAuth2
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests

# Imports neded for JSON / XML endpoints
from flask import jsonify
from xml.etree.ElementTree import Element, tostring

# Imports needed for file upload functionality
import os
from werkzeug import secure_filename
from uuid import uuid1 as uuid_gen


# ======================= SETUP & DEFINITIONS =======================
# Define Flask app
app = Flask(__name__)

# Constants for upload functionalities
UPLOAD_FOLDER = 'static/uploads/images'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
MAX_UPLOAD_SIZE = 4 * 1024 * 1024

# Client information for Google Plus OAuth2 authentication (supply your own)
CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']


# ======================= HELPER FUNCTIONS =======================
def generate_token():
    """ Generate a random 32-character alphanumerical token """
    return ''.join(
        random.choice(
            string.ascii_uppercase + string.digits)
        for x in xrange(32))


def generate_context(item_id=None, category_id=None):
    """ Returns a catalogue context with categories and item(s)
    item_id:        if set retrieves item details
    category_id:    if set retrieves items of this category
                    (note: category_id is ignored, if item_id is provided)

    If neither category_id nor item_id is provided,
    all items in the catalogue will be returned

    Always returns all categories """
    context = dict()
    context['categories'] = crud.get_all_categories()

    if item_id is not None:
        context['items'] = crud.get_item_by_id(item_id)
    elif category_id is not None:
        context['items'] = crud.get_items_by_category(category_id)
    else:
        context['items'] = crud.get_all_items()

    return context


def allowed_file(filename):
    """ Returns true if filenname extension is allowed

    From http://flask.pocoo.org/docs/0.10/patterns/fileuploads """
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def get_file_extension(filename):
    """ Returns filename extension

    From http://flask.pocoo.org/docs/0.10/patterns/fileuploads """
    return filename.rsplit('.', 1)[1]


def logged_in(func):
    """ Checks whether a user is logged in
    and re-directs if they are not.
    Use as @decorator to protect access-restricted routes """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            if not login_session['logged_in']:
                flash("Please login to do that")
                logging.debug("User not logged in. Redirecting...")
                return redirect(url_for('index'), code=302)
        except KeyError:
            flash("Please login to do that")
            return redirect(url_for('index'), code=302)

        return func(*args, **kwargs)

    return wrapper


# ======================= ROUTES =======================
@app.route("/")
@app.route("/category/<category_name>/<int:category_id>",
           endpoint="category")
def index(category_name=None, category_id=None):
    """ Shows category list and items
    category_name:      only required for route, not used
    category_id:        if set, show only items from this category
                        (if not provided, all items will be shown)


    In effect, this function provides all categories and items on the main page
    and all categories and category-specific items on category pages """
    context = generate_context(
        category_id=category_id)

    return render_template(
        'item_list.html',
        categories=context['categories'],
        title="Home",
        items=context['items'])


@app.route("/item/<item_name>/<int:item_id>")
def item(item_name, item_id):
    """ Shows category list and details of specific item
    item_name:  only required for route, not used
    item_id:    the id of the item whose details are to be shown """
    context = generate_context(
        item_id=item_id)

    return render_template(
        'item_details.html',
        categories=context['categories'],
        title="Item - " + item_name,
        item=context['items'])


@app.route("/item/<item_name>/<int:item_id>/edit",
           methods=['GET', 'POST'])
@logged_in
def edit_item(item_name, item_id):
    """ Allows logged in users to edit an item's details
    item_name:  only required for route, not used
    item_id:    the id of the item whose details are to be edited

    Can only be accessed by logged in users """
    context = generate_context(item_id=item_id)

    # Only allow item change on POST request
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category_id = request.form['category-id']

        file = request.files['file']
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        crud.update_item(item_id, name, description, category_id, filename)
        flash("Item successfully saved")

    return render_template(
        'item_edit_form.html',
        categories=context['categories'],
        item=context['items'],
        title="Edit item - " + item_name)


@app.route("/item/<item_name>/<int:item_id>/delete",
           methods=['GET', 'POST'])
@logged_in
def delete_item(item_name, item_id):
    """ Allows logged in users to delete an item
    item_name:  only required for route, not used
    item_id:    the id of the item which is to be deleted

    Can only be accessed by logged in users

    This function uses snippet parts of
    http://flask.pocoo.org/snippets/3 for nonces """

    context = generate_context(item_id=item_id)

    # Only allow item deletion on POST request
    if request.method == 'POST':
        delete = request.form['delete']
        token = login_session.pop('_csrf_token')
        logging.debug("The CSRF token: %s" % request.form['_csrf_token'])
        logging.debug("The login session's expected CSRF token: %s" % token)

        # Prevent deletion if checkbox not ticked or CSRF token incorrect
        if delete:
            if request.form['_csrf_token'] != token:
                logging.info("Incorrect CSRF token. Redirecting...")
                abort(403)

            logging.debug("CSRF tokens are matching. Deleting item.")

            crud.delete_item(item_id)
            flash("The item was successfully deleted")
            return redirect(url_for('index'), code=302)

    # Generate a random CSRF token and show delete form
    login_session['_csrf_token'] = generate_token()
    return render_template(
        'item_delete_form.html',
        categories=context['categories'],
        item=context['items'],
        title="Edit item - " + item_name,
        csrf_token=login_session['_csrf_token'])


@app.route("/item/create", methods=['GET', 'POST'])
@logged_in
def create_item():
    """ Allows logged in users to create an item

    Can only be accessed by logged in users """
    categories = crud.get_all_categories()

    # Only allow item creation on POST request
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category_id = request.form['category-id']

        file = request.files['file']

        # Only allow upload of files which have an allowed extension
        if file and allowed_file(file.filename):
            extension = get_file_extension(file.filename)
            logging.debug("The file's extension is: %s" % extension)

            # Generate a UUID filename to avoid duplicate filenames
            filename = "%s.%s" % (uuid_gen(), extension)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None

        crud.create_item(name, description, category_id, filename)

        return redirect(url_for('index'), code=302)

    return render_template(
        'item_create_form.html',
        categories=categories)


@app.route("/catalogue.json")
def json_endpoint():
    """ The endpoint to access the catalogue in JSON format

    Be advised that this currently exposes the complete catalogue
    which is something you may want to avoid

    Big thanks to michael_940140431 on the Udacity forums
    for getting me on the right track """
    output = []
    entries = crud.get_all_categories()

    for entry in entries:
        items = crud.get_items_by_category(entry.id)

        entry = entry.serialise
        entry['Item'] = [i.serialise for i in items]

        output.append(entry)

    return jsonify(Category=output)


@app.route("/catalogue.xml")
def xml_endpoint():
    """ The endpoint to access the catalogue in XML format

    Be advised that this currently exposes the complete catalogue
    which is something you may want to avoid """
    def generate_children(parent, children):
        """ This function assigns a list of children to a parent element
        parent:     the name of the parent tag (provide as string)
        children:   a dictionary of children
                    (the key becomes the tag name, the value the text)

        This function does not deal with attributes,
        but only tags and text values """
        parent = Element(parent)
        children = children.serialise

        for key, value in children.items():
            child = Element(key)
            child.text = str(value)
            parent.append(child)

        return parent

    categories = crud.get_all_categories()

    catalogue_elem = Element('catalogue')
    for category in categories:
        cats_elem = generate_children('category', category)

        items_elem = Element('items')
        items = crud.get_items_by_category(category.id)
        for item in items:
            item_elem = generate_children('item', item)
            items_elem.append(item_elem)

        cats_elem.append(items_elem)
        catalogue_elem.append(cats_elem)

    return Response(tostring(catalogue_elem), mimetype='application/xml')


@app.route('/login')
def login():
    """ Provides a page with Google Plus sign-in functionality """
    login_session['state'] = generate_token()
    logging.debug("Randomly generated state: %s" % login_session['state'])

    return render_template(
        'login.html',
        STATE=login_session['state'])


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ Allows users to log in via Google Plus sign-in (OAuth2)

    The code was mostly provided by
    Udacity's Full-Stack Development course and adapted """
    # Validate state token
    logging.debug("request.args state: %s" % request.args.get('state'))
    logging.debug("login_session state: %s" % login_session['state'])

    if request.args.get('state') != login_session['state']:
        logging.error("Invalid state parameter.")

        return redirect(url_for('index'), code=401)

    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        logging.error("Failed to upgrade the authorisation code.")

        return redirect(url_for('index'), code=401)

    # Check that the access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort
    if result.get('error') is not None:
        logging.error("Error in access token info.")
        return redirect(url_for('index'), code=500)

    # Verify that the access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        logging.error("Token's user ID doesn't match given user ID.")
        return redirect(url_for('index'), code=401)

    # Verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        logging.error("Token's client ID does not match app's.")
        return redirect(url_for('index'), code=401)

    # Check if user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        logging.info("Current user is already connected.")
        return redirect(url_for('index'), code=200)

    # Store the access token in the session for later use
    login_session['access_token'] = credentials.access_token
    logging.debug("The access token: %s" % login_session['access_token'])
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['picture'] = data['picture']
    login_session['username'] = data['name']
    login_session['logged_in'] = True

    return redirect(url_for('index'), code=302)


@app.route('/gdisconnect')
def gdisconnect():
    """ Allows users logged in via Google Plus to sign out

    The code was mostly provided by
    Udacity's Full-Stack Development course and adapted """
    access_token = login_session['access_token']

    # Check if user is connected
    if access_token is None:
        logging.debug("Access Token is None. Current user not connected")
        return redirect(url_for('index'), code=401)

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
          % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    logging.debug("Logout request status: %s" % result['status'])
    if result['status'] == '200':
        # Destroy login session data, confirm logout and redirect to index page
        del login_session['access_token']
        del login_session['picture']
        del login_session['logged_in']
        del login_session['username']

        logging.debug("Logout successful")
        flash("Logout successful")
        return redirect(url_for('index'), code=302)
    else:
        # Token revoking failed, redirect to index page
        logging.debug("Failed to revoke token for given user")
        return redirect(url_for('index'), code=400)


if __name__ == "__main__":
    # Set the flask app's secret key, you may replace it with your own
    app.secret_key = 'My secret key'

    # IMPORTANT: Do not turn debug mode on when application is in production
    app.debug = True

    # Set application's upload folder and maximum file size
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE

    # Run flask application
    app.run()
