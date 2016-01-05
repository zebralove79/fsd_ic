# Project 3 - Item Catalogue

This repository contains course work for the Udacity course Full Stack Web Developer. It is for the third assignment, the implementation of an item catalogue.

The code was written by [Moritz Hellwig](http://blog.zebralove79.com). Some parts of the code have come from Udacity and other sources; these are acknowledged in the documentation as well as in the acknowledgements section below.

## Table of contents

* [Quick start](#quick-start)
* [Requirements](#requirements)
* [Endpoints](#endpoints)
* [Warnings](#warnings)
* [Acknowledgements](#acknowledgements)
* [Resources used](#resources-used)

## Quick start

* Clone the repo: `git clone https://github.com/zebralove79/fsp2_ic/`

For the Google+ signin functionality you will have to
* Provide your client_secrets.json in the main folder
* Provide your client id in `templates/login.html`

Once set up
* Run application.py

Then you can access the item catalogue at http://localhost:5000

## Requirements

* Python 2.7
including:
** Flask 0.10
** SQLAlchemy 1.0
** oauth2client 1.5.2
** requests 2.8.1

## Endpoints

Two endpoints have been implemented, XML and JSON. You can access them through http://localhost:5000/catalogue.xml and http://localhost:5000/catalogue.json respectively.

## Warnings

### Sample database

The current implementation uses a sample SQLite database with sample data. If you plan on using the item catalogue on a (web) server, it is highly recommended to use MySQL, PostgreSQL or another SQLAlchemy-compatible, better suited database solution instead. SQLite has shortcomings which make it unsuitable for web applications.

The data in the sample item catalogue database was taken from wikipedia for demonstration purposes only.

### Debug mode

The debug mode of the item catalogue is still turned on for debugging fun. Remember to turn it off when you are done debugging.

## Acknowledgements

Special thanks to
* Udacity, for offering the course and some of the code
* michael_940140431 (Udacity forums), for getting me on the right track regarding the XML and JSON endpoints
* R., for non-technical support

## Resources used
* Flask documentation: http://flask.pocoo.org/docs/0.10
* SQLAlchemy documentation: http://docs.sqlalchemy.org/en/rel_1_0/
* Boostrap 3.3.5: http://getbootstrap.com/
* Udacity forums