import logging
logging.basicConfig(level=logging.DEBUG,
                    format=' %(asctime)s - %(levelname)s - %(message)s')

from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item
from sqlalchemy import create_engine

engine = create_engine('sqlite:///item_catalogue.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# =========== Crud - create ===========
def create_item(name, description, category, image=None):
    """ Creates a new item entry in the database """
    item = Item(name=name,
                description=description,
                category=category,
                image=image)

    session.add(item)
    session.commit()


# =========== cRud - read ===========
def get_all_entries(type):
    """ Retrieves all entries of the requested type
    type:       the type you want to retrieve (Category or Item) """
    entries = session.query(type).all()
    return entries


def get_all_categories():
    """ Fetches all categories from the database """
    entries = get_all_entries(Category)
    return entries


def get_all_items():
    """ Fetches all items from the database """
    entries = get_all_entries(Item)
    return entries


def get_items_by_category(category_id):
    """ Fetches all items belonging to category id from the database
    category_id:    the category id whose items are to be retrieved """
    entries = session.query(Item).filter_by(category=category_id).all()
    return entries


def get_item_by_id(item_id):
    """ Fetches an item's details from the database
    item_id:    the item id whose details you want to retrieve """
    entry = session.query(Item).filter_by(id=item_id).one()
    return entry


# =========== crUd - update ===========
def update_item(item_id, name, description, category_id, image=None):
    """ Updates an exisiting item in the database
    item_id:        the id of the item whose details you want to change
    name:           the (new) item name
    description:    the (new) item description
    category_id:    the item's (new) category id
    image:          the item's (new) image """
    entry = session.query(Item).filter_by(id=item_id).one()
    entry.name = name
    entry.description = description
    entry.category = category_id
    if image is not None:
        entry.image = image

    session.add(entry)
    session.commit()


# =========== cruD - delete ===========
def delete_item(item_id):
    """ Deletes an item from the database
    item_id:    the id of the item you want to delete """
    entry = session.query(Item).filter_by(id=item_id).one()

    session.delete(entry)
    session.commit()
