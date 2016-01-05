import logging

import sys

from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Category(Base):
    """ This class defines an item in the catalogue
    id:     the category's unique id
    name:   the category's name """
    __tablename__ = 'categories'

    id = Column(
        'id', Integer,
        nullable=False,
        primary_key=True)
    name = Column(
        'name', String,
        nullable=False)

    @property
    def serialise(self):
        """ Returns category data in easily serialisable format """
        return {
            'id':   self.id,
            'name': self.name,
        }


class Item(Base):
    """ This class defines the item in the catalogue
    id:             the item's unique id
    name:           the name or title of the item
    description:    the item's description
    category:       the category id to which the item belongs
                    (foreign key references to the Category class' id)
    image:          the item's image """
    __tablename__ = 'items'

    id = Column(
        'id', Integer,
        nullable=False,
        primary_key=True)
    name = Column(
        'name', String,
        nullable=False)
    description = Column(
        'description', String)
    category = Column(
        'category',
        ForeignKey('categories.id'),
        nullable=False)
    image = Column(
        'image',
        String)

    categories = relationship(Category)

    @property
    def serialise(self):
        """ Returns item data in easily serialisable format """
        return {
            'id':           self.id,
            'name':         self.name,
            'description':  self.description,
            'category':     self.category,
            'image':        self.image
        }

# Set up database and database engine
logging.info('Setting up db engine')
engine = create_engine('sqlite:///item_catalogue.db')
Base.metadata.create_all(engine)
