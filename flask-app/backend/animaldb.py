from flask import Flask, render_template, request, redirect
from werkzeug import secure_filename
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session, relationship 

app = Flask(__name__)


Base = declarative_base()


class Animal(Base):
    __tablename__ = 'animal'
    name = Column(String(80), unique=True, nullable=False, primary_key=True)
    typ = Column(String(150))

    def __repr__(self):
        return "<Name: {}>".format(self.name)
		# define how to represent our book object as a string. 
		# This allows us to do things like print(book), and see meaningful output

engine = create_engine('sqlite:///zoo.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

#DBSession = sessionmaker(bind=engine)
#session = DBSession()
session = scoped_session(sessionmaker(bind=engine))
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()


@app.before_first_request
def create_tables():
    if not engine.dialect.has_table(engine, 'animal'):  # If table don't exist, Create.
        Base.metadata.create_all(engine)
        # Insert a Book in the book table
        print('[CREATE TABLE]')
        animal = Animal(name='Kirby', typ='Elephant')
        session.add(animal)
        session.commit()
        print('[FINISHED TABLE]')

@app.teardown_request
def remove_session(ex=None):
    session.remove()

@app.route('/', methods=["GET", "POST"])
def home():
    animals = None
    if request.form:
        try:
            animal = Animal(name=request.form.get("name"), typ=request.form.get("typ"))
            session.add(animal)
            session.commit()
        except Exception as e:
            print("Failed to add animals")
            print(e)
    try:
        animals = session.query(Animal).all()
        session.commit()
    except Exception as e:
        session.rollback()
        raise
    return render_template("home.html", animals=animals)

@app.route("/update", methods=["POST"])
def update():
    try:
        newname = request.form.get("newname")
        oldname = request.form.get("oldname")
        animal = session.query(Animal).filter_by(name=oldname).first()
        animal.name = newname
        session.commit()
    except Exception as e:
        print("Couldn't update animal name")
        print(e)
    return redirect("/")
  
  
@app.route("/delete", methods=["POST"])
def delete():
    name = request.form.get("name")
    animal = session.query(Animal).filter_by(name=name).first()
    session.delete(animal)
    session.commit()
    return redirect("/")
  
if __name__ == "__main__":
    app.run(debug=True)