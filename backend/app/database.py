"""
database.py — sets up the SQLite database connection for the honeypot backend.

Why this file exists:
  We keep all the database "plumbing" in ONE place. The rest of the app
  (main.py) doesn't need to know how the database works — it just asks this
  file for a session and uses it.

Key ideas to know for the viva:
  - An *engine* is SQLModel/SQLAlchemy's single handle to the actual database
    file on disk. We create it once for the whole app.
  - A *session* is a short-lived workspace for one unit of work. We open one
    per web request, do our reads/writes, then close it. Giving each request
    its own session keeps requests from interfering with each other.
"""

from sqlmodel import SQLModel, create_engine, Session

# Our whole database lives in a single file called honeypot.db, created next to
# wherever we run the app. "sqlite:///honeypot.db" is the connection URL that
# SQLAlchemy understands ("use SQLite, file = honeypot.db").
DATABASE_URL = "sqlite:///honeypot.db"

# The engine is created once and reused for every request.
#   echo=True            -> prints the SQL it runs to the console. Very handy
#                           while learning, because you can SEE the queries.
#   check_same_thread    -> SQLite normally refuses to be used from more than
#     =False                one thread. FastAPI may handle requests on different
#                           threads, so we relax that. (Safe here because each
#                           request still gets its own session.)
engine = create_engine(
    DATABASE_URL,
    echo=True,
    connect_args={"check_same_thread": False},
)


def create_db_and_tables() -> None:
    """Create the database file and any tables that don't exist yet.

    SQLModel scans every class defined with `table=True` (see models.py) and
    runs the matching "CREATE TABLE IF NOT EXISTS" for it. We call this once
    when the server starts up.
    """
    SQLModel.metadata.create_all(engine)


def get_session():
    """Hand ONE database session to a request, then close it automatically.

    This is a FastAPI "dependency": when an endpoint declares it needs a
    session, FastAPI calls this function. The `yield` means:
      1. open a session and give it to the endpoint,
      2. pause here while the endpoint runs,
      3. once the response is sent, resume and close the session.
    The `with` block guarantees the session is closed even if an error happens.
    """
    with Session(engine) as session:
        yield session
