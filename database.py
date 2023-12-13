import sqlite3
from flask import g

# def connect_to_database():
#     sql = sqlite3.connect("biokart.db")
#     sql.row_factory = sqlite3.Row
#     return sql

# def get_database():
#     if not hasattr(g, "biokart_db"):
#         g.biokart_db = connect_to_database()
#     return g.biokart_db


def connect_to_database():
    try:
        sql = sqlite3.connect("biokart.db")
        sql.row_factory = sqlite3.Row
        return sql
    except sqlite3.Error as e:
        return {"error": f"Database connection error: {str(e)}"}, 500

def get_database():
    if not hasattr(g, "biokart_db"):
        try:
            g.biokart_db = connect_to_database()
        except Exception as e:
            return {"error": f"Failed to get database connection: {str(e)}"}, 500
    return g.biokart_db