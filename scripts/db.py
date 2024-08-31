import sqlite3
import argparse
import os

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(e)
    return conn
    
def create_db(conn):
    createContentTable="""CREATE TABLE IF NOT EXISTS content (
            id integer PRIMARY KEY,
            location text NOT NULL,
            content blob);"""
    try:
        c = conn.cursor()
        c.execute(createContentTable)
    except Error as e:
        print(e)

def insert_content(conn, data):
    insertContent="""INSERT INTO content VALUES (NULL, ?, ?);"""
    try:
        c = conn.cursor()
        c.execute(insertContent, data)
        rowid = c.lastrowid
        print (rowid)
    except sqlite3.Error as e:
        print(e)

def get_content(conn, location):
    getcontent="""SELECT content FROM content WHERE location = ?"""
    try:
        c = conn.cursor()
        c.execute(getcontent, location)
        return (c.fetchone()[0])
    except sqlite3.Error as e:
        print(e)

def get_locations(conn):
    getlocations="""SELECT location FROM content"""
    try:
        c = conn.cursor()
        c.execute(getlocations)
        return (c.fetchall())
    except sqlite3.Error as e:
        print(e)
    

if __name__ == "__main__":
    database = r"sqlite.db"
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--create','-c', help='Create Database', action='store_true')
    group.add_argument('--insert','-i', help='Insert Content', action='store_true')
    group.add_argument('--get','-g', help='Get Content', action='store_true')
    group.add_argument('--getLocations','-l', help='Get all Locations', action='store_true')

    parser.add_argument('--location','-L')
    parser.add_argument('--content','-C')
    args = parser.parse_args()
    
    conn = create_connection(database)

    if (args.create):
        print("[+] Creating Database")
        create_db(conn)
    elif (args.insert):
        if(args.location is None and args.content is None):
            parser.error("--insert requires --location, --content.")
        else:
            print("[+] Inserting Data")
            insert_content(conn, (args.location, args.content))
            conn.commit()
    elif (args.get):
        if(args.location is None):
            parser.error("--get requires --location, --content.")
        else:
            print("[+] Getting Content")
            print(get_content(conn, (args.location,)))
    if (args.getLocations):
        print("[+] Getting All Locations")
        print(get_locations(conn))
