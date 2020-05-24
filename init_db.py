import sqlite3

SQLITE_PATH = 'sqlitedb.db'


def create_table(conn, sql):
    try:
        c = conn.cursor()
        c.execute(sql)
    except Exception as e:
        print(e)


create_statistic_sql = """CREATE TABLE IF NOT EXISTS statistic (
    id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
    mean real,
    dispersion real,
    standard_deviation real,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);"""

create_file_sql = """CREATE TABLE IF NOT EXISTS file (
    id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
    statistic_id integer NOT NULL,
    name text,
    path text,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (statistic_id) REFERENCES statistic (id)
);"""


if __name__ == '__main__':
    conn = sqlite3.connect(SQLITE_PATH)
    create_table(conn, create_statistic_sql)
    create_table(conn, create_file_sql)
