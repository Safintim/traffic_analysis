insert_statistic_sql = """
INSERT INTO statistic (mean, dispersion, standard_deviation)
VALUES (?, ?, ?);
"""

insert_file_sql = """
INSERT INTO file (statistic_id, path)
VALUES (?, ?);
"""


def insert(conn, sql, data):
    cursor = conn.cursor()
    cursor.execute(sql, data)
    conn.commit()
    return cursor


def insert_statistic(conn, data):
    return insert(conn, insert_statistic_sql, data)


def insert_file(conn, data):
    return insert(conn, insert_file_sql, data)
