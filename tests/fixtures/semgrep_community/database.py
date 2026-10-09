def lookup(name):
    cursor = connection.cursor()
    query = "SELECT name FROM users WHERE name = '%s'" % name
    return cursor.execute(query)
