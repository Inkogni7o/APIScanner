fun lookup(name: String) {
    val query = "SELECT name FROM users WHERE name = '" + name + "'"
    connection.createStatement().executeQuery(query)
}
