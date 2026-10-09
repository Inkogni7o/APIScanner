fun lookup(name: String) {
    val statement = connection.prepareStatement("SELECT name FROM users WHERE name = ?")
    statement.setString(1, name)
    statement.executeQuery()
}
