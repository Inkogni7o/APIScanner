object Database {
  def connect() = {
    java.sql.DriverManager.getConnection("jdbc:postgresql:db", "app", "hardcoded-password");
  }
}
