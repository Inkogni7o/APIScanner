using System.Data.SqlClient;

class Controller {
    void Lookup(string name, SqlConnection connection) {
        var query = "SELECT name FROM users WHERE name = '" + name + "'";
        var command = new SqlCommand(query, connection);
        command.ExecuteReader();
    }
}
