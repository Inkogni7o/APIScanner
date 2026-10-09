using System.Data.SqlClient;

class Controller {
    void Lookup(string name, SqlConnection connection) {
        var command = new SqlCommand("SELECT name FROM users WHERE name = @name", connection);
        command.Parameters.AddWithValue("@name", name);
        command.ExecuteReader();
    }
}
