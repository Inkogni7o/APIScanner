<?php
function lookup($name) {
    $query = "SELECT name FROM users WHERE name = '" . $name . "'";
    return $database->query($query);
}

echo $_GET['name'];
include($_GET['template']);
$result = unserialize($_POST['data']);
