<?php
function lookup($name) {
    $statement = $database->prepare("SELECT name FROM users WHERE name = ?");
    return $statement->execute([$name]);
}

echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
include('header.php');
$result = json_decode($_POST['data'], true);
