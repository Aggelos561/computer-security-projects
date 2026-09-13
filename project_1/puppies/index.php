<?php

    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
    header("Access-Control-Allow-Headers: Content-Type");

    $filename = "/var/www/puppies/rfi_data.txt";

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {

        $fileContent = $_POST['fileContent'];
        $file = fopen($filename, "w");
        fwrite($file, $fileContent);
        fclose($file);

    }

    exit;

?>

<html>
  <body>
    <h1><?= "Puppies!" ?></h1>
    <img src="https://i.ytimg.com/vi/DhpYAyVsFXQ/hqdefault.jpg"></img>
  </body>
</html>
