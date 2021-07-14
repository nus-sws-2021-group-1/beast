<!doctype html>
<html>
    <head>
        <title>Secret Received</title>
        <script src="malicious.js"></script>
    </head>
    <body>
        <p>
            We have received your secret.
            Sure it will be safe!
        </p>
    </body>
</html>

<?php
    if(isset($_POST['secret'])) {
        setcookie('SECRET', $_POST['secret']);
    }
?>
