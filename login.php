<?php
@include 'config.php';
session_start();

if (isset($_POST['submit'])) {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $pass = $_POST['pass'];

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message[] = 'Invalid email format!';
    } else {
        // Fetch user details securely
        $sql = "SELECT * FROM `users` WHERE email = ?";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$email]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row) {
            $stored_password = $row['password'];
            $is_password_correct = false;

            // Check if password is hashed using password_hash() (recommended)
            if (password_verify($pass, $stored_password)) {
                $is_password_correct = true;
            }
            // Check if password is stored as MD5 hash (not recommended, but fallback)
            elseif (md5($pass) === $stored_password) {
                $is_password_correct = true;
            }

            if ($is_password_correct) {
                $_SESSION['user_id'] = $row['id'];

                if ($row['user_type'] === 'admin') {
                    $_SESSION['admin_id'] = $row['id'];
                    header('location:admin_page.php');
                } else {
                    header('location:home.php');
                }
                exit();
            } else {
                $message[] = 'Incorrect email or password!';
            }
        } else {
            $message[] = 'User not found!';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.1/css/all.min.css">
    <link rel="stylesheet" href="css/components.css">
</head>
<body>

<?php
if (isset($message)) {
    foreach ($message as $msg) {
        echo '<div class="message">
            <span>' . htmlspecialchars($msg) . '</span>
            <i class="fas fa-times" onclick="this.parentElement.remove();"></i>
        </div>';
    }
}
?>

<section class="form-container">
    <form action="" method="POST">
        <h3>Login Now</h3>
        <input type="email" name="email" class="box" placeholder="Enter your email" required>
        <input type="password" name="pass" class="box" placeholder="Enter your password" required>
        <input type="submit" value="Login Now" class="btn" name="submit">
        <p>Don't have an account? <a href="register.php">Register Now</a></p>
    </form>
</section>

</body>
</html>