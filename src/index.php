<?php

// Configure un gestionnaire d'erreur personnalisé
set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        return;
    }
    throw new ErrorException($message, 0, $severity, $file, $line);
});

register_shutdown_function(function() {
    $error = error_get_last();
    if ($error !== null && $error['type'] === E_ERROR) {
        throw new ErrorException($error['message'], 0, $error['type'], $error['file'], $error['line']);
    }
});

class Note {
    private $db;

    public function __construct($dbPath = 'database.sqlite') {
        $this->db = new PDO('sqlite:' . $dbPath);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->createTables();
    }

    private function createTables() {
        $this->db->exec('CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )');

        $this->db->exec('CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )');
    }

    private function generateEncryptionKey($userId) {
        $stmt = $this->db->prepare('SELECT password, created_at FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            throw new Exception("Utilisateur non trouvé.");
        }

        $salt = $user['created_at'] . $userId;
        $key = hash_pbkdf2("sha256", $user['password'], $salt, 100000, 32);

        return $key;
    }

    private function encryptNoteContent($content, $key) {
        $iv = openssl_random_pseudo_bytes(16);
        $encryptedContent = openssl_encrypt($content, 'aes-256-cbc', $key, 0, $iv);
        return base64_encode($iv . $encryptedContent);
    }

    private function decryptNoteContent($encryptedContent, $key) {
        $encryptedContent = base64_decode($encryptedContent);
        $iv = substr($encryptedContent, 0, 16);
        $ciphertext = substr($encryptedContent, 16);
        return openssl_decrypt($ciphertext, 'aes-256-cbc', $key, 0, $iv);
    }

    public function addNote($title, $content, $userId) {
        $key = $this->generateEncryptionKey($userId);
        $encryptedContent = $this->encryptNoteContent($content, $key);

        $stmt = $this->db->prepare('INSERT INTO notes (title, content, created_at, updated_at, user_id) VALUES (?, ?, datetime("now"), datetime("now"), ?)');
        return $stmt->execute([$title, $encryptedContent, $userId]);
    }

    public function updateNote($id, $title, $content, $userId) {
        $key = $this->generateEncryptionKey($userId);
        $encryptedContent = $this->encryptNoteContent($content, $key);

        $stmt = $this->db->prepare('UPDATE notes SET title = ?, content = ?, updated_at = datetime("now") WHERE id = ? AND user_id = ?');
        return $stmt->execute([$title, $encryptedContent, $id, $userId]);
    }

    public function getAllNotesByUser($userId) {
        $key = $this->generateEncryptionKey($userId);

        $stmt = $this->db->prepare('SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC');
        $stmt->execute([$userId]);
        $notes = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($notes as &$note) {
            $note['content'] = $this->decryptNoteContent($note['content'], $key);
        }

        return $notes;
    }

    public function getNoteById($id, $userId) {
        $key = $this->generateEncryptionKey($userId);

        $stmt = $this->db->prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?');
        $stmt->execute([$id, $userId]);
        $note = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($note) {
            $note['content'] = $this->decryptNoteContent($note['content'], $key);
        }

        return $note;
    }

    public function deleteNoteById($id, $userId) {
        $stmt = $this->db->prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
        return $stmt->execute([$id, $userId]);
    }

    public function registerUser($username, $password) {
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->db->prepare('INSERT INTO users (username, password, created_at) VALUES (?, ?, datetime("now"))');
        return $stmt->execute([$username, $hashedPassword]);
    }

    public function loginUser($username, $password) {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE username = ?');
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }
        return false;
    }
}

session_start();
$note = new Note();
$action = isset($_GET['action']) ? $_GET['action'] : 'list';
$htmlContent = '';
$message = '';

try {
    if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $user = $note->loginUser($_POST['username'], $_POST['password']);
        if ($user) {
            $_SESSION['user_id'] = $user['id'];
            header('Location: index.php');
            exit;
        } else {
            $message = '<p style="color:red;">Nom d\'utilisateur ou mot de passe incorrect.</p>';
        }
    }

    if ($action === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $note->registerUser($_POST['username'], $_POST['password']);
        $message = '<p style="color:green;">Compte créé avec succès !</p>';
        header('Location: index.php?action=login');
        exit;
    }

    if ($action === 'logout') {
        session_destroy();
        header('Location: index.php?action=login');
        exit;
    }

    if (!isset($_SESSION['user_id']) && !in_array($action, ['login', 'register'])) {
        header('Location: index.php?action=login');
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if ($action === 'add') {
            $note->addNote($_POST['title'], $_POST['content'], $_SESSION['user_id']);
            $message = '<p style="color:green;">Note ajoutée avec succès !</p>';
            header('Location: index.php');
            exit;
        } elseif ($action === 'edit' && isset($_GET['id'])) {
            $note->updateNote($_GET['id'], $_POST['title'], $_POST['content'], $_SESSION['user_id']);
            $message = '<p style="color:green;">Note mise à jour avec succès !</p>';
            header('Location: index.php');
            exit;
        }
    }

    if ($action === 'delete' && isset($_GET['id'])) {
        $note->deleteNoteById($_GET['id'], $_SESSION['user_id']);
        $message = '<p style="color:green;">Note supprimée avec succès !</p>';
        header('Location: index.php');
        exit;
    }

    ob_start();

    if (!isset($_SESSION['user_id']) && $action === 'login') {
        $htmlContent .= $message;
        $htmlContent .= '<h1>Connexion</h1>';
        $htmlContent .= '<form method="post">';
        $htmlContent .= '<label>Nom d\'utilisateur:</label>';
        $htmlContent .= '<input type="text" name="username" required>';
        $htmlContent .= '<label>Mot de passe:</label>';
        $htmlContent .= '<input type="password" name="password" required>';
        $htmlContent .= '<button type="submit">Se connecter</button>';
        $htmlContent .= '</form>';
        $htmlContent .= '<p>Pas de compte ? <a href="index.php?action=register">S\'inscrire</a></p>';
    } elseif (!isset($_SESSION['user_id']) && $action === 'register') {
        $htmlContent .= $message;
        $htmlContent .= '<h1>Inscription</h1>';
        $htmlContent .= '<form method="post">';
        $htmlContent .= '<label>Nom d\'utilisateur:</label>';
        $htmlContent .= '<input type="text" name="username" required>';
        $htmlContent .= '<label>Mot de passe:</label>';
        $htmlContent .= '<input type="password" name="password" required>';
        $htmlContent .= '<button type="submit">S\'inscrire</button>';
        $htmlContent .= '</form>';
        $htmlContent .= '<p>Déjà un compte ? <a href="index.php?action=login">Se connecter</a></p>';
    } elseif ($action === 'add') {
        $htmlContent .= '<h1>Ajouter une nouvelle note</h1>';
        $htmlContent .= '<form method="post">';
        $htmlContent .= '<label>Titre:</label>';
        $htmlContent .= '<input type="text" name="title" required>';
        $htmlContent .= '<label>Contenu:</label>';
        $htmlContent .= '<textarea name="content" required></textarea>';
        $htmlContent .= '<button type="submit">Ajouter</button>';
        $htmlContent .= '</form>';
        $htmlContent .= '<a href="index.php" style="color: blue; text-decoration: underline; font-weight: bold;">Retour à la liste des notes</a>';
    } elseif ($action === 'edit' && isset($_GET['id'])) {
        $noteToEdit = $note->getNoteById($_GET['id'], $_SESSION['user_id']);
        if ($noteToEdit) {
            $htmlContent .= '<h1>Modifier la note</h1>';
            $htmlContent .= '<form method="post">';
            $htmlContent .= '<label>Titre:</label>';
            $htmlContent .= '<input type="text" name="title" value="' . htmlspecialchars($noteToEdit['title']) . '" required>';
            $htmlContent .= '<label>Contenu:</label>';
            $htmlContent .= '<textarea name="content" required>' . htmlspecialchars($noteToEdit['content']) . '</textarea>';
            $htmlContent .= '<button type="submit">Mettre à jour</button>';
            $htmlContent .= '</form>';
            $htmlContent .= '<a href="index.php" style="color: blue; text-decoration: underline; font-weight: bold;">Retour à la liste des notes</a>';
        } else {
            $htmlContent .= '<p>Note non trouvée.</p>';
        }
    } else {
        $htmlContent .= '<h1>Liste des notes</h1>';
        $notes = $note->getAllNotesByUser($_SESSION['user_id']);
        if ($notes) {
            foreach ($notes as $noteItem) {
                $htmlContent .= '<div>';
                $htmlContent .= '<h2>' . htmlspecialchars($noteItem['title']) . '</h2>';
                $htmlContent .= '<p>' . htmlspecialchars($noteItem['content']) . '</p>';
                $htmlContent .= '<a href="index.php?action=edit&id=' . $noteItem['id'] . '">Modifier</a>';
                $htmlContent .= ' | ';
                $htmlContent .= '<a href="index.php?action=delete&id=' . $noteItem['id'] . '" onclick="return confirm(\'Êtes-vous sûr de vouloir supprimer cette note ?\')">Supprimer</a>';
                $htmlContent .= '</div>';
            }
        } else {
            $htmlContent .= '<p>Aucune note disponible.</p>';
        }
        $htmlContent .= '<a href="index.php?action=add" style="color: blue; text-decoration: underline; font-weight: bold;">Ajouter une nouvelle note</a>';
        $htmlContent .= '<p><a href="index.php?action=logout">Se déconnecter</a></p>';
    }

    echo $htmlContent;
    ob_end_flush();
} catch (Exception $e) {
    // Gérer les exceptions et afficher une page d'erreur générique
    $htmlContent = '<h1>Une erreur est survenue</h1>';
    $htmlContent .= '<p>Nous rencontrons un problème technique. Veuillez réessayer plus tard.</p>';
    $htmlContent .= '<a href="index.php">Retour à la page d\'accueil</a>';
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestion de Bloc-Notes</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
        }

        .container {
            max-width: 900px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border-radius: 5px;
        }

        h1 {
            text-align: center;
            color: #333;
        }

        form {
            display: flex;
            flex-direction: column;
        }

        label {
            margin: 10px 0 5px;
            color: #333;
        }

        input[type="text"],
        input[type="password"],
        textarea {
            padding: 10px;
            font-size: 16px;
            border: 1px solid #ccc;
            border-radius: 4px;
            width: 100%;
        }

        button {
            margin-top: 15px;
            padding: 10px;
            background-color: #28a745;
            color: white;
            border: none;
            cursor: pointer;
            font-size: 16px;
            border-radius: 4px;
        }

        button:hover {
            background-color: #218838;
        }

        a {
            color: #007bff;
            text-decoration: none;
        }

        a:hover {
            text-decoration: underline;
        }

        ul {
            list-style: none;
            padding: 0;
        }

        li {
            background-color: #f9f9f9;
            margin: 10px 0;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }

        .note-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .note-header a {
            margin-left: 15px;
            padding: 6px 12px;
            border-radius: 4px;
            text-decoration: none;
            font-size: 14px;
            font-weight: bold;
            color: white;
        }

        .note-header a[href*="edit"] {
            background-color: #ffc107;
        }

        .note-header a[href*="edit"]:hover {
            background-color: #e0a800;
        }

        .note-header a[href*="delete"] {
            background-color: #dc3545;
        }

        .note-header a[href*="delete"]:hover {
            background-color: #c82333;
        }

        a[href*="logout"] {
            display: inline-block;
            background-color: #17a2b8;
            color: white;
            padding: 10px 15px;
            margin-top: 15px;
            border-radius: 4px;
            text-align: center;
        }

        a[href*="logout"]:hover {
            background-color: #138496;
        }

        a[href*="add"] {
            display: inline-block;
            background-color: #28a745;
            color: white;
            padding: 10px 15px;
            margin-top: 15px;
            border-radius: 4px;
            text-align: center;
        }

        a[href*="add"]:hover {
            background-color: #218838;
        }

    </style>
</head>
<body>

<div class="container">
    <?php echo $htmlContent; // Display the generated HTML content ?>
</div>

</body>
</html>
