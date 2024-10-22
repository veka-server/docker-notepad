<?php

// Configure un gestionnaire d'erreur personnalisé
set_error_handler(function ($severity, $message, $file, $line) {
    // Vérifie si ce type d'erreur doit être capturé
    if (!(error_reporting() & $severity)) {
        // Ce type d'erreur est masqué par le paramètre de error_reporting
        return;
    }

    // Lance une exception
    throw new ErrorException($message, 0, $severity, $file, $line);
});

// Autre option : transforme les exceptions fatales non capturées en erreurs
register_shutdown_function(function() {
    $error = error_get_last();
    if ($error !== null && $error['type'] === E_ERROR) {
        // Transforme l'erreur fatale en exception
        throw new ErrorException($error['message'], 0, $error['type'], $error['file'], $error['line']);
    }
});

class Note {
    private $db;

    public function __construct($dbPath = 'db/database.sqlite') {
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

    // Génération de la clé de chiffrement pour un utilisateur donné
    private function generateEncryptionKey($userId) {
        // Récupérer les infos de l'utilisateur (mot de passe, id, date de création)
        $stmt = $this->db->prepare('SELECT password, created_at FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            throw new Exception("Utilisateur non trouvé.");
        }

        // Combinaison des informations pour générer la clé
        $salt = $user['created_at'] . $userId; // Utilisation de la date de création et de l'ID comme sel
        $key = hash_pbkdf2("sha256", $user['password'], $salt, 100000, 32); // Génère une clé de 256 bits

        return $key;
    }

    // Fonction pour chiffrer une note
    private function encryptNoteContent($content, $key) {
        $iv = openssl_random_pseudo_bytes(16); // Génère un IV aléatoire de 16 octets
        $encryptedContent = openssl_encrypt($content, 'aes-256-cbc', $key, 0, $iv);
        return base64_encode($iv . $encryptedContent); // Stocke IV + contenu chiffré
    }

    // Fonction pour déchiffrer une note
    private function decryptNoteContent($encryptedContent, $key) {
        $encryptedContent = base64_decode($encryptedContent);
        $iv = substr($encryptedContent, 0, 16); // Séparer l'IV du contenu chiffré
        $ciphertext = substr($encryptedContent, 16);
        return openssl_decrypt($ciphertext, 'aes-256-cbc', $key, 0, $iv);
    }

    // Ajouter une note (avec chiffrement)
    public function addNote($title, $content, $userId) {
        $key = $this->generateEncryptionKey($userId);
        $encryptedContent = $this->encryptNoteContent($content, $key);

        $stmt = $this->db->prepare('INSERT INTO notes (title, content, created_at, updated_at, user_id) VALUES (?, ?, datetime("now"), datetime("now"), ?)');
        return $stmt->execute([$title, $encryptedContent, $userId]);
    }

    // Mettre à jour une note (avec chiffrement)
    public function updateNote($id, $title, $content, $userId) {
        $key = $this->generateEncryptionKey($userId);
        $encryptedContent = $this->encryptNoteContent($content, $key);

        $stmt = $this->db->prepare('UPDATE notes SET title = ?, content = ?, updated_at = datetime("now") WHERE id = ? AND user_id = ?');
        return $stmt->execute([$title, $encryptedContent, $id, $userId]);
    }

    // Récupérer toutes les notes d'un utilisateur (avec déchiffrement)
    public function getAllNotesByUser($userId) {
        $key = $this->generateEncryptionKey($userId);

        $stmt = $this->db->prepare('SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC');
        $stmt->execute([$userId]);
        $notes = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Déchiffrement des notes
        foreach ($notes as &$note) {
            $note['content'] = $this->decryptNoteContent($note['content'], $key);
        }

        return $notes;
    }

    // Récupérer une note spécifique (avec déchiffrement)
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

    // Suppression de note (pas de changement pour cette partie)
    public function deleteNoteById($id, $userId) {
        $stmt = $this->db->prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
        return $stmt->execute([$id, $userId]);
    }

    // Inscription d'un utilisateur
    public function registerUser($username, $password) {
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->db->prepare('INSERT INTO users (username, password, created_at) VALUES (?, ?, datetime("now"))');
        return $stmt->execute([$username, $hashedPassword]);
    }

    // Connexion utilisateur (inchangé)
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
$htmlContent = ''; // Variable to hold HTML content
$message = '';

try {
    // Connexion utilisateur
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

    // Inscription utilisateur
    if ($action === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $note->registerUser($_POST['username'], $_POST['password']);
        header('Location: index.php?action=login');
        exit;
    }

    // Déconnexion utilisateur
    if ($action === 'logout') {
        session_destroy();
        header('Location: index.php?action=login');
        exit;
    }

    // Gestion de la session utilisateur
    if (!isset($_SESSION['user_id']) && !in_array($action, ['login', 'register'])) {
        header('Location: index.php?action=login');
        exit;
    }

    // Traitement des actions (Ajout, Édition, Suppression, Liste)
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if ($action === 'add') {
            $note->addNote($_POST['title'], $_POST['content'], $_SESSION['user_id']);
            header('Location: index.php');
            exit;
        } elseif ($action === 'edit' && isset($_GET['id'])) {
            $note->updateNote($_GET['id'], $_POST['title'], $_POST['content'], $_SESSION['user_id']);
            header('Location: index.php');
            exit;
        }
    }

    if ($action === 'delete' && isset($_GET['id'])) {
        $note->deleteNoteById($_GET['id'], $_SESSION['user_id']);
        header('Location: index.php');
        exit;
    }

    // Si aucune action valide n'est trouvée
    if (!in_array($action, ['list', 'add', 'edit', 'delete', 'login', 'register'])) {
        throw new Exception('Action inconnue');
    }

    ob_start(); // Start output buffering

    $htmlContent = $message;

    // Generate HTML content
    if (!isset($_SESSION['user_id']) && $action === 'login') {
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
        $htmlContent .= '<h1>Inscription</h1>';
        $htmlContent .= '<form method="post">';
        $htmlContent .= '<label>Nom d\'utilisateur:</label>';
        $htmlContent .= '<input type="text" name="username" required>';
        $htmlContent .= '<label>Mot de passe:</label>';
        $htmlContent .= '<input type="password" name="password" required>';
        $htmlContent .= '<button type="submit">S\'inscrire</button>';
        $htmlContent .= '</form>';
        $htmlContent .= '<p>Déjà un compte ? <a href="index.php?action=login">Se connecter</a></p>';

    } elseif (isset($_SESSION['user_id'])) {
        if ($action === 'list') {
            $htmlContent .= '<h1>Liste des Blocs-Notes</h1>';
            $htmlContent .= '<a href="?action=add">Ajouter un Bloc-Note</a> <a href="?action=logout">Se déconnecter</a>';
            $htmlContent .= '<ul>';
            foreach ($note->getAllNotesByUser($_SESSION['user_id']) as $n) {
                $htmlContent .= '<li>';
                $htmlContent .= '<div class="note-header">';
                $htmlContent .= '<strong>' . htmlspecialchars($n['title']) . '</strong>';
                $htmlContent .= '<a href="?action=edit&id=' . $n['id'] . '">Modifier</a>';
                $htmlContent .= '<a href="?action=delete&id=' . $n['id'] . '" onclick="return confirm(\'Êtes-vous sûr de vouloir supprimer ce bloc-note ?\')">Supprimer</a>';
                $htmlContent .= '</div>';
                $htmlContent .= 'Créé le: ' . $n['created_at'] . '<br>';
                $htmlContent .= 'Dernière édition: ' . $n['updated_at'] . '<br>';
                $htmlContent .= 'Taille: ' . strlen($n['content']) . ' octets';
                $htmlContent .= '</li>';
            }
            $htmlContent .= '</ul>';

        } elseif ($action === 'add') {
            $htmlContent .= '<h1>Ajouter un Bloc-Note</h1>';
            $htmlContent .= '<form method="post">';
            $htmlContent .= '<label>Titre:</label>';
            $htmlContent .= '<input type="text" name="title" required>';
            $htmlContent .= '<label>Contenu:</label>';
            $htmlContent .= '<textarea name="content" rows="8" required></textarea>';
            $htmlContent .= '<button type="submit">Ajouter</button>';
            $htmlContent .= '</form>';
            $htmlContent .= '<a href="index.php">Retour à la liste</a>';

        } elseif ($action === 'edit' && isset($_GET['id'])) {
            $noteData = $note->getNoteById($_GET['id'], $_SESSION['user_id']);
            $title = htmlspecialchars($noteData['title']);
            $content = htmlspecialchars($noteData['content']);

            $htmlContent .= '<h1>Modifier le Bloc-Note</h1>';
            $htmlContent .= '<form method="post">';
            $htmlContent .= '<label>Titre:</label>';
            $htmlContent .= '<input type="text" name="title" value="' . $title . '" required>';
            $htmlContent .= '<label>Contenu:</label>';
            $htmlContent .= '<textarea name="content" rows="8" required>' . $content . '</textarea>';
            $htmlContent .= '<button type="submit">Modifier</button>';
            $htmlContent .= '</form>';
            $htmlContent .= '<a href="index.php">Retour à la liste</a>';
        }
    }

    $htmlContent .= ob_get_clean(); // Store output buffer in the variable
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
