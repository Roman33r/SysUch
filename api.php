<?php
// Планёрка: хранение в MySQL. Страница работает с базой как с общим JSON-файлом, объединение правок происходит в браузере.
// shortcut: один пароль на команду и все данные одним документом; отдельные таблицы и личные входы понадобятся, когда нужны права по сотрудникам
ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

const TOKEN_DAYS = 30, LOGIN_FAILS = 5, LOGIN_LOCK_MIN = 15, DOC_MAX = 16 * 1024 * 1024, BLOB_MAX = 7500000; // 5 МБ файла в base64 с запасом

function reply($data, $code = 200) { http_response_code($code); echo json_encode($data, JSON_UNESCAPED_UNICODE); exit; }
function fail($text, $code) { reply(['planerka' => true, 'error' => $text], $code); }

set_exception_handler(function ($e) { error_log('planerka: ' . $e->getMessage()); fail('База данных недоступна. Проверьте настройки в config.php.', 500); });

$cfgFile = __DIR__ . '/config.php';
if (!is_file($cfgFile)) fail('Нет файла config.php. Создайте его из config.sample.php.', 500);
$cfg = require $cfgFile;
if (strlen($cfg['password'] ?? '') < 10) fail('В config.php задайте пароль команды не короче 10 символов.', 500);

$pdo = new PDO("mysql:host={$cfg['db_host']};dbname={$cfg['db_name']};charset=utf8mb4", $cfg['db_user'], $cfg['db_pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$pdo->exec('CREATE TABLE IF NOT EXISTS planerka_doc (id TINYINT PRIMARY KEY, version BIGINT NOT NULL, data LONGTEXT NOT NULL, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
$pdo->exec('CREATE TABLE IF NOT EXISTS planerka_blobs (id VARCHAR(40) PRIMARY KEY, data LONGTEXT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
$pdo->exec('CREATE TABLE IF NOT EXISTS planerka_logins (ip VARCHAR(45) PRIMARY KEY, fails INT NOT NULL, at INT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
$pdo->exec("INSERT IGNORE INTO planerka_doc (id, version, data) VALUES (1, 0, '')");

$key = hash('sha256', $cfg['password'] . '|' . $cfg['db_pass']); // смена пароля команды завершает все входы
function token($exp, $key) { return $exp . '.' . hash_hmac('sha256', (string) $exp, $key); }
function authed($key) {
  $parts = explode('.', $_COOKIE['planerka'] ?? '');
  return count($parts) === 2 && (int) $parts[0] > time() && hash_equals(token((int) $parts[0], $key), $_COOKIE['planerka']);
}
function setToken($value, $exp) {
  $https = ($_SERVER['HTTPS'] ?? '') === 'on' || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
  setcookie('planerka', $value, ['expires' => $exp, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict', 'secure' => $https]);
}

$action = $_GET['a'] ?? '';
$isPost = $_SERVER['REQUEST_METHOD'] === 'POST';
$body = [];
if ($isPost) {
  // чужой сайт не может отправить такой запрос без разрешения
  if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) fail('Неверный запрос.', 415);
  $body = json_decode(file_get_contents('php://input'), true);
  if (!is_array($body)) fail('Данные не дошли: возможно, запрос больше лимита хостинга (post_max_size).', 413);
}

if ($action === 'status') reply(['planerka' => true, 'auth' => authed($key)]);

if ($action === 'login' && $isPost) {
  $ip = $_SERVER['REMOTE_ADDR'] ?? '';
  $q = $pdo->prepare('SELECT fails, at FROM planerka_logins WHERE ip = ?');
  $q->execute([$ip]);
  $row = $q->fetch(PDO::FETCH_ASSOC);
  $fails = $row && $row['at'] > time() - LOGIN_LOCK_MIN * 60 ? (int) $row['fails'] : 0;
  if ($fails >= LOGIN_FAILS) fail('Слишком много попыток. Подождите ' . LOGIN_LOCK_MIN . ' минут.', 429);
  if (!is_string($body['password'] ?? null) || !hash_equals($cfg['password'], $body['password'])) {
    $pdo->prepare('REPLACE INTO planerka_logins (ip, fails, at) VALUES (?, ?, ?)')->execute([$ip, $fails + 1, time()]);
    fail('Неверный пароль.', 403);
  }
  $pdo->prepare('DELETE FROM planerka_logins WHERE ip = ?')->execute([$ip]);
  $exp = time() + TOKEN_DAYS * 86400;
  setToken(token($exp, $key), $exp);
  reply(['ok' => true]);
}

if ($action === 'logout' && $isPost) { setToken('', time() - 3600); reply(['ok' => true]); }

if (!authed($key)) fail('Нужно войти.', 401);

if ($action === 'ver') reply(['version' => (int) $pdo->query('SELECT version FROM planerka_doc WHERE id = 1')->fetchColumn()]);

if ($action === 'load') {
  $row = $pdo->query('SELECT version, data FROM planerka_doc WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
  reply(['version' => (int) $row['version'], 'data' => $row['data']]);
}

if ($action === 'save' && $isPost) {
  $data = $body['data'] ?? null;
  $doc = is_string($data) && strlen($data) <= DOC_MAX ? json_decode($data, true) : null;
  if (!is_array($doc) || !is_array($doc['tasks'] ?? null) || !is_array($doc['people'] ?? null)) fail('Это не данные Планёрки или они слишком большие.', 400);
  // записать можно только поверх той версии, что видел браузер; иначе он сначала объединит чужие правки
  $q = $pdo->prepare('UPDATE planerka_doc SET data = ?, version = version + 1 WHERE id = 1 AND version = ?');
  $q->execute([$data, (int) ($body['base'] ?? -1)]);
  if ($q->rowCount() !== 1) fail('Данные уже изменил кто-то другой.', 409);
  reply(['version' => (int) $pdo->query('SELECT version FROM planerka_doc WHERE id = 1')->fetchColumn()]);
}

// shortcut: содержимое удалённых вложений остаётся в таблице; чистить, если база начнёт заметно расти
if ($action === 'blob') {
  if ($isPost) {
    $id = $body['id'] ?? ''; $data = $body['data'] ?? '';
    if (!is_string($id) || !preg_match('/^[\w-]{1,40}$/', $id) || !is_string($data) || strncmp($data, 'data:', 5) !== 0 || strlen($data) > BLOB_MAX) fail('Файл не подходит.', 400);
    $pdo->prepare('REPLACE INTO planerka_blobs (id, data) VALUES (?, ?)')->execute([$id, $data]);
    reply(['ok' => true]);
  }
  $q = $pdo->prepare('SELECT data FROM planerka_blobs WHERE id = ?');
  $q->execute([$_GET['id'] ?? '']);
  $data = $q->fetchColumn();
  if ($data === false) fail('Файл не найден.', 404);
  reply(['data' => $data]);
}

fail('Неизвестное действие.', 404);
