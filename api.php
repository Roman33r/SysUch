<?php
// Планёрка: хранение в MySQL. Страница работает с базой как с общим JSON-файлом, объединение правок происходит в браузере.
// shortcut: все данные одним документом: сервер защищает только сотрудников и роли, а задачи и чаты технически доступны любому вошедшему; для прав на них понадобятся отдельные таблицы
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
if (strlen($cfg['password'] ?? '') < 10) fail('В config.php задайте пароль администратора не короче 10 символов.', 500);

$pdo = new PDO("mysql:host={$cfg['db_host']};dbname={$cfg['db_name']};charset=utf8mb4", $cfg['db_user'], $cfg['db_pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$pdo->exec('CREATE TABLE IF NOT EXISTS planerka_doc (id TINYINT PRIMARY KEY, version BIGINT NOT NULL, data LONGTEXT NOT NULL, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
$pdo->exec('CREATE TABLE IF NOT EXISTS planerka_blobs (id VARCHAR(40) PRIMARY KEY, data LONGTEXT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
$pdo->exec('CREATE TABLE IF NOT EXISTS planerka_logins (ip VARCHAR(45) PRIMARY KEY, fails INT NOT NULL, at INT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
$pdo->exec('CREATE TABLE IF NOT EXISTS planerka_seen (who VARCHAR(40) PRIMARY KEY, at INT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
$pdo->exec('CREATE TABLE IF NOT EXISTS planerka_users (login VARCHAR(40) PRIMARY KEY, person VARCHAR(40) NOT NULL UNIQUE, hash VARCHAR(255) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
$pdo->exec("INSERT IGNORE INTO planerka_doc (id, version, data) VALUES (1, 0, '')");

$key = hash('sha256', $cfg['password'] . '|' . $cfg['db_pass']); // смена пароля администратора завершает все входы
const ADMIN = 'admin';
// хэш пароля входит в подпись: новый пароль или удаление пользователя завершают его входы
function token($login, $exp, $stamp, $key) { return "$login|$exp|" . hash_hmac('sha256', "$login|$exp|$stamp", $key); }
function userRow($pdo, $login) {
  $q = $pdo->prepare('SELECT login, person, hash FROM planerka_users WHERE login = ?');
  $q->execute([$login]);
  return $q->fetch(PDO::FETCH_ASSOC);
}
function publicUser($login, $row) { return ['login' => $login, 'person' => $row ? $row['person'] : null, 'admin' => !$row]; }
function currentUser($pdo, $key) {
  $parts = explode('|', $_COOKIE['planerka'] ?? '');
  if (count($parts) !== 3 || (int) $parts[1] <= time()) return null;
  $row = $parts[0] === ADMIN ? null : userRow($pdo, $parts[0]);
  if ($parts[0] !== ADMIN && !$row) return null;
  return hash_equals(token($parts[0], (int) $parts[1], $row ? $row['hash'] : '', $key), $_COOKIE['planerka']) ? publicUser($parts[0], $row) : null;
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

if ($action === 'status') { $me = currentUser($pdo, $key); reply(['planerka' => true, 'auth' => (bool) $me, 'user' => $me]); }

if ($action === 'login' && $isPost) {
  $ip = $_SERVER['REMOTE_ADDR'] ?? '';
  $q = $pdo->prepare('SELECT fails, at FROM planerka_logins WHERE ip = ?');
  $q->execute([$ip]);
  $row = $q->fetch(PDO::FETCH_ASSOC);
  $fails = $row && $row['at'] > time() - LOGIN_LOCK_MIN * 60 ? (int) $row['fails'] : 0;
  if ($fails >= LOGIN_FAILS) fail('Слишком много попыток. Подождите ' . LOGIN_LOCK_MIN . ' минут.', 429);
  $login = is_string($body['login'] ?? null) ? strtolower(trim($body['login'])) : '';
  $pass = is_string($body['password'] ?? null) ? $body['password'] : '';
  $row = $login === ADMIN ? null : userRow($pdo, $login);
  // хэш считается и для несуществующего логина, чтобы время ответа его не выдавало
  $ok = $login === ADMIN ? hash_equals($cfg['password'], $pass) : password_verify($pass, $row ? $row['hash'] : password_hash('', PASSWORD_DEFAULT)) && $row;
  if (!$ok) {
    $pdo->prepare('REPLACE INTO planerka_logins (ip, fails, at) VALUES (?, ?, ?)')->execute([$ip, $fails + 1, time()]);
    fail('Неверный логин или пароль.', 403);
  }
  $pdo->prepare('DELETE FROM planerka_logins WHERE ip = ?')->execute([$ip]);
  $exp = time() + TOKEN_DAYS * 86400;
  setToken(token($login, $exp, $row ? $row['hash'] : '', $key), $exp);
  reply(['ok' => true, 'user' => publicUser($login, $row)]);
}

if ($action === 'logout' && $isPost) { setToken('', time() - 3600); reply(['ok' => true]); }

$me = currentUser($pdo, $key);
if (!$me) fail('Нужно войти.', 401);

// сотрудники и роли из документа; браузер хранит их в том же виде
function peopleOf($doc) {
  $map = [];
  foreach ($doc['people'] ?? [] as $p) {
    if (!is_array($p) || !is_scalar($p['id'] ?? null)) continue;
    $map[(string) $p['id']] = ['name' => $p['name'] ?? '', 'role' => $p['role'] ?? '', 'cap' => $p['cap'] ?? 0, 'hue' => $p['hue'] ?? '', 'archived' => !empty($p['archived']), 'access' => $p['access'] ?? 'employee'];
  }
  return $map;
}
function storedPeople($pdo) { return peopleOf(json_decode((string) $pdo->query('SELECT data FROM planerka_doc WHERE id = 1')->fetchColumn(), true) ?: []); }
function accessOf($me, $people) {
  if ($me['admin']) return 'admin';
  $p = $people[$me['person']] ?? null;
  return $p && !$p['archived'] ? $p['access'] : 'employee';
}
// руководитель меняет сотрудников, но не роли и не карточки администраторов; сотрудник не меняет ничего
function peopleChangeError($old, $new, $access) {
  if ($access === 'admin') return null;
  if ($access !== 'manager') return $old == $new ? null : 'Менять сотрудников может только руководитель или администратор.';
  foreach ($new as $id => $p) if ($p['access'] !== ($old[$id]['access'] ?? 'employee')) return 'Выдавать роли может только администратор.';
  foreach ($old as $id => $p) if ($p['access'] === 'admin' && ($new[$id] ?? null) != $p) return 'Карточку администратора может менять только администратор.';
  return null;
}

if (in_array($action, ['users', 'user_save', 'user_del'], true)) {
  if (accessOf($me, storedPeople($pdo)) !== 'admin') fail('Это может только администратор.', 403);
  if ($action === 'users') reply(['users' => $pdo->query('SELECT login, person FROM planerka_users ORDER BY login')->fetchAll(PDO::FETCH_ASSOC)]);
  if (!$isPost) fail('Неверный запрос.', 405);
  $login = is_string($body['login'] ?? null) ? strtolower(trim($body['login'])) : '';
  if ($action === 'user_del') {
    $pdo->prepare('DELETE FROM planerka_users WHERE login = ?')->execute([$login]);
    reply(['ok' => true]);
  }
  $pass = $body['password'] ?? null;
  if (!is_string($pass) || strlen($pass) < 8 || strlen($pass) > 72) fail('Пароль должен быть длиной от 8 до 72 символов.', 400);
  $hash = password_hash($pass, PASSWORD_DEFAULT);
  if (userRow($pdo, $login)) {
    $pdo->prepare('UPDATE planerka_users SET hash = ? WHERE login = ?')->execute([$hash, $login]);
    reply(['ok' => true]);
  }
  if ($login === ADMIN || !preg_match('/^[a-z0-9._-]{2,40}$/', $login)) fail('Логин: от 2 до 40 латинских букв, цифр и знаков . _ - (имя admin занято).', 400);
  $person = $body['person'] ?? null;
  if (!is_string($person) || !preg_match('/^[\w-]{1,40}$/', $person)) fail('Выберите сотрудника.', 400);
  $q = $pdo->prepare('SELECT login FROM planerka_users WHERE person = ?');
  $q->execute([$person]);
  if ($q->fetchColumn() !== false) fail('У этого сотрудника уже есть логин.', 400);
  $pdo->prepare('INSERT INTO planerka_users (login, person, hash) VALUES (?, ?, ?)')->execute([$login, $person, $hash]);
  reply(['ok' => true]);
}

// браузер спрашивает версию каждые 5 секунд; here=1 значит, что Планёрка открыта на экране, так сервер узнаёт, кто в сети
if ($action === 'ver') {
  if (!empty($_GET['here'])) $pdo->prepare('REPLACE INTO planerka_seen (who, at) VALUES (?, ?)')->execute([$me['admin'] ? 'boss' : (string) $me['person'], time()]);
  $seen = array_map('intval', $pdo->query('SELECT who, at FROM planerka_seen')->fetchAll(PDO::FETCH_KEY_PAIR));
  reply(['version' => (int) $pdo->query('SELECT version FROM planerka_doc WHERE id = 1')->fetchColumn(), 'seen' => (object) $seen, 'now' => time()]);
}

if ($action === 'load') {
  $row = $pdo->query('SELECT version, data FROM planerka_doc WHERE id = 1')->fetch(PDO::FETCH_ASSOC);
  reply(['version' => (int) $row['version'], 'data' => $row['data']]);
}

if ($action === 'save' && $isPost) {
  $data = $body['data'] ?? null;
  $doc = is_string($data) && strlen($data) <= DOC_MAX ? json_decode($data, true) : null;
  if (!is_array($doc) || !is_array($doc['tasks'] ?? null) || !is_array($doc['people'] ?? null)) fail('Это не данные Планёрки или они слишком большие.', 400);
  // shortcut: если правка отклонена, браузер показывает ошибку и повторяет запись; нужна кнопка «взять данные с сервера», если права будут часто меняться во время работы
  if ((int) ($body['base'] ?? -1) > 0) {
    $old = storedPeople($pdo);
    $why = peopleChangeError($old, peopleOf($doc), accessOf($me, $old));
    if ($why) fail($why, 403);
  }
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
