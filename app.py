import os
import time
import hmac
import hashlib
from flask import Flask, request, jsonify, render_template_string
from werkzeug.middleware.proxy_fix import ProxyFix
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

PEPPER_SECRET = os.environ.get("APP_PEPPER_SECRET", "secret_server_pepper_key_2026")

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID
)


def apply_pepper(password: str) -> str:
    return hmac.new(
        PEPPER_SECRET.encode("utf-8"),
        password.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


MAX_FAILED_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 180
FAILED_LOGIN_LOG = {}


def get_client_ip() -> str:
    return request.remote_addr or "127.0.0.1"


def clean_and_get_attempts(key: str, now: float) -> list:
    attempts = FAILED_LOGIN_LOG.get(key, [])
    valid_attempts = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
    if valid_attempts:
        FAILED_LOGIN_LOG[key] = valid_attempts
    else:
        FAILED_LOGIN_LOG.pop(key, None)
    return valid_attempts


def check_rate_limit(ip: str, username: str) -> int:
    now = time.time()
    ip_attempts = clean_and_get_attempts(f"ip:{ip}", now)
    user_attempts = clean_and_get_attempts(f"user:{username.lower()}", now) if username else []

    wait_ip = int(RATE_LIMIT_WINDOW - (now - ip_attempts[0])) + 1 if len(ip_attempts) >= MAX_FAILED_ATTEMPTS else 0
    wait_user = int(RATE_LIMIT_WINDOW - (now - user_attempts[0])) + 1 if len(user_attempts) >= MAX_FAILED_ATTEMPTS else 0

    return max(wait_ip, wait_user)


def record_failed_attempt(ip: str, username: str) -> tuple[int, int]:
    now = time.time()
    ip_key = f"ip:{ip}"
    ip_attempts = clean_and_get_attempts(ip_key, now)
    ip_attempts.append(now)
    FAILED_LOGIN_LOG[ip_key] = ip_attempts

    user_attempts = []
    if username:
        user_key = f"user:{username.lower()}"
        user_attempts = clean_and_get_attempts(user_key, now)
        user_attempts.append(now)
        FAILED_LOGIN_LOG[user_key] = user_attempts

    used = max(len(ip_attempts), len(user_attempts))
    remaining = max(0, MAX_FAILED_ATTEMPTS - used)
    retry_after = check_rate_limit(ip, username) if remaining == 0 else 0
    return remaining, retry_after


def clear_failed_attempts(ip: str, username: str):
    FAILED_LOGIN_LOG.pop(f"ip:{ip}", None)
    if username:
        FAILED_LOGIN_LOG.pop(f"user:{username.lower()}", None)


BREACHED_PASSWORDS = {
    "123456", "password", "12345678", "123456789", "12345",
    "qwerty", "qwerty123", "admin123", "iloveyou", "welcome123"
}

HIBP_INDEX = {}
for pwd in BREACHED_PASSWORDS:
    sha1_hex = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    HIBP_INDEX.setdefault(sha1_hex[:5], set()).add(sha1_hex[5:])


def is_password_pwned(password: str) -> bool:
    sha1_full = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_full[:5], sha1_full[5:]
    return suffix in HIBP_INDEX.get(prefix, set())


USERS_DB = {
    "admin": ph.hash(apply_pepper("AnToan@2026"))
}
DUMMY_HASH = USERS_DB["admin"]


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    confirm = data.get("confirm_password", "")

    if not username or not password:
        return jsonify({"error": "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu."}), 400

    if len(username) < 3:
        return jsonify({"error": "Tên đăng nhập phải có ít nhất 3 ký tự."}), 400

    if username.lower() in (u.lower() for u in USERS_DB):
        return jsonify({"error": "Tên đăng nhập này đã được sử dụng."}), 409

    if len(password) < 8:
        return jsonify({"error": "Mật khẩu phải có ít nhất 8 ký tự."}), 400

    if password != confirm:
        return jsonify({"error": "Mật khẩu xác nhận không khớp."}), 400

    if is_password_pwned(password):
        return jsonify({
            "error": "Mật khẩu này quá phổ biến hoặc đã bị lộ trong các vụ rò rỉ dữ liệu. Vui lòng chọn mật khẩu khác an toàn hơn."
        }), 422

    USERS_DB[username] = ph.hash(apply_pepper(password))
    return jsonify({"message": "Đăng ký tài khoản thành công! Bạn có thể đăng nhập ngay."})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    client_ip = get_client_ip()

    if not username or not password:
        return jsonify({"error": "Vui lòng nhập tên đăng nhập và mật khẩu."}), 400

    retry_after = check_rate_limit(client_ip, username)
    if retry_after > 0:
        return jsonify({
            "error": f"Bạn đã nhập sai quá {MAX_FAILED_ATTEMPTS} lần trong 3 phút. Vui lòng thử lại sau {retry_after} giây.",
            "retry_after": retry_after
        }), 429

    matched_user = next((u for u in USERS_DB if u.lower() == username.lower()), None)

    if not matched_user:
        try:
            ph.verify(DUMMY_HASH, apply_pepper(password))
        except VerifyMismatchError:
            pass

        remaining, lock_sec = record_failed_attempt(client_ip, username)
        if lock_sec > 0:
            return jsonify({
                "error": f"Bạn đã nhập sai quá {MAX_FAILED_ATTEMPTS} lần trong 3 phút. Vui lòng thử lại sau {lock_sec} giây.",
                "retry_after": lock_sec
            }), 429

        return jsonify({
            "error": f"Tên đăng nhập hoặc mật khẩu không chính xác. (Còn {remaining} lần thử)"
        }), 401

    try:
        ph.verify(USERS_DB[matched_user], apply_pepper(password))
        clear_failed_attempts(client_ip, matched_user)
        return jsonify({
            "message": "Đăng nhập thành công!",
            "username": matched_user
        })
    except VerifyMismatchError:
        remaining, lock_sec = record_failed_attempt(client_ip, matched_user)
        if lock_sec > 0:
            return jsonify({
                "error": f"Bạn đã nhập sai quá {MAX_FAILED_ATTEMPTS} lần trong 3 phút. Vui lòng thử lại sau {lock_sec} giây.",
                "retry_after": lock_sec
            }), 429

        return jsonify({
            "error": f"Tên đăng nhập hoặc mật khẩu không chính xác. (Còn {remaining} lần thử)"
        }), 401


HTML_UI = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Đăng nhập hệ thống</title>
  <style>
    * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #1e293b;
      padding: 16px;
    }
    .auth-card {
      background: #ffffff;
      width: 100%;
      max-width: 400px;
      padding: 36px 32px;
      border-radius: 16px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.35);
    }
    .auth-header {
      text-align: center;
      margin-bottom: 28px;
    }
    .auth-header h1 {
      margin: 0 0 8px 0;
      font-size: 24px;
      font-weight: 700;
      color: #0f172a;
    }
    .auth-header p {
      margin: 0;
      font-size: 14px;
      color: #64748b;
    }
    .form-group {
      margin-bottom: 18px;
    }
    label {
      display: block;
      font-size: 13.5px;
      font-weight: 600;
      color: #334155;
      margin-bottom: 6px;
    }
    input {
      width: 100%;
      padding: 11px 14px;
      font-size: 14.5px;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input:focus {
      border-color: #2563eb;
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
    }
    .btn-primary {
      width: 100%;
      padding: 12px;
      font-size: 15px;
      font-weight: 600;
      color: #ffffff;
      background: #2563eb;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.2s;
      margin-top: 4px;
    }
    .btn-primary:hover {
      background: #1d4ed8;
    }
    .btn-primary:disabled {
      background: #94a3b8;
      cursor: not-allowed;
    }
    .switch-view {
      text-align: center;
      margin-top: 22px;
      padding-top: 18px;
      border-top: 1px solid #e2e8f0;
      font-size: 14px;
      color: #64748b;
    }
    .switch-view a {
      color: #2563eb;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      margin-left: 4px;
    }
    .switch-view a:hover {
      text-decoration: underline;
    }
    .alert {
      padding: 11px 14px;
      border-radius: 8px;
      font-size: 13.5px;
      margin-bottom: 18px;
      display: none;
      line-height: 1.4;
    }
    .alert-error {
      background: #fef2f2;
      color: #b91c1c;
      border: 1px solid #fecaca;
    }
    .alert-success {
      background: #f0fdf4;
      color: #15803d;
      border: 1px solid #bbf7d0;
    }
    .hidden {
      display: none;
    }
    .welcome-box {
      text-align: center;
      padding: 10px 0;
    }
    .avatar-circle {
      width: 64px;
      height: 64px;
      background: #dbeafe;
      color: #2563eb;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 26px;
      font-weight: 700;
      margin: 0 auto 16px auto;
    }
    .btn-outline {
      width: 100%;
      padding: 11px;
      font-size: 14.5px;
      font-weight: 600;
      color: #475569;
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      cursor: pointer;
      margin-top: 20px;
    }
    .btn-outline:hover {
      background: #f1f5f9;
    }
  </style>
</head>
<body>

  <div class="auth-card">
    <div id="alert-box" class="alert"></div>

    <div id="view-login">
      <div class="auth-header">
        <h1>Đăng nhập</h1>
        <p>Chào mừng bạn quay trở lại hệ thống</p>
      </div>

      <form onsubmit="handleLogin(event)">
        <div class="form-group">
          <label for="login-username">Tên đăng nhập</label>
          <input type="text" id="login-username" placeholder="Nhập tên đăng nhập" required autocomplete="username" />
        </div>
        <div class="form-group">
          <label for="login-password">Mật khẩu</label>
          <input type="password" id="login-password" placeholder="Nhập mật khẩu" required autocomplete="current-password" />
        </div>
        <button type="submit" id="btn-login" class="btn-primary">Đăng nhập</button>
      </form>

      <div class="switch-view">
        Chưa có tài khoản? <a onclick="switchTab('register')">Đăng ký tài khoản</a>
      </div>
    </div>

    <div id="view-register" class="hidden">
      <div class="auth-header">
        <h1>Tạo tài khoản mới</h1>
        <p>Điền thông tin bên dưới để đăng ký</p>
      </div>

      <form onsubmit="handleRegister(event)">
        <div class="form-group">
          <label for="reg-username">Tên đăng nhập</label>
          <input type="text" id="reg-username" placeholder="Tối thiểu 3 ký tự" required autocomplete="username" />
        </div>
        <div class="form-group">
          <label for="reg-password">Mật khẩu</label>
          <input type="password" id="reg-password" placeholder="Tối thiểu 8 ký tự" required autocomplete="new-password" />
        </div>
        <div class="form-group">
          <label for="reg-confirm">Xác nhận mật khẩu</label>
          <input type="password" id="reg-confirm" placeholder="Nhập lại mật khẩu" required autocomplete="new-password" />
        </div>
        <button type="submit" id="btn-register" class="btn-primary">Đăng ký</button>
      </form>

      <div class="switch-view">
        Đã có tài khoản? <a onclick="switchTab('login')">Đăng nhập ngay</a>
      </div>
    </div>

    <div id="view-dashboard" class="hidden">
      <div class="welcome-box">
        <div class="avatar-circle" id="user-avatar">U</div>
        <h2 style="margin:0 0 6px 0; color:#0f172a;">Xin chào, <span id="display-username"></span>!</h2>
        <p style="margin:0; font-size:14px; color:#64748b;">Bạn đã đăng nhập vào hệ thống thành công.</p>
        <button class="btn-outline" onclick="handleLogout()">Đăng xuất</button>
      </div>
    </div>
  </div>

<script>
  let lockTimer = null;

  function showAlert(message, type) {
    const box = document.getElementById("alert-box");
    box.textContent = message;
    box.className = "alert " + (type === "success" ? "alert-success" : "alert-error");
    box.style.display = "block";
  }

  function hideAlert() {
    document.getElementById("alert-box").style.display = "none";
  }

  function startLockoutCountdown(seconds) {
    const btn = document.getElementById("btn-login");
    if (lockTimer) clearInterval(lockTimer);

    let remaining = seconds;
    btn.disabled = true;

    const updateText = () => {
      const mins = Math.floor(remaining / 60);
      const secs = remaining % 60;
      const timeStr = mins > 0 ? `${mins} phút ${secs} giây` : `${secs} giây`;
      btn.textContent = `Tạm khóa (${timeStr})`;
      showAlert(`Bạn đã nhập sai quá 5 lần trong 3 phút. Vui lòng thử lại sau ${timeStr}.`, "error");
    };

    updateText();
    lockTimer = setInterval(() => {
      remaining--;
      if (remaining <= 0) {
        clearInterval(lockTimer);
        lockTimer = null;
        btn.disabled = false;
        btn.textContent = "Đăng nhập";
        hideAlert();
      } else {
        updateText();
      }
    }, 1000);
  }

  function switchTab(tab) {
    if (!lockTimer) hideAlert();
    document.getElementById("view-login").classList.toggle("hidden", tab !== "login");
    document.getElementById("view-register").classList.toggle("hidden", tab !== "register");
    document.getElementById("view-dashboard").classList.toggle("hidden", tab !== "dashboard");
  }

  async function handleLogin(e) {
    e.preventDefault();
    if (lockTimer) return;
    hideAlert();

    const btn = document.getElementById("btn-login");
    btn.disabled = true;
    btn.textContent = "Đang xử lý...";

    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;

    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();

      if (res.status === 429 && data.retry_after) {
        startLockoutCountdown(data.retry_after);
        return;
      }

      if (!res.ok) {
        showAlert(data.error || "Đăng nhập thất bại.", "error");
      } else {
        document.getElementById("display-username").textContent = data.username;
        document.getElementById("user-avatar").textContent = data.username.charAt(0).toUpperCase();
        document.getElementById("login-password").value = "";
        switchTab("dashboard");
      }
    } catch (err) {
      showAlert("Không thể kết nối đến máy chủ.", "error");
    } finally {
      if (!lockTimer) {
        btn.disabled = false;
        btn.textContent = "Đăng nhập";
      }
    }
  }

  async function handleRegister(e) {
    e.preventDefault();
    hideAlert();
    const btn = document.getElementById("btn-register");
    btn.disabled = true;
    btn.textContent = "Đang tạo tài khoản...";

    const username = document.getElementById("reg-username").value;
    const password = document.getElementById("reg-password").value;
    const confirm_password = document.getElementById("reg-confirm").value;

    try {
      const res = await fetch("/api/register", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ username, password, confirm_password })
      });
      const data = await res.json();

      if (!res.ok) {
        showAlert(data.error || "Đăng ký thất bại.", "error");
      } else {
        switchTab("login");
        document.getElementById("login-username").value = username;
        document.getElementById("reg-username").value = "";
        document.getElementById("reg-password").value = "";
        document.getElementById("reg-confirm").value = "";
        showAlert(data.message, "success");
      }
    } catch (err) {
      showAlert("Không thể kết nối đến máy chủ.", "error");
    } finally {
      btn.disabled = false;
      btn.textContent = "Đăng ký";
    }
  }

  function handleLogout() {
    switchTab("login");
  }
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_UI)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
