from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, session, abort
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, HiddenField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
from contextlib import closing
from functools import wraps

# ===================== App & Config =====================
app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-change-me"  # Đổi khi deploy
# Một số bảo vệ session cơ bản
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# ===================== MySQL (XAMPP) =====================
DB_CONFIG = dict(
    host="localhost",
    user="root",          # mặc định XAMPP
    password="",          # nếu MySQL có mật khẩu thì sửa tại đây
    database="user_manager",
    auth_plugin="mysql_native_password",  # nếu lỗi auth có thể bỏ dòng này
)

def get_conn():
    """Mở connection tới MySQL theo DB_CONFIG."""
    return mysql.connector.connect(**DB_CONFIG)

# ===================== WTForms =====================
class RegisterForm(FlaskForm):
    fullname = StringField("Họ và tên", validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=100)])
    password = PasswordField("Mật khẩu", validators=[DataRequired(), Length(min=6, max=64)])
    confirm  = PasswordField(
        "Nhập lại mật khẩu",
        validators=[DataRequired(), EqualTo("password", "Mật khẩu không khớp")]
    )
    submit = SubmitField("Tạo tài khoản")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=100)])
    password = PasswordField("Mật khẩu", validators=[DataRequired(), Length(min=6, max=64)])
    submit = SubmitField("Đăng nhập")

# --- Form quản trị ---
class AdminEditUserForm(FlaskForm):
    fullname = StringField("Họ và tên", validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=100)])
    role = SelectField("Quyền", choices=[("user","user"),("staff","staff"),("admin","admin")], validators=[DataRequired()])
    submit = SubmitField("Lưu thay đổi")

class AdminDeleteForm(FlaskForm):
    uid = HiddenField(validators=[DataRequired()])
    submit = SubmitField("Xoá")

# ===================== Helpers & Decorators =====================
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            flash("Vui lòng đăng nhập.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper

def roles_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            u = session.get("user")
            if not u:
                flash("Vui lòng đăng nhập.", "warning")
                return redirect(url_for("login"))
            if u.get("role") not in allowed_roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator

@app.context_processor
def inject_user():
    """Đưa current_user & helper vào template."""
    u = session.get("user")
    return dict(current_user=u, is_logged_in=bool(u))

# ===================== Routes cơ bản =====================
@app.route("/")
def home():
    u = session.get("user")
    if not u:
        return redirect(url_for("login"))
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        fullname = form.fullname.data.strip()
        email = form.email.data.strip().lower()
        password_hash = generate_password_hash(form.password.data)

        try:
            with closing(get_conn()) as conn:
                conn.set_charset_collation('utf8mb4', 'utf8mb4_unicode_ci')
                with closing(conn.cursor(dictionary=True)) as cur:
                    # Kiểm tra trùng email
                    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
                    if cur.fetchone():
                        flash("Email đã tồn tại. Vui lòng dùng email khác.", "danger")
                        return redirect(url_for("register"))
                    # Thêm mới (role mặc định: user)
                    cur.execute(
                        "INSERT INTO users(fullname, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                        (fullname, email, password_hash, "user")
                    )
                    conn.commit()
            flash(f"Đăng ký thành công! Chào {fullname} 👋", "success")
            return redirect(url_for("login"))
        except Error:
            flash("Không kết nối được MySQL hoặc lỗi truy vấn. Kiểm tra XAMPP và cấu hình DB.", "danger")

    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data
        try:
            with closing(get_conn()) as conn:
                with closing(conn.cursor(dictionary=True)) as cur:
                    cur.execute(
                        "SELECT id, fullname, email, password_hash, role FROM users WHERE email=%s",
                        (email,)
                    )
                    user = cur.fetchone()
                    if not user or not check_password_hash(user["password_hash"], password):
                        flash("Email hoặc mật khẩu không đúng.", "danger")
                        return redirect(url_for("login"))

                    # Lưu session
                    session["user"] = {
                        "id": user["id"],
                        "fullname": user["fullname"],
                        "email": user["email"],
                        "role": user["role"]
                    }

                    # Điều hướng theo role
                    if user["role"] == "admin":
                        return redirect(url_for("admin_dashboard"))
                    elif user["role"] == "staff":
                        return redirect(url_for("staff_area"))
                    else:
                        return redirect(url_for("profile"))

        except Error:
            flash("Lỗi kết nối MySQL.", "danger")

    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Bạn đã đăng xuất.", "info")
    return redirect(url_for("login"))

# ===================== Khu vực có phân quyền =====================
@app.route("/profile")
@login_required
def profile():
    return render_template("base.html", title=f"Hồ sơ - {session['user']['fullname']}")

@app.route("/staff-area")
@roles_required("admin", "staff")
def staff_area():
    return render_template("base.html", title="Khu vực nhân viên (Admin/Staff)")

@app.route("/admin")
@roles_required("admin")
def admin_dashboard():
    # Trang tổng quan admin, có link sang quản lý người dùng
    return render_template("base.html", title="Trang quản trị (Admin only)")

# ===================== Admin: quản lý người dùng =====================
@app.route("/admin/users")
@roles_required("admin")
def admin_users():
    q = request.args.get("q", "").strip()
    sql = "SELECT id, fullname, email, role, created_at FROM users"
    params = []
    if q:
        sql += " WHERE fullname LIKE %s OR email LIKE %s"
        like = f"%{q}%"
        params = [like, like]
    sql += " ORDER BY id DESC LIMIT 500"

    with closing(get_conn()) as conn, closing(conn.cursor(dictionary=True)) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    del_form = AdminDeleteForm()  # để render CSRF trong từng row
    return render_template("admin_users.html", rows=rows, q=q, del_form=del_form)

@app.route("/admin/users/<int:uid>")
@roles_required("admin")
def admin_user_view(uid):
    with closing(get_conn()) as conn, closing(conn.cursor(dictionary=True)) as cur:
        cur.execute("SELECT id, fullname, email, role, created_at FROM users WHERE id=%s", (uid,))
        u = cur.fetchone()
    if not u:
        flash("Người dùng không tồn tại.", "warning")
        return redirect(url_for("admin_users"))
    return render_template("admin_user_view.html", u=u)

@app.route("/admin/users/<int:uid>/edit", methods=["GET", "POST"])
@roles_required("admin")
def admin_user_edit(uid):
    with closing(get_conn()) as conn, closing(conn.cursor(dictionary=True)) as cur:
        cur.execute("SELECT id, fullname, email, role FROM users WHERE id=%s", (uid,))
        u = cur.fetchone()
        if not u:
            flash("Người dùng không tồn tại.", "warning")
            return redirect(url_for("admin_users"))

    form = AdminEditUserForm(data=u)
    if form.validate_on_submit():
        fullname = form.fullname.data.strip()
        email = form.email.data.strip().lower()
        role = form.role.data

        with closing(get_conn()) as conn, closing(conn.cursor(dictionary=True)) as cur:
            # Email trùng với tài khoản khác?
            cur.execute("SELECT id FROM users WHERE email=%s AND id<>%s", (email, uid))
            if cur.fetchone():
                flash("Email đã thuộc về tài khoản khác.", "danger")
                return redirect(url_for("admin_user_edit", uid=uid))

            cur.execute(
                "UPDATE users SET fullname=%s, email=%s, role=%s WHERE id=%s",
                (fullname, email, role, uid)
            )
            conn.commit()

        flash("Cập nhật người dùng thành công.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin_user_edit.html", form=form, uid=uid)

@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@roles_required("admin")
def admin_user_delete(uid):
    form = AdminDeleteForm()
    if not form.validate_on_submit() or int(form.uid.data) != uid:
        flash("Yêu cầu không hợp lệ.", "danger")
        return redirect(url_for("admin_users"))

    # Chặn tự xoá chính mình
    if session["user"]["id"] == uid:
        flash("Không thể tự xoá tài khoản đang đăng nhập.", "warning")
        return redirect(url_for("admin_users"))

    with closing(get_conn()) as conn, closing(conn.cursor()) as cur:
        cur.execute("DELETE FROM users WHERE id=%s", (uid,))
        conn.commit()

    flash("Đã xoá người dùng.", "success")
    return redirect(url_for("admin_users"))

# ===================== Error handlers =====================
@app.errorhandler(403)
def forbidden(_):
    flash("Bạn không có quyền truy cập.", "danger")
    return redirect(url_for("home"))

@app.errorhandler(404)
def not_found(_):
    flash("Không tìm thấy trang bạn yêu cầu.", "warning")
    return redirect(url_for("home"))

# ===================== Main =====================
if __name__ == "__main__":
    # Nhớ Start Apache + MySQL trong XAMPP trước khi chạy
    app.run(debug=True)
