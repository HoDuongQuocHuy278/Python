from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, session, abort, send_from_directory
)
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired

from wtforms import (
    StringField, PasswordField, SubmitField, SelectField, HiddenField,
    DecimalField, TextAreaField
)
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo, NumberRange, Optional
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import os, time
from decimal import Decimal
from pathlib import Path

import mysql.connector
from mysql.connector import Error
from contextlib import closing
from functools import wraps
# ===================== App & Config =====================
app = Flask(__name__)

from pathlib import Path
from tempfile import gettempdir


def ensure_media_root():
    candidates = [
        Path(app.instance_path) / "uploads",
        Path(app.root_path) / "media",
        Path(gettempdir()) / "traodoi_uploads",
    ]
    for p in candidates:
        try:
            p.mkdir(parents=True, exist_ok=True)
            t = p / ".write_test"
            t.write_bytes(b"ok")
            t.unlink(missing_ok=True)
            app.config["MEDIA_ROOT"] = str(p)
            print("MEDIA_ROOT =>", app.config["MEDIA_ROOT"])
            return p
        except Exception as e:
            print("MEDIA candidate failed:", p, "=>", e)
    raise RuntimeError("No writable MEDIA_ROOT found")

MEDIA_DIR = ensure_media_root()
ALLOWED_EXTS = ["jpg","jpeg","png","webp"]
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB

MEDIA_DIR = ensure_media_root()

def _save_image(file_storage):
    """
    Lưu file vào MEDIA_ROOT và trả về CHỈ tên file (vd: '5_1726722333.jpg').
    Trả None nếu không có file hoặc định dạng không hợp lệ.
    """
    if not file_storage or not getattr(file_storage, "filename", ""):
        return None

    filename = secure_filename(file_storage.filename)
    if "." not in filename:
        flash("File ảnh không hợp lệ.", "warning")
        return None

    ext = filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTS:
        flash("Định dạng ảnh không hỗ trợ. Chỉ jpg, jpeg, png, webp.", "warning")
        return None

    root = Path(app.config["MEDIA_ROOT"])
    try:
        root.mkdir(parents=True, exist_ok=True)
    except Exception:
        # fallback lại nếu thư mục bị xóa khi đang chạy
        root = ensure_media_root()

    new_name = f"{session['user']['id']}_{int(time.time())}.{ext}"
    target = root / new_name
    target.parent.mkdir(parents=True, exist_ok=True)

    try:
        try: file_storage.stream.seek(0, os.SEEK_SET)
        except Exception: pass
        print("Saving to:", target, "| parent exists?", target.parent.exists())
        with open(target, "wb") as f:
            f.write(file_storage.read())
    except Exception as e:
        print("SAVE ERROR:", e)
        flash("Không thể lưu ảnh lên máy chủ.", "danger")
        return None

    return new_name

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

CATEGORIES = [
    ("Sách","Sách"), ("Thời trang nữ","Thời trang nữ"), ("Thời trang nam","Thời trang nam"),
    ("Mẹ & bé","Mẹ & bé"), ("Đồ chơi","Đồ chơi"), ("Xe cộ","Xe cộ"),
    ("Đồ gia dụng","Đồ gia dụng"), ("Giày dép","Giày dép"),
    ("Đồ điện tử","Đồ điện tử"), ("Thú cưng","Thú cưng"),
]
CONDITIONS = [
    ("new","Mới 100%"),
    ("like_new","Như mới"),
    ("used","Đã qua sử dụng"),
    ("for_parts","Hỏng/để lấy linh kiện"),
]
# Nếu chưa có biến ALLOWED_EXTS ở phần cấu hình upload, thêm:
class RegisterForm(FlaskForm):
    fullname = StringField("Họ và tên", validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=100)])
    password = PasswordField("Mật khẩu", validators=[DataRequired(), Length(min=6, max=64)])
    confirm  = PasswordField(
        "Nhập lại mật khẩu",
        validators=[DataRequired(), EqualTo("password", "Mật khẩu không khớp")]
    )
    submit = SubmitField("Tạo tài khoản")

class SellForm(FlaskForm):
    title = StringField("Tiêu đề", validators=[DataRequired(), Length(min=5, max=120)])
    description = TextAreaField("Mô tả chi tiết", validators=[DataRequired(), Length(min=10, max=5000)])
    price = DecimalField("Giá (VND)", places=0, rounding=None,
                         validators=[DataRequired(), NumberRange(min=0)])
    category = SelectField("Danh mục", choices=CATEGORIES, validators=[DataRequired()])
    condition_level = SelectField("Tình trạng", choices=CONDITIONS, validators=[DataRequired()])
    location = StringField("Khu vực", validators=[Optional(), Length(max=100)])
    image = FileField("Ảnh bìa (jpg/png/webp)",
                      validators=[Optional(), FileAllowed(ALLOWED_EXTS, "Định dạng ảnh không hợp lệ")])
    submit = SubmitField("Đăng bán")

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
    
    u = session.get("user")
    def media_url(name):
        import os
        if not name: return None
        return url_for("uploaded_file", filename=os.path.basename(name))
    return dict(current_user=u, is_logged_in=bool(u), media_url=media_url)



# ===================== Routes cơ bản =====================
@app.route("/")
def home():
    u = session.get("user")
    if not u:
        # khách chưa đăng nhập vẫn xem marketplace
        return render_template("home.html", title="Trao đổi đồ cũ")
    return render_template("home.html", title="Trao đổi đồ cũ")


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

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["MEDIA_ROOT"], filename, as_attachment=False)
# ===================== Error handlers =====================
@app.errorhandler(403)
def forbidden(_):
    flash("Bạn không có quyền truy cập.", "danger")
    return redirect(url_for("home"))

@app.errorhandler(404)
def not_found(_):
    flash("Không tìm thấy trang bạn yêu cầu.", "warning")
    return redirect(url_for("home"))
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """
    Trang đăng bán sản phẩm:
    - Validate form
    - Lưu ảnh về instance/uploads (trả về tên file)
    - Ghi DB
    """
    form = SellForm()

    if form.validate_on_submit():
        # Lấy dữ liệu form
        title = form.title.data.strip()
        description = form.description.data.strip()

        # Ép giá về Decimal (nhận cả '3,500,000')
        from decimal import Decimal, InvalidOperation
        try:
            price = (
                Decimal(form.price.data)
                if isinstance(form.price.data, (int, float, Decimal))
                else Decimal(str(form.price.data).replace(",", "").strip())
            )
        except (InvalidOperation, ValueError):
            flash("Giá không hợp lệ.", "warning")
            return render_template("sell.html", form=form)

        category = form.category.data
        condition_level = form.condition_level.data
        location = (form.location.data or "").strip() or None

        # LƯU ẢNH BÌA — chỉ gọi MỘT lần
        cover_path = _save_image(form.image.data)
        print("MEDIA_ROOT =", app.config["MEDIA_ROOT"])
        print("filename  ->", getattr(form.image.data, "filename", None))
        print("saved as  ->", cover_path)

        # Debug kiểm tra nhanh
        print("MEDIA_ROOT =", app.config["MEDIA_ROOT"])
        print("filename  ->", getattr(form.image.data, "filename", None))
        print("saved as  ->", cover_path)

        # Ghi DB
        try:
            with closing(get_conn()) as conn:
                try:
                    conn.set_charset_collation('utf8mb4', 'utf8mb4_unicode_ci')
                except Exception:
                    pass
                with closing(conn.cursor()) as cur:
                    cur.execute(
                        """
                        INSERT INTO listings
                          (user_id, title, description, price, category, condition_level, location, cover_image, status)
                        VALUES
                          (%s, %s, %s, %s, %s, %s, %s, %s, 'active')
                        """,
                        (
                            session["user"]["id"],
                            title,
                            description,
                            str(price),
                            category,
                            condition_level,
                            location,
                            cover_path,  # tên file (có thể None nếu không chọn ảnh)
                        ),
                    )
                    conn.commit()
            flash("Đăng bán thành công!", "success")
            return redirect(url_for("my_listings"))

        except Error as e:
            print("MySQL error at /sell:", e)
            flash("Không thể lưu tin đăng. Vui lòng kiểm tra kết nối MySQL.", "danger")

    elif request.method == "POST":
        # POST nhưng form không hợp lệ
        flash("Vui lòng kiểm tra lại các trường còn thiếu/không hợp lệ.", "warning")

    # GET hoặc lỗi -> render lại form
    return render_template("sell.html", form=form)
@app.route("/my/listings")
@login_required
def my_listings():
    """Danh sách tin đăng của chính người dùng hiện tại."""
    with closing(get_conn()) as conn, closing(conn.cursor(dictionary=True)) as cur:
        cur.execute("""
            SELECT id, title, price, status, created_at, cover_image
            FROM listings
            WHERE user_id = %s
            ORDER BY id DESC
        """, (session["user"]["id"],))
        rows = cur.fetchall()
    return render_template("my_listings.html", rows=rows)


@app.route("/listing/<int:lid>")
def listing_detail(lid):
    """Trang chi tiết 1 tin đăng (ai cũng xem được trừ khi tin bị ẩn)."""
    with closing(get_conn()) as conn, closing(conn.cursor(dictionary=True)) as cur:
        cur.execute("""
            SELECT l.id, l.title, l.description, l.price, l.category, l.condition_level, l.location,
                   l.cover_image, l.status, l.created_at,
                   u.fullname AS seller_name, u.email AS seller_email
            FROM listings l
            JOIN users u ON u.id = l.user_id
            WHERE l.id = %s AND l.status <> 'hidden'
        """, (lid,))
        item = cur.fetchone()
    if not item:
        flash("Tin đăng không tồn tại hoặc đã ẩn.", "warning")
        return redirect(url_for("home"))
    return render_template("listing_detail.html", item=item)
# ===================== Main =====================
if __name__ == "__main__":
    # Nhớ Start Apache + MySQL trong XAMPP trước khi chạy
    app.run(debug=True)
