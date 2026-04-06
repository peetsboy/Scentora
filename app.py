import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)

print("Database location:", os.path.abspath("inventory.db"))
app = Flask(__name__)
UPLOAD_FOLDER = os.path.join("static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SECRET_KEY"] = "change-this-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///inventory.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---- CONFIG ----
load_dotenv()
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")


# ---- LOGIN MANAGER (CUSTOMERS) ----
login_manager = LoginManager(app)
login_manager.login_view = "client_login"


# ---- MODELS ----
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(30), unique=True, nullable=False, index=True)
    email = db.Column(db.String(50), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, index=True)
    category = db.Column(db.String(80), nullable=False, index=True)
    price = db.Column(db.Float, nullable=True)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    description = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(300), nullable=True)

    def status(self):
        if self.quantity <= 0:
            return "out"
        if self.quantity <= 5:
            return "low"
        return "in"


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Link each order to a customer account
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    customer_name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(40), nullable=False)
    address = db.Column(db.Text, nullable=False)

    status = db.Column(db.String(30), nullable=False, default="pending")  # pending/processing/delivered/canceled
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())

    items = db.relationship("OrderItem", backref="order", cascade="all, delete-orphan")


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)

    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    product_name = db.Column(db.String(120), nullable=False)
    unit_price = db.Column(db.Float, nullable=True)

    quantity = db.Column(db.Integer, nullable=False, default=1)


# ---- INIT DB (run once) ----
@app.before_request
def create_tables_once():
    if not getattr(app, "_tables_created", False):
        db.create_all()
        app._tables_created = True


# ---- PUBLIC ROUTES ----
@app.route("/")
def index():
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    show = (request.args.get("show") or "all").strip()

    query = Product.query

    if q:
        like = f"%{q}%"
        query = query.filter(or_(Product.name.ilike(like), Product.category.ilike(like)))

    if category:
        query = query.filter(Product.category == category)

    if show == "in":
        query = query.filter(Product.quantity > 5)
    elif show == "low":
        query = query.filter(Product.quantity.between(1, 5))
    elif show == "out":
        query = query.filter(Product.quantity <= 0)

    products = query.order_by(Product.category.asc(), Product.name.asc()).all()
    categories = [c[0] for c in db.session.query(Product.category).distinct().order_by(Product.category).all()]

    return render_template("index.html", products=products, categories=categories, q=q, category=category, show=show)


@app.route("/product/<int:product_id>")
def product_page(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template("product.html", product=product)


@app.route("/admin/orders/<int:order_id>/print")
def admin_print_order(order_id):
    if not is_admin():
        return redirect(url_for("admin_login"))

    order = Order.query.get_or_404(order_id)
    return render_template("admin_print_order.html", order=order)


# ---- CUSTOMER AUTH ----
@app.route("/register", methods=["GET", "POST"])
def client_register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    error = None

    if request.method == "POST":
        phone = request.form.get("phone")
        email = (request.form.get("email") or "").strip() or None
        password = request.form.get("password")

        if User.query.filter_by(phone=phone).first():
            error = "Phone already exists"

        elif email and User.query.filter_by(email=email).first():
            error = "Email already exists"

        else:
            user = User(phone=phone, email=email)
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            login_user(user)
            return redirect(url_for("account_orders"))

    return render_template("client_register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def client_login():
    if current_user.is_authenticated:
        return redirect(url_for("account_orders"))

    error = None
    if request.method == "POST":
        phone = (request.form.get("phone") or "").strip()
        password = (request.form.get("password") or "").strip()

        user = User.query.filter((User.phone == phone) | (User.email == phone)).first()
        if not user or not user.check_password(password):
            error = "Wrong phone or password."
        else:
            login_user(user)
            return redirect(url_for("account_orders"))

    return render_template("client_login.html", error=error)


@app.route("/logout")
@login_required
def client_logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/account/orders")
@login_required
def account_orders():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template("account_orders.html", orders=orders)


# ---- CHECKOUT (COD) ----
@app.route("/checkout/<int:product_id>", methods=["GET", "POST"])
@login_required
def checkout(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == "POST":
        customer_name = (request.form.get("customer_name") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        address = (request.form.get("address") or "").strip()

        try:
            qty = int(request.form.get("qty") or 1)
        except ValueError:
            qty = 1
        qty = max(1, qty)

        if not customer_name or not phone or not address:
            return render_template("checkout.html", product=product, error="Please fill all fields.")

        if product.quantity < qty:
            return render_template(
                "checkout.html",
                product=product,
                error=f"Not enough stock. Available: {product.quantity}",
            )

        order = Order(
            user_id=current_user.id,
            customer_name=customer_name,
            phone=phone,
            address=address,
            status="pending",
        )

        item = OrderItem(
            product_id=product.id,
            product_name=product.name,
            unit_price=product.price,
            quantity=qty,
        )
        order.items.append(item)

        # Reserve stock immediately
        product.quantity -= qty

        db.session.add(order)
        db.session.commit()

        return render_template("order_success.html", order=order, product=product)

    return render_template("checkout.html", product=product, error=None)


# ---- ADMIN AUTH ----
def is_admin():
    return session.get("is_admin") is True


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password") or ""
        if password == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        return render_template("admin_login.html", error="Wrong password.")
    return render_template("admin_login.html", error=None)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("index"))


# ---- ADMIN CRUD ----
@app.route("/admin")
def admin_dashboard():
    if not is_admin():
        return redirect(url_for("admin_login"))
    users = User.query.order_by(User.created_at.desc()).all()
    products = Product.query.order_by(Product.category.asc(), Product.name.asc()).all()
    return render_template("admin_dashboard.html", products=products, users=users)


@app.route("/admin/add", methods=["POST"])
def admin_add():
    if not is_admin():
        abort(403)

    name = (request.form.get("name") or "").strip()
    category = (request.form.get("category") or "General").strip()
    description = (request.form.get("description") or "").strip()
    image_file = request.files.get("image")

    filename = None
    if image_file and image_file.filename != "":
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        image_file.save(image_path)

    try:
        price = float(request.form.get("price") or 0)
    except ValueError:
        price = 0

    try:
        quantity = int(request.form.get("quantity") or 0)
    except ValueError:
        quantity = 0

    if not name:
        return redirect(url_for("admin_dashboard"))

    p = Product(
        name=name,
        category=category,
        price=price if price > 0 else None,
        quantity=max(0, quantity),
        description=description if description else None,
        image_filename=filename,
    )
    db.session.add(p)
    db.session.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/edit/<int:product_id>", methods=["GET", "POST"])
def admin_edit(product_id):
    if not is_admin():
        return redirect(url_for("admin_login"))

    product = Product.query.get_or_404(product_id)

    if request.method == "POST":
        product.name = (request.form.get("name") or "").strip()
        product.category = (request.form.get("category") or "General").strip()
        product.description = (request.form.get("description") or "").strip() or None

        # BUG FIX: removed product.image_url (field does not exist)

        try:
            product.price = float(request.form.get("price") or 0) or None
        except ValueError:
            product.price = None

        try:
            product.quantity = max(0, int(request.form.get("quantity") or 0))
        except ValueError:
            product.quantity = 0

        image_file = request.files.get("image")
        if image_file and image_file.filename != "":
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image_file.save(image_path)
            product.image_filename = filename

        db.session.commit()
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_edit.html", product=product)


@app.route("/admin/delete/<int:product_id>", methods=["POST"])
def admin_delete(product_id):
    if not is_admin():
        abort(403)

    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for("admin_dashboard"))


# ---- ADMIN ORDERS ----
@app.route("/admin/orders")
def admin_orders():
    if not is_admin():
        return redirect(url_for("admin_login"))

    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin_orders.html", orders=orders)


@app.route("/admin/orders/<int:order_id>/status", methods=["POST"])
def admin_update_order_status(order_id):
    if not is_admin():
        abort(403)

    order = Order.query.get_or_404(order_id)
    new_status = (request.form.get("status") or "").strip()

    allowed = {"pending", "processing", "delivered", "canceled"}
    if new_status in allowed:
        order.status = new_status
        db.session.commit()

    return redirect(url_for("admin_orders"))


if __name__ == "__main__":
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))