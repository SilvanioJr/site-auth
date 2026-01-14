from datetime import date, datetime, timedelta
import calendar
import os
import secrets

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort, g
)
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image


# =========================
# CONFIG
# =========================

MESES_PT = {
    1: "Janeiro", 2: "Fevereiro", 3: "Março", 4: "Abril",
    5: "Maio", 6: "Junho", 7: "Julho", 8: "Agosto",
    9: "Setembro", 10: "Outubro", 11: "Novembro", 12: "Dezembro"
}

app = Flask(__name__)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.permanent_session_lifetime = timedelta(minutes=45)

secret = os.environ.get("SECRET_KEY")
if not secret:
    raise RuntimeError("Defina a variável de ambiente SECRET_KEY")
app.secret_key = secret

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

UPLOAD_FOLDER = "static/uploads/users"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# =========================
# MODELS
# =========================

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    photo_path = db.Column(db.String(255))


class Escala(db.Model):
    __tablename__ = "escalas"

    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, nullable=False)
    tipo = db.Column(db.String(50))
    evento = db.Column(db.String(255))
    horario = db.Column(db.Time)


class UsuarioEscala(db.Model):
    __tablename__ = "usuario_escala"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    escala_id = db.Column(db.Integer, db.ForeignKey("escalas.id"))
    funcao = db.Column(db.String(100))

    user = db.relationship("User")
    escala = db.relationship("Escala")


# =========================
# LOGIN
# =========================

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# =========================
# HELPERS
# =========================

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def senha_forte(s):
    return len(s) >= 8 and any(c.isdigit() for c in s) and any(c.isalpha() for c in s)


# =========================
# SECURITY HEADERS
# =========================

@app.before_request
def gerar_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)

@app.after_request
def security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        f"script-src 'self' 'nonce-{g.csp_nonce}';"
    )
    return response


# =========================
# ROTAS
# =========================

@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
@limiter.limit("20 per minute", methods=["GET"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and check_password_hash(user.password_hash, request.form["password"]):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Usuário ou senha inválidos", "error")
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    hoje = datetime.today()
    mes = request.args.get("mes", hoje.month, type=int)
    ano = request.args.get("ano", hoje.year, type=int)

    registros = (
        Escala.query
        .filter(db.extract("month", Escala.data) == mes)
        .filter(db.extract("year", Escala.data) == ano)
        .order_by(Escala.data, Escala.horario)
        .all()
    )

    escalas = {}
    for e in registros:
        escalas.setdefault(e.data.day, []).append({
            "tipo": e.tipo,
            "evento": e.evento,
            "horario": e.horario.strftime("%H:%M") if e.horario else ""
        })

    return render_template(
        "dashboard.html",
        dias=range(1, calendar.monthrange(ano, mes)[1] + 1),
        nome_mes=MESES_PT[mes],
        usuario=current_user.username,
        escalas=escalas,
        mes=mes,
        ano=ano,
        mes_anterior=12 if mes == 1 else mes - 1,
        ano_anterior=ano - 1 if mes == 1 else ano,
        mes_proximo=1 if mes == 12 else mes + 1,
        ano_proximo=ano + 1 if mes == 12 else ano
    )


@app.route("/minhas-escalas")
@login_required
def minhas_escalas():
    hoje = datetime.today()
    mes = request.args.get("mes", hoje.month, type=int)
    ano = request.args.get("ano", hoje.year, type=int)

    registros = (
        UsuarioEscala.query
        .join(Escala)
        .filter(UsuarioEscala.user_id == current_user.id)
        .filter(db.extract("month", Escala.data) == mes)
        .filter(db.extract("year", Escala.data) == ano)
        .order_by(Escala.data, Escala.horario)
        .all()
    )

    return render_template("minhas_escalas.html", escalas=registros, nome_mes=MESES_PT[mes])


@app.route("/admin/escalas", methods=["GET", "POST"])
@login_required
def admin_escalas():
    if not current_user.is_admin:
        return redirect(url_for("dashboard"))

    if request.method == "POST" and request.form.get("acao") == "criar_escala":
        escala = Escala(
            data=datetime.strptime(request.form["data"], "%Y-%m-%d").date(),
            tipo=request.form["tipo"],
            evento=request.form["evento"],
            horario=datetime.strptime(request.form["horario"], "%H:%M").time()
        )
        db.session.add(escala)
        db.session.commit()
        flash("Escala criada", "success")

    escalas = Escala.query.order_by(Escala.data).all()
    usuarios = User.query.order_by(User.username).all()
    return render_template("admin_escalas.html", escalas=escalas, usuarios=usuarios)


@app.route("/admin/visao-escalas")
@login_required
def admin_visao_escalas():
    if not current_user.is_admin:
        return redirect(url_for("dashboard"))

    registros = UsuarioEscala.query.join(User).join(Escala).all()
    return render_template("admin_visao_escalas.html", registros=registros)


@app.route("/admin/remover-atribuicao", methods=["POST"])
@login_required
def remover_atribuicao():
    if not current_user.is_admin:
        abort(403)

    registro = UsuarioEscala.query.get(request.form["usuario_escala_id"])
    if registro:
        db.session.delete(registro)
        db.session.commit()
        flash("Atribuição removida", "success")
    return redirect(url_for("admin_visao_escalas"))


@app.route("/perfil", methods=["GET", "POST"])
@login_required
def perfil():
    if request.method == "POST":
        file = request.files.get("photo")
        if not file or not allowed_file(file.filename):
            flash("Arquivo inválido", "error")
            return redirect(url_for("perfil"))

        filename = f"user_{current_user.id}.jpg"
        path = os.path.join(UPLOAD_FOLDER, filename)
        img = Image.open(file).convert("RGB")
        img.thumbnail((500, 500))
        img.save(path, "JPEG")

        current_user.photo_path = f"/static/uploads/users/{filename}"
        db.session.commit()
        flash("Foto atualizada", "success")

    return render_template("perfil.html")


@app.route("/admin/usuarios", methods=["GET", "POST"])
@login_required
def admin_usuarios():
    if not current_user.is_super_admin:
        abort(403)

    if request.method == "POST":
        acao = request.form["acao"]

        if acao == "criar":
            if not senha_forte(request.form["password"]):
                flash("Senha fraca", "error")
            else:
                user = User(
                    username=request.form["username"],
                    password_hash=generate_password_hash(request.form["password"]),
                    is_admin=request.form["role"] == "admin"
                )
                db.session.add(user)
                db.session.commit()
                flash("Usuário criado", "success")

        elif acao == "trocar_senha":
            user = User.query.get(request.form["user_id"])
            user.password_hash = generate_password_hash(request.form["nova_senha"])
            db.session.commit()
            flash("Senha alterada", "success")

        elif acao == "excluir_usuario":
            user = User.query.get(request.form["user_id"])
            if user.id != current_user.id and not user.is_super_admin:
                db.session.delete(user)
                db.session.commit()
                flash("Usuário excluído", "success")

    usuarios = User.query.all()
    return render_template("admin_usuarios.html", usuarios=usuarios)


@app.route("/trocar-senha", methods=["GET", "POST"])
@login_required
def trocar_senha():
    if request.method == "POST":
        if not check_password_hash(current_user.password_hash, request.form["senha_atual"]):
            flash("Senha atual incorreta", "error")
            return redirect(url_for("trocar_senha"))

        if not senha_forte(request.form["nova_senha"]):
            flash("Senha fraca", "error")
            return redirect(url_for("trocar_senha"))

        current_user.password_hash = generate_password_hash(request.form["nova_senha"])
        db.session.commit()
        flash("Senha alterada", "success")
        return redirect(url_for("dashboard"))

    return render_template("trocar_senha.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# =========================
# INIT
# =========================

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=False)
