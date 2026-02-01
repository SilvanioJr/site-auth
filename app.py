from datetime import date, datetime, timedelta
import calendar
import os
import secrets
import os
from supabase import create_client
from io import BytesIO
from PIL import Image

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
from sqlalchemy import extract
from sqlalchemy import select, extract, case




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

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


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
        "img-src 'self' https: data:; "
        "style-src 'self' 'unsafe-inline'; "
        f"script-src 'self' 'nonce-{g.csp_nonce}';"
    )
    return response


# =========================
# ROTAS
# =========================

@app.route("/", methods=["GET", "POST"])
@limiter.limit(
    "6 per minute",
    methods=["POST"],
    error_message="Muitas tentativas de login. Aguarde cerca de 1 minuto e tente novamente."
)
@limiter.limit("20 per minute", methods=["GET"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Busca o usuário pelo username (equivalente ao SELECT do SQL Server)
        user = User.query.filter_by(username=username).first()

        # Validação exatamente igual à anterior
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Usuário ou senha inválidos", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    hoje = datetime.today()

    mes = request.args.get("mes", type=int)
    ano = request.args.get("ano", type=int)

    if not mes or not ano:
        mes = hoje.month
        ano = hoje.year

    nome_mes = MESES_PT[mes]
    total_dias = calendar.monthrange(ano, mes)[1]
    dias = list(range(1, total_dias + 1))

    # Buscar escalas do mês (equivalente ao SELECT com MONTH / YEAR)
    registros = (
        Escala.query
        .filter(
            extract("month", Escala.data) == mes,
            extract("year", Escala.data) == ano
        )
        .order_by(Escala.data, Escala.horario)
        .all()
    )

    escalas = {}

    for row in registros:
        dia = row.data.day

        if dia not in escalas:
            escalas[dia] = []

        escalas[dia].append({
            "tipo": row.tipo,
            "evento": row.evento,
            "horario": row.horario.strftime("%H:%M") if row.horario else None
        })

    # mês anterior
    mes_anterior = mes - 1
    ano_anterior = ano
    if mes_anterior == 0:
        mes_anterior = 12
        ano_anterior -= 1

    # próximo mês
    mes_proximo = mes + 1
    ano_proximo = ano
    if mes_proximo == 13:
        mes_proximo = 1
        ano_proximo += 1

    return render_template(
        "dashboard.html",
        dias=dias,
        nome_mes=nome_mes,
        usuario=current_user.username,
        escalas=escalas,
        mes=mes,
        ano=ano,
        mes_anterior=mes_anterior,
        ano_anterior=ano_anterior,
        mes_proximo=mes_proximo,
        ano_proximo=ano_proximo
    )


@app.route("/minhas_escalas")
@login_required
def minhas_escalas():
    hoje = datetime.today()

    mes = request.args.get("mes", type=int)
    ano = request.args.get("ano", type=int)

    if not mes or not ano:
        mes = hoje.month
        ano = hoje.year

    nome_mes = MESES_PT[mes]

    stmt = (
        select(
            extract("day", Escala.data).label("Dia"),
            UsuarioEscala.funcao.label("Funcao"),
           case(
                (Escala.horario.is_(None), None),
                else_=Escala.horario
            ).label("Horario"),
            Escala.evento.label("Evento")
        )
        .join(Escala, UsuarioEscala.escala_id == Escala.id)
        .where(
            UsuarioEscala.user_id == current_user.id,
            extract("month", Escala.data) == mes,
            extract("year", Escala.data) == ano
        )
        .order_by(Escala.data, Escala.horario)
    )

    result = db.session.execute(stmt).all()

    # Ajuste final do Horario para string HH:MM (igual ao CONVERT do SQL Server)
    escalas = []
    for row in result:
        escalas.append({
            "Dia": row.Dia,
            "Funcao": row.Funcao,
            "Horario": row.Horario.strftime("%H:%M") if row.Horario else "",
            "Evento": row.Evento
            })

    return render_template(
        "minhas_escalas.html",
        escalas=escalas,
        nome_mes=nome_mes
    )


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))



@app.route("/admin_escalas", methods=["GET", "POST"])
@login_required
def admin_escalas():

    if not current_user.is_admin:
        return redirect(url_for("dashboard"))

    # 🔹 Cadastro de nova escala
    if request.method == "POST" and request.form.get("acao") == "criar_escala":
        data = request.form["data"]
        evento = request.form["evento"]
        horario = request.form["horario"]
        tipo = request.form["tipo"]

        nova_escala = Escala(
            data=data,
            tipo=tipo,
            evento=evento,
            horario=horario if horario else None
        )

        db.session.add(nova_escala)
        db.session.commit()

        flash("Escala criada com sucesso!", "success")

    # 🔹 Atribuir usuário à escala
    if request.method == "POST" and request.form.get("acao") == "atribuir_usuario":
        escala_id = request.form["escala_id"]
        user_id = request.form["user_id"]
        funcao = request.form["funcao"]

        vinculo = UsuarioEscala(
            user_id=user_id,
            escala_id=escala_id,
            funcao=funcao
        )

        db.session.add(vinculo)
        db.session.commit()

        flash("Usuário atribuído à escala com sucesso!", "success")

    # 🔹 Buscar escalas do mês atual
    hoje = date.today()
    mes_atual = hoje.month
    ano_atual = hoje.year

    escalas = (
        Escala.query
        .filter(
            extract("month", Escala.data) == mes_atual,
            extract("year", Escala.data) == ano_atual
        )
        .order_by(Escala.data)
        .all()
    )

    # 🔹 Lista para excluir (últimas 30 escalas)
    escalas_lista = (
        Escala.query
        .order_by(Escala.data.desc(), Escala.horario.desc())
        .limit(30)
        .all()
    )


    # 🔹 Buscar usuários
    usuarios = (
        User.query
        .order_by(User.username)
        .all()
    )

    return render_template(
        "admin_escalas.html",
        escalas=escalas,
        usuarios=usuarios,
        escalas_lista=escalas_lista
    )



# @app.route("/admin_escalas/excluir/<int:escala_id>", methods=["POST"])
# @login_required
# def excluir_escala(escala_id):

#     # Segurança: só admin e super admin
#     if not (current_user.is_admin or current_user.is_super_admin):
#         flash("Acesso negado.", "error")
#         return redirect(url_for("dashboard"))

#     escala = Escala.query.get_or_404(escala_id)

#     try:
#         # Remove vínculos dessa escala
#         UsuarioEscala.query.filter_by(escala_id=escala.id).delete()

#         # Remove a escala
#         db.session.delete(escala)
#         db.session.commit()

#         flash("Escala excluída com sucesso!", "success")

#     except Exception as e:
#         db.session.rollback()
#         flash("Erro ao excluir escala.", "error")
#         print(e)

#     return redirect(url_for("admin_escalas"))


@app.route("/admin_escalas/excluir", methods=["POST"])
@login_required
def excluir_escala_post():
    if not (current_user.is_admin or current_user.is_super_admin):
        flash("Acesso negado.", "error")
        return redirect(url_for("dashboard"))

    escala_id = request.form.get("escala_id", type=int)
    if not escala_id:
        flash("Selecione uma escala.", "error")
        return redirect(url_for("admin_escalas"))

    escala = Escala.query.get_or_404(escala_id)

    try:
        UsuarioEscala.query.filter_by(escala_id=escala.id).delete()
        db.session.delete(escala)
        db.session.commit()
        flash("Escala excluída com sucesso!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Erro ao excluir escala.", "error")
        print(e)

    return redirect(url_for("admin_escalas"))



@app.route("/admin_visao_escalas")
@login_required
def admin_visao_escalas():

    if not current_user.is_admin:
        return redirect(url_for("dashboard"))

    hoje = date.today()
    mes_atual = hoje.month
    ano_atual = hoje.year

    stmt = (
        select(
            UsuarioEscala.id.label("UsuarioEscalaId"),
            User.username.label("Username"),
            Escala.data.label("Data"),
            Escala.evento.label("Evento"),
            Escala.tipo.label("Tipo"),
            UsuarioEscala.funcao.label("Funcao"),
            Escala.horario.label("Horario")
        )
        .join(User, User.id == UsuarioEscala.user_id)
        .join(Escala, Escala.id == UsuarioEscala.escala_id)
        .where(
            extract("month", Escala.data) == mes_atual,
            extract("year", Escala.data) == ano_atual
        )
        .order_by(Escala.data, User.username)
    )

    registros = db.session.execute(stmt).all()

    return render_template(
        "admin_visao_escalas.html",
        registros=registros
    )



@app.route("/admin/remover-atribuicao", methods=["POST"])
@login_required
def remover_atribuicao():

    if not current_user.is_admin:
        return redirect(url_for("dashboard"))

    usuario_escala_id = request.form.get("usuario_escala_id")

    if usuario_escala_id:
        registro = UsuarioEscala.query.get(usuario_escala_id)

        if registro:
            db.session.delete(registro)
            db.session.commit()

            flash("Atribuição removida com sucesso.", "success")

    return redirect(url_for("admin_visao_escalas"))



@app.route("/perfil", methods=["GET", "POST"])
@login_required
def perfil():
    if request.method == "POST":
        if "photo" not in request.files:
            flash("Nenhum arquivo enviado", "error")
            return redirect(url_for("perfil"))

        file = request.files["photo"]

        if file.filename == "":
            flash("Nenhum arquivo selecionado", "error")
            return redirect(url_for("perfil"))

        if file and allowed_file(file.filename):
            filename = f"user_{current_user.id}.jpg"

            img = Image.open(file)
            img = img.convert("RGB")
            img.thumbnail((500, 500))

            buf = BytesIO()
            img.save(buf, format="JPEG", quality=85)
            buf.seek(0)

            supabase.storage.from_("avatars").upload(
                filename,
                buf.getvalue(),
                {"content-type": "image/jpeg"}
            )

            public_url = supabase.storage.from_("avatars").get_public_url(filename)

            current_user.photo_path = public_url
            db.session.commit()

            flash("Foto atualizada com sucesso", "success")
            return redirect(url_for("perfil"))

        flash("Formato de arquivo inválido", "error")
        return redirect(url_for("perfil"))

    return render_template("perfil.html")



@app.route("/admin_usuarios", methods=["GET", "POST"])
@login_required
def admin_usuarios():
    if not current_user.is_super_admin:
        abort(403)

    if request.method == "POST":
        acao = request.form.get("acao")

        # =====================
        # CRIAR USUÁRIO
        # =====================
        if acao == "criar":
            username = request.form["username"]
            password = request.form["password"]
            role = request.form["role"]

            password_hash = generate_password_hash(password)
            is_admin = True if role == "admin" else False
            is_super_admin = False

            novo_usuario = User(
                username=username,
                password_hash=password_hash,
                is_admin=is_admin,
                is_super_admin=is_super_admin
            )

            db.session.add(novo_usuario)
            db.session.commit()

            flash("Usuário cadastrado com sucesso!", "success")

        # =====================
        # TROCAR SENHA
        # =====================
        elif acao == "trocar_senha":
            user_id = request.form["user_id"]
            nova_senha = request.form["nova_senha"]

            usuario = User.query.get(user_id)
            if usuario:
                usuario.password_hash = generate_password_hash(nova_senha)
                db.session.commit()
                flash("Senha redefinida com sucesso!", "success")

        # =====================
        # EXCLUIR USUÁRIO
        # =====================
        elif acao == "excluir_usuario":
            user_id = int(request.form["user_id"])

            # 🔒 PROTEÇÃO: não excluir a si mesmo
            if user_id == current_user.id:
                flash("Você não pode excluir o próprio usuário.", "error")
            else:
                usuario = User.query.filter_by(
                    id=user_id,
                    is_super_admin=False
                ).first()

                if not usuario:
                    flash("Usuário não pode ser excluído.", "error")
                else:
                    # ✅ APAGA VÍNCULOS ANTES (resolve FK)
                    UsuarioEscala.query.filter_by(user_id=user_id).delete()
                    db.session.delete(usuario)
                    db.session.commit()
                    flash("Usuário excluído com sucesso!", "success")

    # =====================
    # LISTAR USUÁRIOS
    # =====================
    usuarios = User.query.with_entities(
        User.id,
        User.username
    ).all()

    return render_template(
        "admin_usuarios.html",
        usuarios=usuarios
    )


@app.route("/trocar_senha", methods=["GET", "POST"])
@login_required
def trocar_senha():
    if request.method == "POST":
        senha_atual = request.form["senha_atual"]
        nova_senha = request.form["nova_senha"]
        confirmar_senha = request.form["confirmar_senha"]

        # 1️⃣ Verifica senha atual
        if not check_password_hash(current_user.password_hash, senha_atual):
            flash("Senha atual incorreta.", "error")
            return redirect(url_for("trocar_senha"))

        # 2️⃣ Confirma nova senha
        if nova_senha != confirmar_senha:
            flash("As novas senhas não coincidem.", "error")
            return redirect(url_for("trocar_senha"))

        if not senha_forte(nova_senha):
            flash("Senha fraca (mín. 8 caracteres e número)", "error")
            return redirect(url_for("trocar_senha"))

        # 3️⃣ Gera novo hash
        novo_hash = generate_password_hash(nova_senha)

        # 4️⃣ Atualiza no banco (equivalente ao UPDATE)
        current_user.password_hash = novo_hash
        db.session.commit()

        flash("Senha alterada com sucesso!", "success")
        return redirect(url_for("perfil"))

    return render_template("trocar_senha.html")



# =========================
# INIT
# =========================

# with app.app_context():
#     db.create_all()

if __name__ == "__main__":
    app.run(debug=False)
