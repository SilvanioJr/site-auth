MESES_PT = {
    1: "Janeiro",
    2: "Fevereiro",
    3: "Março",
    4: "Abril",
    5: "Maio",
    6: "Junho",
    7: "Julho",
    8: "Agosto",
    9: "Setembro",
    10: "Outubro",
    11: "Novembro",
    12: "Dezembro"
}

from datetime import date
from flask import flash
from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import check_password_hash
import pyodbc
import calendar
import os
import secrets
from datetime import datetime
from flask_login import current_user
from werkzeug.utils import secure_filename
from flask import abort
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image
from datetime import timedelta
from flask import g




app = Flask(__name__)
csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.permanent_session_lifetime = timedelta(minutes=45)

secret = os.environ.get("SECRET_KEY")
if not secret:
    raise RuntimeError("Defina a variável de ambiente SECRET_KEY")
app.secret_key = secret


UPLOAD_FOLDER = "static/uploads/users"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def senha_forte(senha):
    return (
        len(senha) >= 8 and
        any(c.isdigit() for c in senha) and
        any(c.isalpha() for c in senha)
    )



# 🔌 Configuração SQL Server
conn_str = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=localhost;"
    "DATABASE=SiteAuth;"
    "Trusted_Connection=yes;"
)

# 🔐 Login Manager
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# 👤 Modelo de usuário
# class User(UserMixin):
#     def __init__(self, id, username, password, is_admin):
#         self.id = id
#         self.username = username
#         self.PasswordHash = password
#         self.Isadmin = is_admin
# class User(UserMixin):
#     def __init__(self, id, username, password_hash, is_admin):
#         self.id = id
#         self.username = username
#         self.password_hash = password_hash
#         self.is_admin = is_admin

# class User(UserMixin):
#     def __init__(self, id, username, password_hash, is_admin, photo_path=None):
#         self.id = id
#         self.username = username
#         self.password_hash = password_hash
#         self.is_admin = is_admin
#         self.photo_path = photo_path

class User(UserMixin):
    def __init__(
        self,
        id,
        username,
        password_hash,
        is_admin,
        photo_path,
        is_super_admin
    ):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = is_admin
        self.photo_path = photo_path
        self.is_super_admin = is_super_admin



@login_manager.user_loader
def load_user(user_id):
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT Id, Username, PasswordHash, IsAdmin, PhotoPath, IsSuperAdmin
        FROM Users
        WHERE Id = ?
        """,
        user_id
    )


    row = cursor.fetchone()
    conn.close()

    if row:
        return User(
            row.Id,
            row.Username,
            row.PasswordHash,
            row.IsAdmin,
            row.PhotoPath,
            row.IsSuperAdmin
        )


    return None


@app.before_request
def gerar_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.after_request
def security_headers(response):
    nonce = g.get("csp_nonce")

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        f"script-src 'self' 'nonce-{nonce}';"
    )
    return response


# 📄 Rotas
@app.route("/", methods=["GET", "POST"])
@limiter.limit("6 per minute", methods=["POST"], error_message="Muitas tentativas de login. Aguarde cerca de 1 minuto e tente novamente.")
@limiter.limit("20 per minute", methods=["GET"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT Id, Username, PasswordHash, IsAdmin, PhotoPath, IsSuperAdmin
            FROM Users
            WHERE Username = ?
            """,
            username
        )

        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user.PasswordHash, password):
            login_user(
                User(
                    user.Id,
                    user.Username,
                    user.PasswordHash,
                    user.IsAdmin,
                    user.PhotoPath,
                    user.IsSuperAdmin
                )
            )



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

    # Buscar escalas do mês
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            DAY(Data) AS Dia,
            Tipo,
            Evento,
            Horario
        FROM Escalas
        WHERE MONTH(Data) = ? AND YEAR(Data) = ?
        ORDER BY Data, Horario
    """, mes, ano)

    escalas = {}

    for row in cursor.fetchall():
        dia = row.Dia

        if dia not in escalas:
            escalas[dia] = []

        escalas[dia].append({
            "tipo": row.Tipo,
            "evento": row.Evento,
            "horario": row.Horario.strftime("%H:%M")
        })

    conn.close()

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

@app.route("/minhas-escalas")
@login_required
def minhas_escalas():
    hoje = datetime.today()

    mes = request.args.get("mes", type=int)
    ano = request.args.get("ano", type=int)

    if not mes or not ano:
        mes = hoje.month
        ano = hoje.year

    nome_mes = MESES_PT[mes]

    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            DAY(e.Data) AS Dia,
            ue.Funcao,
            CASE 
                WHEN e.Horario IS NULL THEN ''
                ELSE CONVERT(VARCHAR(5), e.Horario, 108)
            END AS Horario,
            e.Evento
        FROM UsuarioEscala ue
        JOIN Escalas e ON ue.EscalaId = e.Id
        WHERE
            ue.UserId = ?
            AND MONTH(e.Data) = ?
            AND YEAR(e.Data) = ?
        ORDER BY e.Data, e.Horario

    """,
        current_user.id,
        mes,
        ano
    )

    escalas = cursor.fetchall()
    conn.close()

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


@app.route("/admin/escalas", methods=["GET", "POST"])
@login_required
def admin_escalas():

    if not current_user.is_admin:
        return redirect(url_for("dashboard"))

    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()

    # 🔹 Cadastro de nova escala
    if request.method == "POST" and request.form.get("acao") == "criar_escala":
        data = request.form["data"]
        evento = request.form["evento"]
        horario = request.form["horario"]
        tipo = request.form["tipo"]

        cursor.execute("""
            INSERT INTO Escalas (Data, Tipo, Evento, Horario)
            VALUES (?, ?, ?, ?)
        """, data, tipo, evento, horario)

        conn.commit()
        flash("Escala criada com sucesso!", "success")


    # 🔹 Atribuir usuário à escala
    if request.method == "POST" and request.form.get("acao") == "atribuir_usuario":
        escala_id = request.form["escala_id"]
        user_id = request.form["user_id"]
        funcao = request.form["funcao"]

        cursor.execute("""
            INSERT INTO UsuarioEscala (UserId, EscalaId, Funcao)
            VALUES (?, ?, ?)
        """, user_id, escala_id, funcao)

        conn.commit()
        flash("Usuário atribuído à escala com sucesso!", "success")


    # 🔹 Buscar escalas
    hoje = date.today()
    mes_atual = hoje.month
    ano_atual = hoje.year

    cursor.execute("""
        SELECT Id, Data, Evento
        FROM Escalas
        WHERE MONTH(Data) = ? AND YEAR(Data) = ?
        ORDER BY Data
    """, mes_atual, ano_atual)

    escalas = cursor.fetchall()

    # 🔹 Buscar usuários
    cursor.execute("""
        SELECT Id, Username
        FROM Users
        ORDER BY Username
    """)
    usuarios = cursor.fetchall()

    conn.close()

    return render_template(
        "admin_escalas.html",
        escalas=escalas,
        usuarios=usuarios
    )

@app.route("/admin/visao-escalas")
@login_required
def admin_visao_escalas():

    if not current_user.is_admin:
        return redirect(url_for("dashboard"))

    hoje = date.today()
    mes_atual = hoje.month
    ano_atual = hoje.year

    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            ue.Id AS UsuarioEscalaId,
            u.Username,
            e.Data,
            e.Evento,
            e.Tipo,
            ue.Funcao,
            e.Horario
        FROM UsuarioEscala ue
        JOIN Users u ON u.Id = ue.UserId
        JOIN Escalas e ON e.Id = ue.EscalaId
        WHERE MONTH(e.Data) = ? AND YEAR(e.Data) = ?
        ORDER BY e.Data, u.Username
    """, mes_atual, ano_atual)

    registros = cursor.fetchall()
    conn.close()

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
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM UsuarioEscala WHERE Id = ?",
            usuario_escala_id
        )

        conn.commit()
        conn.close()

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
            ext = file.filename.rsplit(".", 1)[1].lower()
            filename = f"user_{current_user.id}.{ext}"

            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            img = Image.open(file)
            img = img.convert("RGB")
            img.thumbnail((500, 500))
            img.save(file_path, "JPEG")


            db_path = f"/static/uploads/users/{filename}"

            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE Users SET PhotoPath = ? WHERE Id = ?",
                db_path,
                current_user.id
            )
            conn.commit()
            conn.close()

            flash("Foto atualizada com sucesso", "success")
            return redirect(url_for("perfil"))

        flash("Formato de arquivo inválido", "error")
        return redirect(url_for("perfil"))

    return render_template("perfil.html")


@app.route("/admin/usuarios", methods=["GET", "POST"])
@login_required
def admin_usuarios():
    if not current_user.is_super_admin:
        abort(403)

    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()

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
            is_admin = 1 if role == "admin" else 0
            is_super_admin = 0

            cursor.execute(
                """
                INSERT INTO Users (Username, PasswordHash, IsAdmin, IsSuperAdmin)
                VALUES (?, ?, ?, ?)
                """,
                username,
                password_hash,
                is_admin,
                is_super_admin
            )

            conn.commit()
            flash("Usuário cadastrado com sucesso!", "success")

        # =====================
        # TROCAR SENHA
        # =====================
        elif acao == "trocar_senha":
            user_id = request.form["user_id"]
            nova_senha = request.form["nova_senha"]

            nova_hash = generate_password_hash(nova_senha)

            cursor.execute(
                "UPDATE Users SET PasswordHash = ? WHERE Id = ?",
                nova_hash,
                user_id
            )

            conn.commit()
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
                cursor.execute(
                    "DELETE FROM Users WHERE Id = ? AND IsSuperAdmin = 0",
                    user_id
                )

                if cursor.rowcount == 0:
                    flash("Usuário não pode ser excluído.", "error")
                else:
                    conn.commit()
                    flash("Usuário excluído com sucesso!", "success")

    # =====================
    # LISTAR USUÁRIOS
    # =====================
    cursor.execute("SELECT Id, Username FROM Users")
    usuarios = cursor.fetchall()

    conn.close()

    return render_template("admin_usuarios.html", usuarios=usuarios)


@app.route("/trocar-senha", methods=["GET", "POST"])
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

        # 4️⃣ Atualiza no banco
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE Users SET PasswordHash = ? WHERE Id = ?",
            novo_hash,
            current_user.id
        )
        conn.commit()
        conn.close()

        flash("Senha alterada com sucesso!", "success")
        return redirect(url_for("dashboard"))

    return render_template("trocar_senha.html")



# 🚀 Iniciar servidor
if __name__ == "__main__":
    app.run(debug=False)



