from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Optional, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'uma-chave-secreta-muito-segura'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clientes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))

class ClienteLogin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'))
    cliente = db.relationship('Cliente', backref=db.backref('login', uselist=False))


class Cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    contato = db.Column(db.String(50))
    email = db.Column(db.String(100))
    projetos = db.relationship('Projeto', backref='cliente', lazy=True)


class Projeto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    link_powerbi = db.Column(db.String(500), nullable=False)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)


# Forms
class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Login')


class ClienteForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    contato = StringField('Contato')
    email = StringField('Email', validators=[DataRequired(), Email()])
    # Adicione estes novos campos
    criar_login = BooleanField('Criar acesso para o cliente?')
    password = PasswordField('Senha', validators=[Optional()])
    confirm_password = PasswordField('Confirmar Senha', validators=[Optional()])
    submit = SubmitField('Salvar')

    def validate(self, extra_validators=None):
        # Validação padrão primeiro
        if not super().validate():
            return False

        # Validações customizadas
        if self.criar_login.data:
            if not self.password.data:
                self.password.errors.append('Senha é obrigatória')
                return False
            if self.password.data != self.confirm_password.data:
                self.confirm_password.errors.append('As senhas não coincidem')
                return False

        return True

class ClienteLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Login')

class EditarProjetoForm(FlaskForm):
    nome = StringField('Nome do Projeto', validators=[DataRequired()])
    link_powerbi = StringField('Link Power BI', validators=[DataRequired()])
    submit = SubmitField('Salvar Alterações')


class ProjetoForm(FlaskForm):
    nome = StringField('Nome do Projeto', validators=[DataRequired()])
    link_powerbi = StringField('Link Power BI', validators=[DataRequired()])
    submit = SubmitField('Adicionar Projeto')


class AdicionarSenhaForm(FlaskForm):
    password = PasswordField('Nova Senha', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired()])
    submit = SubmitField('Cadastrar Senha')



    def validate_confirm_password(self, field):
        if self.password.data != field.data:
            raise ValidationError('As senhas não coincidem')

# Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Rotas
@app.route('/')
@login_required
def index():
    clientes = Cliente.query.all()
    return render_template('admin/index.html', clientes=clientes)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for('index'))
        flash('Credenciais inválidas')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/clientes/novo', methods=['GET', 'POST'])
@login_required
def novo_cliente():
    form = ClienteForm()

    if form.validate_on_submit():
        try:
            # Cria o cliente
            cliente = Cliente(
                nome=form.nome.data,
                contato=form.contato.data,
                email=form.email.data
            )
            db.session.add(cliente)
            db.session.flush()  # Gera o ID sem commit

            # Se marcado para criar login
            if form.criar_login.data:
                # Verifica se email já está em uso
                if ClienteLogin.query.filter_by(email=form.email.data).first():
                    flash('Este email já está cadastrado para login', 'danger')
                    return render_template('admin/novo_cliente.html', form=form)

                # Cria o login do cliente
                cliente_login = ClienteLogin(
                    email=form.email.data,
                    password=generate_password_hash(form.password.data),
                    cliente_id=cliente.id
                )
                db.session.add(cliente_login)

            db.session.commit()
            flash('Cliente cadastrado com sucesso!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar cliente: {str(e)}', 'danger')

    return render_template('admin/novo_cliente.html', form=form)


@app.route('/clientes/<int:id>/projetos', methods=['GET', 'POST'])
@login_required
def projetos_cliente(id):
    cliente = Cliente.query.get_or_404(id)
    form = ProjetoForm()

    if form.validate_on_submit():
        projeto = Projeto(
            nome=form.nome.data,
            link_powerbi=form.link_powerbi.data,
            cliente_id=id
        )
        db.session.add(projeto)
        db.session.commit()
        flash('Projeto adicionado com sucesso!')
        return redirect(url_for('projetos_cliente', id=id))

    return render_template('admin/projetos.html', cliente=cliente, form=form)


# Rotas para clientes
@app.route('/cliente/login', methods=['GET', 'POST'])
def cliente_login():
    form = ClienteLoginForm()
    if form.validate_on_submit():
        cliente_login = ClienteLogin.query.filter_by(email=form.email.data).first()
        if cliente_login and check_password_hash(cliente_login.password, form.password.data):
            login_user(cliente_login)
            return redirect(url_for('cliente_projetos'))
        flash('Email ou senha incorretos', 'danger')
    return render_template('cliente/login.html', form=form)


@app.route('/clientes/<int:id>/adicionar-senha', methods=['GET', 'POST'])
@login_required
def adicionar_senha_cliente(id):
    cliente = Cliente.query.get_or_404(id)
    form = AdicionarSenhaForm()

    if form.validate_on_submit():
        # Verifica se já não existe login para este cliente
        if ClienteLogin.query.filter_by(cliente_id=id).first():
            flash('Este cliente já possui uma senha cadastrada', 'warning')
        else:
            cliente_login = ClienteLogin(
                email=cliente.email,
                password=generate_password_hash(form.password.data),
                cliente_id=id
            )
            db.session.add(cliente_login)
            db.session.commit()
            flash('Senha cadastrada com sucesso!', 'success')
            return redirect(url_for('projetos_cliente', id=id))

    return render_template('admin/adicionar_senha.html', form=form, cliente=cliente)


@app.route('/cliente/projetos')
@login_required
def cliente_projetos():
    if not hasattr(current_user, 'cliente'):  # Verifica se é um cliente
        abort(403)
    return render_template('cliente/projetos.html', cliente=current_user.cliente)


# Rotas administrativas para edição
@app.route('/admin/projetos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_projeto(id):
    if not isinstance(current_user, User):  # Verifica se é admin
        abort(403)
    projeto = Projeto.query.get_or_404(id)
    form = EditarProjetoForm(obj=projeto)

    if form.validate_on_submit():
        form.populate_obj(projeto)
        db.session.commit()
        flash('Projeto atualizado com sucesso!')
        return redirect(url_for('projetos_cliente', id=projeto.cliente_id))

    return render_template('admin/editar_projeto.html', form=form, projeto=projeto)


@app.route('/admin/projetos/excluir/<int:id>', methods=['POST'])
@login_required
def excluir_projeto(id):
    if not isinstance(current_user, User):  # Verifica se é admin
        abort(403)
    projeto = Projeto.query.get_or_404(id)
    cliente_id = projeto.cliente_id
    db.session.delete(projeto)
    db.session.commit()
    flash('Projeto excluído com sucesso!')
    return redirect(url_for('projetos_cliente', id=cliente_id))


@app.route('/admin/clientes/novo', methods=['GET', 'POST'])
@login_required
def novo_cliente_admin():
    form = ClienteForm()

    # Validador customizado para verificar email único
    def validate_email(form, field):
        if Cliente.query.filter_by(email=field.data).first():
            raise ValidationError('Email já cadastrado')

    form.email.validators.append(validate_email)

    if form.validate_on_submit():
        # Cria o cliente
        cliente = Cliente(
            nome=form.nome.data,
            email=form.email.data,
            contato=form.contato.data
        )
        db.session.add(cliente)
        db.session.commit()

        # Cria o login do cliente
        cliente_login = ClienteLogin(
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            cliente_id=cliente.id
        )
        db.session.add(cliente_login)
        db.session.commit()

        flash('Cliente cadastrado com sucesso!', 'success')
        return redirect(url_for('lista_clientes'))

    return render_template('admin/novo_cliente.html', form=form)


@app.route('/projeto/<int:id>')
@login_required
def visualizar_projeto(id):
    projeto = Projeto.query.get_or_404(id)
    return render_template('admin/visualizar_projeto.html', projeto=projeto)


if __name__ == '__main__':
    with app.app_context():
        # Criação do banco de dados
        db.create_all()

        # Cria um cliente de teste (opcional)
        if not ClienteLogin.query.first():
            cliente = Cliente(
                nome="Cliente Teste",
                email="cliente@teste.com",
                contato="(11) 99999-9999"
            )
            db.session.add(cliente)
            db.session.commit()

            cliente_login = ClienteLogin(
                email="cliente@teste.com",
                password="123456",  # Em produção, usar generate_password_hash
                cliente_id=cliente.id
            )
            db.session.add(cliente_login)
            db.session.commit()
            print("Cliente de teste criado!")

        # Criar usuário admin padrão se não existir
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password='admin123')
            db.session.add(admin)
            db.session.commit()
    print(app.url_map)
    app.run(debug=True)