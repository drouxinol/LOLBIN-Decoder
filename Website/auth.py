from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField, BooleanField
from wtforms.validators import DataRequired, Email, Length
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, Validate, Parameter, Command
from . import db
from flask import session
from sqlalchemy import exc


auth = Blueprint('auth', __name__)

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit_login = SubmitField('Login')

class ValidateForm(FlaskForm): #formulario para a tabela validate
    validate = SubmitField('Validate', validators=[DataRequired()])
    reject = SubmitField('Reject', validators=[DataRequired()])
    edit = SubmitField('Edit', validators=[DataRequired()])


class CreateUserForm(FlaskForm): #formuario para criar um user
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=64)])
    submit_create_user = SubmitField('Create')

class EditUserForm(FlaskForm): #formulario para editar um user
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=64)])
    user_id = HiddenField()
    submit_edit_user = SubmitField('Save')

class DeleteUserForm(FlaskForm):
    user_id = HiddenField('User ID', validators=[DataRequired()])
    submit_delete_user = SubmitField('Delete')

class EditParameterForm(FlaskForm): #formulario para editar um parametro da tabela de parametros porque temos campos diferentes
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    command_name = StringField('Command Name', validators=[DataRequired()])
    is_alone = BooleanField('Is_Alone')
    submit_edit_param = SubmitField('Save')

class DeleteParameterForm(FlaskForm):
    parameter_id = HiddenField('Parameter ID', validators=[DataRequired()])
    submit_delete = SubmitField('Delete')

class CreateParameterForm(FlaskForm):
    name = StringField('Parameter Name', validators=[DataRequired()])
    description = StringField('Parameter Description', validators=[DataRequired()])
    is_alone = BooleanField('Is_Alone')
    command_name = StringField('Command Name', validators=[DataRequired()])
    submit_create_param = SubmitField('Create Parameter')

class EditValidateParameterForm(FlaskForm): #formulario para editar um parametro da tabela validate porque temos campos diferentes
    name = StringField('Name', validators=[DataRequired()])
    command_name = StringField('Command Name', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()]) 
    is_alone = BooleanField('Is_Alone')
    submit_edit_validate_param = SubmitField('Save')

class EditCommandForm(FlaskForm): #formulario para editar um comando
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    alias = StringField('Alias', validators=[DataRequired()])
    submit_edit_command = SubmitField('Save')

class DeleteCommandForm(FlaskForm):
    command_id = HiddenField('Command ID', validators=[DataRequired()])
    submit_delete = SubmitField('Delete')

class CreateCommandForm(FlaskForm):
    name = StringField('Command Name', validators=[DataRequired()])
    description = StringField('Command Description', validators=[DataRequired()])
    alias = StringField('Alias')
    submit_create_command = SubmitField('Create Command')


#Para suportar HTTP POST e GET REQUESTS
#Quando vamos para a pagina principal, ele deteta e executa a funcao home()
@auth.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit(): # O método validate_on_submit() verifica se o método de pedido é um POST e se é válido de acordo com os validadores do formulário, e depois verifica o token CSRF para prevenir ataques CSRF.
        email = form.email.data
        password = form.password.data

        print(f"Email: {email}\nPassword: {password}")

        user = User.query.filter_by(email=email).first()
        
        if user:
            ##if check_password_hash(user.password, password):
            if user.password == password:
                login_user(user, remember=True)
                return redirect(url_for('auth.dashboard'))
            else:
                flash('Email or password are incorrect!', 'danger')
                return redirect(url_for('auth.login'))
        else:
            flash('Email or password are incorrect!', 'danger')
            return redirect(url_for('auth.login'))

    return render_template("login.html", form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('views.home'))


@auth.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template("dashboard.html")


@auth.route('/dashboard/validate', methods=['GET', 'POST'])
@login_required
def validate():
    form = ValidateForm()
    if form.validate_on_submit():
        row_id = request.form.get('row_id')

        try:
            # Begin a database transaction
            db.session.begin_nested()

            # Acquire an exclusive lock on the row corresponding to the selected parameter
            row = Validate.query.filter_by(id=row_id).with_for_update().one()

            if form.validate.data:
                command = Command.query.filter_by(name=row.command).first()
                if command is None:
                    flash('Ocorreu um erro.', "danger")
                    return redirect(url_for('auth.validate'))

                parameter = Parameter(name=row.parameter, description=row.param_description, command_id=command.id)
                if parameter is None:
                    flash('Ocorreu um erro.', 'danger')
                    return redirect(url_for('auth.validate'))

                db.session.add(parameter)
                db.session.delete(row)

            elif form.reject.data:
                Validate.query.filter_by(id=row_id).delete()

            elif form.edit.data:
                session['row_id'] = row_id
                return redirect(url_for('auth.edit_validate_parameter'))

            # Save the changes to the database
            db.session.commit()
            flash('Row was validated or deleted successfully.', "success")

        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash('Something went wrong in deleting or validating the row: {}'.format(str(e)), "danger")

        except Exception as e:
            db.session.rollback()
            flash('Something went wrong in deleting or validating the row: {}'.format(str(e)), "danger")

        return redirect(url_for('auth.validate'))

    rows = Validate.query.all()
    return render_template("validate.html", rows=rows, form=form)

@auth.route('/dashboard/edit_validate_parameter', methods=['GET', 'POST'])
@login_required
def edit_validate_parameter():
    form = EditValidateParameterForm()
    parameter = None
    parameter_id = session.get('row_id')
    if parameter_id is not None:
        parameter = Validate.query.get(parameter_id)

    if parameter is None:
        flash('Parameter not found!', 'danger')
        return redirect(url_for('auth.validate'))

    if request.method == 'POST' and form.validate_on_submit():
        command_name = form.command_name.data.lower()
        command = Command.query.filter_by(name=command_name).first()
        if command is None:
            flash('Command not found!', 'danger')
            return redirect(url_for('auth.edit_validate_parameter'))

        try:
            # Begin a database transaction
            db.session.begin_nested()

            # Acquire an exclusive lock on the parameter row
            parameter = Validate.query.filter_by(id=parameter_id).with_for_update().one()

            # Update the parameter object with the new values
            parameter.parameter = form.name.data
            parameter.param_description = form.description.data
            parameter.command = form.command_name.data.lower()
            parameter.is_alone = form.is_alone.data

            # Save the changes to the database
            db.session.commit()
            flash('Parameter edited successfully!', 'success')
            session.pop('row_id')

        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash('An error occurred while editing the parameter: {}'.format(str(e)), 'danger')

        except Exception as e:
            db.session.rollback()
            flash('An error occurred while editing the parameter: {}'.format(str(e)), 'danger')

        return redirect(url_for('auth.validate'))

    form.name.data = parameter.parameter
    form.description.data = parameter.param_description
    form.command_name.data = parameter.command
    form.is_alone.data = parameter.is_alone

    return render_template('edit_validate_parameter.html', form=form, row=parameter)

@auth.route('/dashboard/commands', methods=['GET', 'POST'])
@login_required
def commands():
    deleteform = DeleteCommandForm()
    search_query = None
    search_query = request.args.get('search_query')

    if search_query:
        commands = Command.query.filter(Command.name.like(f'%{search_query}%')).order_by(Command.id.asc())
    else:
        commands = Command.query.order_by(Command.id.asc())

    page = request.args.get('page', 1, type=int) # get the page number from the URL query string
    per_page = 10 # set the number of items per page

    paginated_commands = commands.paginate(page=page, per_page=per_page, error_out=False)    

    if deleteform.validate_on_submit():
        command_id = deleteform.command_id.data
        command = Command.query.get(command_id)
        try:
            # Begin a database transaction
            db.session.begin_nested()

            # Acquire an exclusive lock on the command row
            command = Command.query.filter_by(id=command_id).with_for_update().one()

            # Delete the command
            db.session.delete(command)
            db.session.commit()
            flash(f'Command "{command.name}" has been deleted!', 'success')

        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash(f'An error occurred while deleting the command: {str(e)}', 'danger')

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while deleting the command: {str(e)}', 'danger')

        return redirect(url_for('auth.commands'))

    return render_template("commands.html", commands=paginated_commands, deleteform=deleteform, search_query=search_query)



@auth.route('/dashboard/edit_command', methods=['GET', 'POST'])
@login_required
def edit_command():
    form = EditCommandForm()
    command = None
    command_id = request.form.get('command_id')
    if command_id is not None:
        command = Command.query.get(command_id)

    if command is None:
        flash('Command not found!', 'danger')
        return redirect(url_for('auth.commands'))

    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Begin a database transaction
            db.session.begin_nested()

            # Acquire an exclusive lock on the row corresponding to the selected command
            command = Command.query.filter_by(id=command_id).with_for_update().one()

            command.name = form.name.data
            command.description = form.description.data
            command.alias = form.alias.data

            # Save the changes to the database
            db.session.commit()
            flash('Command edited successfully!', 'success')

        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash(f'An error occurred while editing the command: {str(e)}', 'danger')

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while editing the command: {str(e)}', 'danger')

        return redirect(url_for('auth.commands'))

    form.name.data = command.name
    form.description.data = command.description
    form.alias.data = command.alias

    return render_template('edit_command.html', form=form, command=command)

@auth.route('/dashboard/create_command', methods=['GET', 'POST'])
@login_required
def create_command():
    form = CreateCommandForm()

    if request.method == 'POST' and form.validate_on_submit():
        name = form.name.data.lower()
        description = form.description.data
        alias = str(form.alias.data.split(','))

        try:
            # Begin a database transaction
            db.session.begin_nested()

            # Acquire an exclusive lock on the Command table
            db.session.query(Command).with_for_update().all()

            command = Command.query.filter_by(name=name).first()

            if command:
                flash(f'The command "{name}" already exists!', 'danger')
                return redirect(url_for('auth.create_command'))

            # Create a new command and add it to the session
            command = Command(name=name, description=description, alias=alias)
            db.session.add(command)

            # Save the changes to the database
            db.session.commit()
            flash('Command created successfully!', 'success')

        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash(f'An error occurred while creating the command: {str(e)}', 'danger')

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the command: {str(e)}', 'danger')

        return redirect(url_for('auth.commands'))

    return render_template("create_command.html", form=form)


@auth.route('/dashboard/parameters', methods=['GET', 'POST'])
@login_required
def parameters():
    deleteform = DeleteParameterForm() 
    search_query = None
    search_query = request.args.get('search_query')

    if search_query:
        parameters = Parameter.query.filter(Parameter.name.like(f'%{search_query}%')).order_by(Parameter.id.asc())
    else:
        parameters = Parameter.query.order_by(Parameter.id.asc())


    page = request.args.get('page', 1, type=int) # get the page number from the URL query string
    per_page = 10 # set the number of items per page

    paginated_params = parameters.paginate(page=page, per_page=per_page, error_out=False)    

    if deleteform.validate_on_submit():
        parameter_id = deleteform.parameter_id.data
        parameter = Parameter.query.get(parameter_id)
        if parameter is not None:
            try:
                # Begin a database transaction
                db.session.begin_nested()

                # Acquire an exclusive lock on the row corresponding to the selected parameter
                parameter = Parameter.query.filter_by(id=parameter_id).with_for_update().one()

                db.session.delete(parameter)
                db.session.commit()
                flash(f'Parameter "{parameter.name}" has been deleted!', 'success')
                
            except exc.SQLAlchemyError as e:
                db.session.rollback()
                flash(f'An error occurred while deleting the parameter: {str(e)}', 'danger')
            
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred while deleting the parameter: {str(e)}', 'danger')

            return redirect(url_for('auth.parameters'))
        
    return render_template("parameters.html", parameters=paginated_params, deleteform=deleteform, search_query=search_query)

@auth.route('/dashboard/edit_parameter', methods=['GET', 'POST'])
@login_required
def edit_parameter():
    form = EditParameterForm()
    parameter = None
    command_id = None
    
    parameter_id = request.form.get('parameter_id')
    if parameter_id is not None:
        parameter = Parameter.query.get(parameter_id)

    if parameter is None:
        return redirect(url_for('auth.parameters'))

    if request.method == 'POST' and form.validate_on_submit():
        command_name = form.command_name.data.lower()
        command = Command.query.filter_by(name=command_name).first()

        if command is not None:
            command_id = command.id
        
        if command_id is None:
            flash('Invalid command name. Please enter a valid command name.', 'danger')
            form.command_name.data = Command.query.get(parameter.command_id).name
            return render_template('edit_parameter.html', form=form, parameter=parameter)
        
        try:
            # Begin a database transaction
            db.session.begin_nested()

            # Acquire an exclusive lock on the row corresponding to the selected parameter
            parameter = Parameter.query.filter_by(id=parameter_id).with_for_update().one()

            parameter.name = form.name.data
            parameter.description = form.description.data
            parameter.command_id = command_id
            parameter.is_alone = form.is_alone.data

            db.session.commit()
            flash('Parameter edited successfully!', 'success')

        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash(f'An error occurred while editing the parameter: {str(e)}', 'danger')

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while editing the parameter: {str(e)}', 'danger')

        return redirect(url_for('auth.parameters'))

    form.name.data = parameter.name
    form.description.data = parameter.description
    form.command_name.data = Command.query.get(parameter.command_id).name
    form.is_alone.data = parameter.is_alone

    return render_template('edit_parameter.html', form=form, parameter=parameter)

@auth.route('/dashboard/create_parameter', methods=['GET', 'POST'])
@login_required
def create_parameter():
    form = CreateParameterForm()

    if request.method == 'POST' and form.validate_on_submit():
        name = form.name.data.lower()
        description = form.description.data
        is_alone = form.is_alone.data
        command_name = form.command_name.data.lower()

        try:
            # Begin a database transaction
            db.session.begin_nested()

            # Acquire an exclusive lock on the Command row
            command = Command.query.filter_by(name=command_name).with_for_update().one()

            # Create a new Parameter object
            parameter = Parameter(name=name, description=description, is_alone=is_alone, command_id=command.id)
            db.session.add(parameter)
            db.session.commit()

            flash('Parameter created successfully!', 'success')
            return redirect(url_for('auth.parameters'))

        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash(f'An error occurred while creating the parameter: {str(e)}', 'danger')

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the parameter: {str(e)}', 'danger')

        return render_template('create_parameter.html', form=form)

    return render_template('create_parameter.html', form=form)


@auth.route('/dashboard/users', methods=['GET', 'POST'])
@login_required
def users():
    delete_form = DeleteUserForm()
    search_query = None
    search_query = request.args.get('search_query', '').strip()

    try:
        # Begin a database transaction
        db.session.begin_nested()

        if search_query:
            # Acquire an exclusive lock on the User rows that match the search query
            users = User.query.filter(User.email.like(f'%{search_query}%')).with_for_update().order_by(User.id.asc())
        else:
            # Acquire an exclusive lock on all User rows
            users = User.query.with_for_update().order_by(User.id.asc())

        page = request.args.get('page', 1, type=int) # get the page number from the URL query string
        per_page = 10 # set the number of items per page

        paginated_users = users.paginate(page=page, per_page=per_page, error_out=False)

        if delete_form.validate_on_submit():
            user_id = delete_form.user_id.data
            user = User.query.filter_by(id=user_id).first()
            if user:
                if User.query.count() > 1: # check if the user being deleted is not the last user in the database
                    if user.id == current_user.id: # check if the user being deleted is the current user
                        db.session.delete(user)
                        logout_user()

                        try:
                            db.session.commit()
                            flash('You have been logged out because your account has been deleted.', 'success')
                        except Exception as e:
                            db.session.rollback()
                            flash(f'An error occurred while deleting the user: {str(e)}', 'danger')
                        return redirect(url_for('auth.logout'))
                    
                    db.session.delete(user)
                    try:
                        db.session.commit()
                        flash('User deleted successfully!', 'success')
                    except Exception as e:
                        db.session.rollback()
                        flash(f'An error occurred while deleting the user: {str(e)}', 'danger')
                else:
                    flash('Cannot delete the last user!', 'danger')
            else:
                flash('User not found!', 'danger')
            return redirect(url_for('auth.users', search_query=search_query, page=paginated_users.page))
        return render_template('users.html', users=paginated_users, delete_form=delete_form, search_query=search_query)
        
    except exc.SQLAlchemyError as e:
        db.session.rollback()
        flash(f'An error occurred while retrieving users: {str(e)}', 'danger')
        return redirect(url_for('auth.dashboard'))

    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while retrieving users: {str(e)}', 'danger')
        return redirect(url_for('auth.dashboard'))


@auth.route('/dashboard/edit_user', methods=['GET', 'POST'])
@login_required
def edit_user():
    form = EditUserForm()
    user_id = None
    user = None
    user_id = request.form.get('user_id')
    if user_id:
        try:
            # Begin a database transaction
            db.session.begin_nested()

            # Acquire an exclusive lock on the User row
            user = User.query.filter_by(id=user_id).with_for_update().one()
        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash(f'An error occurred while retrieving the user: {str(e)}', 'danger')
            return redirect(url_for('auth.users'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while retrieving the user: {str(e)}', 'danger')
            return redirect(url_for('auth.users'))

    else:
        flash('User not found!', 'danger')
        return redirect(url_for('auth.users'))

    if request.method == 'POST' and form.validate_on_submit():
        if user:
            user.email = form.email.data
            password = form.password.data
            user.password = generate_password_hash(password)

            try:
                db.session.commit()
                flash('User edited successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred while editing the user: {str(e)}', 'danger')
            return redirect(url_for('auth.users'))
        else:
            flash('User not found!', 'danger')

    return render_template('edit_user.html', form=form, user=user)


@auth.route('dashboard/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    form = CreateUserForm()

    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        try:
            # Begin a database transaction
            db.session.begin_nested()

            # Acquire an exclusive lock on the User table
            db.session.query(User).with_for_update().all()

            # Check if email is already taken
            user = User.query.filter_by(email=email).first()
            if user:
                flash('Email is already taken!', 'danger')
                return render_template("create_user.html", form=form)

            hashed_password = generate_password_hash(password)
            user = User(email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()

            flash('User created successfully!', 'success')
            return redirect(url_for('auth.dashboard'))

        except exc.SQLAlchemyError as e:
            db.session.rollback()
            flash(f'An error occurred while creating the user: {str(e)}', 'danger')

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the user: {str(e)}', 'danger')

        return redirect(url_for('auth.create_user'))

    return render_template("create_user.html", form=form)
