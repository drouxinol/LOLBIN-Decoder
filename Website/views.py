from flask import Blueprint, render_template, request, flash
from .models import Command, Parameter, Validate
from . import db
import re
import openai
import os
import ast
from requests.exceptions import HTTPError

#openai.api_key = [INSERT OPENAI KEY HERE AND REMOVE THIS LINE FROM COMMENT]

views = Blueprint('views', __name__)

# Quando vamos para a pagina principal, ele deteta e executa a funcao home()
# vai ser um GET REQUEST pq nao estamos a passar informaçoes como passwords ou usernames, nem estamos a fazer updates ou a modificar nada no lado do servidor
@views.route('/', methods=['GET'])
def home():
    search_input = None
    commands = []
    special_chars = ['>', '>>', '|', '<', '<<', '&', '&&']

    if 'Search-input' in request.args:

        search_input = request.args.get('Search-input')

        # tiramos os espaços no inicio e no fim e dividimos o comando em partes para um lista para podermos comparar com a base de dados
        search_input_list = search_input.strip().lower().split()

        for i, part in enumerate(search_input_list):
            if part.startswith('C:\\'):
                search_input_list[i] = os.path.basename(part)

        print(search_input_list)

        # Initialize the current command and flag
        current_command = None
        current_flag = None

        # Iterate over the parts of the command
        for part in search_input_list:

            # Temos de fazer isto porque o reggex nao deteta, ou é mesmo muito complicado, detetar este tipo de caracteres
            if part in special_chars:
                print("Detected command:", part)
                current_command = Command.query.filter_by(name=part).first()
                # Create a dictionary for the command and add it to the list
                command_dict = {
                    'name': current_command.name,
                    'description': current_command.description,
                    'parameters': []
                }
                commands.append(command_dict)
                continue

            for cmd in Command.query.all():
                if re.match(r'\b{}\b'.format(re.escape(cmd.name)), part, re.IGNORECASE):
                    current_command = cmd
                    print("Detected command:", current_command.name)
                    # Create a dictionary for the command and add it to the list
                    command_dict = {
                        'name': current_command.name,
                        'description': current_command.description,
                        'parameters': []
                    }
                    commands.append(command_dict)
                    break
                else:
                    alias_list = ast.literal_eval(cmd.alias)
                    for alias in alias_list:
                        if re.match(r'\b{}\b'.format(re.escape(alias)), part, re.IGNORECASE):
                            current_command = cmd
                            print("Detected command alias:", alias)
                            # Create a dictionary for the command and add it to the list
                            command_dict = {
                                'name': current_command.name,
                                'description': current_command.description,
                                'parameters': []
                            }
                            commands.append(command_dict)
                            break
                    else:
                        continue  # Continue to next command if no alias match is found
                    break  # Exit the loop if an alias match is found and go to the next part of the command-line

            else:
                # If the part is not a command, treat it as a flag for the current command
                if not current_command:
                    print("Unrecognized part: ", part)
                else:
                    # Check if the part is an associated flag for the current command
                    # If the command was found, iterate over its parameters
                    for param in current_command.parameters:
                        # if is_alone is True, assume the parameter is a separate word
                        if param.is_alone:
                            pattern = r'(?<!\w){}(?!\w)'.format(re.escape(param.name))
                        # if is_alone is False, assume the parameter is joined to text
                        else:
                            pattern = r'\S*{}\S*'.format(re.escape(param.name))
                        if part.startswith(('-', '/')) and re.match(pattern, part, re.IGNORECASE):
                            current_flag = param
                            print("Detected parameter:", current_flag.name)
                            # Create a dictionary for each parameter and add it to the command dictionary
                            param_dict = {
                                'name': current_flag.name,
                                'description': current_flag.description,
                                'flag': False
                            }
                            last_position = len(commands) - 1
                            commands[last_position]['parameters'].append(param_dict)
                            break
                    else:
                        print("Unrecognized parameter: " +
                              part + ".\nAsking chatgpt...")
                        # We check if the flag already exists for the same command, to avoid repetition in the "validate" table.
                        existing_param = Validate.query.filter_by(
                            command=current_command.name, parameter=part).first()
                        if existing_param:
                            # Create a dictionary for each parameter and add it to the command dictionary
                            param_dict = {
                                'name': existing_param.parameter,  # nome do parametro que esta na tabela validate
                                # descriçao do parametro que esta na tabela validate
                                'description': existing_param.param_description,
                                'flag': True
                            }
                            last_position = len(commands) - 1
                            commands[last_position]['parameters'].append(param_dict)

                        else:
                            try:
                                if part.startswith('http'):
                                    # Get the index of the current part
                                    current_index = search_input_list.index(part)
                                    # Get the previous part
                                    previous_part = search_input_list[current_index - 1]

                                    # Request suggestion from ChatGPT
                                    prompt = f"Give the description, in the context of offensive cybersecurity, of the purpose of the link '{part}' when it is used with the flag '{previous_part}' and when it is associated the windows {current_command.name} command?"
                                    response = openai.Completion.create(
                                        engine="text-davinci-003",
                                        prompt=prompt,
                                        max_tokens=1024,
                                        n=1,
                                        stop=None,
                                        temperature=0.5,
                                    )

                                elif part.startswith(('-', '/')):
                                    # Request suggestion from ChatGPT
                                    prompt = f"Give the description, in the context of offensive cybersecurity, of the flag '{part}' for the windows {current_command.name} command?"
                                    response = openai.Completion.create(
                                        engine="text-davinci-003",
                                        prompt=prompt,
                                        max_tokens=1024,
                                        n=1,
                                        stop=None,
                                        temperature=0.5,
                                    )
                                else:
                                    # Request suggestion from ChatGPT
                                    prompt = f"Give the description, in the context of offensive cybersecurity, of the '{part}' for the windows {current_command.name} command?"
                                    response = openai.Completion.create(
                                        engine="text-davinci-003",
                                        prompt=prompt,
                                        max_tokens=1024,
                                        n=1,
                                        stop=None,
                                        temperature=0.5,
                                    )
                                if response and response.choices:  # if the gpt response is not empty
                                    suggestion = response.choices[0].text.strip(
                                    )
                                    print("Suggested flag:", suggestion)
                                    current_flag = part
                                    parameter = Parameter(name=part)
                                    validate = Validate(
                                        command=current_command.name, parameter=parameter.name, param_description=suggestion)
                                    db.session.add(validate)
                                    db.session.commit()

                                    # Create a dictionary for each parameter and add it to the command dictionary
                                    param_dict = {
                                        'name': part,
                                        'description': suggestion,
                                        'flag': True
                                    }
                                    last_position = len(commands) - 1
                                    commands[last_position]['parameters'].append(param_dict)

                                else:
                                    print("API returned empty response.")
                                    param_dict = {
                                        'name': part,
                                        'description': 'Unknown',
                                        'flag': True
                                    }
                                    last_position = len(commands) - 1
                                    commands[last_position]['parameters'].append(param_dict)
                            except HTTPError as http_error:
                                if http_error.response.status_code == 404:
                                    print("API returned a 404 error.")
                                    param_dict = {
                                        'name': part,
                                        'description': 'Unknown',
                                        'flag': True
                                    }
                                    last_position = len(commands) - 1
                                    commands[last_position]['parameters'].append(param_dict)
                                else:
                                    print(
                                        "HTTP error occurred during API call:", str(http_error))
                                    param_dict = {
                                        'name': part,
                                        'description': 'Unknown',
                                        'flag': True
                                    }
                                    last_position = len(commands) - 1
                                    commands[last_position]['parameters'].append(param_dict)
                            except Exception as e:
                                print("Error occurred during API call:", str(e))
                                param_dict = {
                                    'name': part,
                                    'description': 'Unknown',
                                    'flag': True
                                }
                                last_position = len(commands) - 1
                                commands[last_position]['parameters'].append(param_dict)
        if not commands and search_input:
            flash('Nenhum comando válido foi encontrado.', 'warning')

    return render_template("home.html", commands=commands, search_input=search_input)
