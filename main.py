import datetime
from flask import Flask, request, jsonify
from flask_restful import Resource, Api, abort
from flask_httpauth import HTTPBasicAuth
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
import json


app = Flask(__name__)
api = Api(app)
auth = HTTPBasicAuth()
app.secret_key = 'your-secret-key'  # Add this line
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # replace with your secret key
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
jwt = JWTManager(app)

blacklist = set()



# Define the home route
@app.route('/')
def home_route():
    # Returns a list of available routes in HTML format
    return """
    <h1>Route</h1>
    <ul>
        <li><a href="/user">Users</a></li>
        <li><a href="/curhat">Curhats</a></li>
        <li><a href="/comment">Comments</a></li>
        <li><a href="/project">Projects</a></li>
        <li><a href="/projectupdate">Project Updates</a></li>
    </ul>
    """
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
            for user in users:
                if user['username'] == username:
                    if check_password_hash(user['password'], password):
                        access_token = create_access_token(identity=username)
                        return jsonify(access_token=access_token, userid=user['userid']), 200
    except FileNotFoundError:
        return jsonify({"msg": "User not found"}), 401

    return jsonify({"msg": "Bad username or password"}), 401

@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify({'msg': 'You are accessing a protected route'}), 200

@app.route('/current_user', methods=['GET'])
@jwt_required()
def get_current_user():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Define the User resource
class User(Resource):

    # Define the GET method
    def get(self, user_id=None, search=None):
        # Tries to open and load the users.json file
        try:
            with open('users.json', 'r') as f:
                users = json.load(f)
        # If the file is not found, aborts with a 404 error
        except FileNotFoundError:
            abort(404, description="File not found")

        # If a search query is provided, filters the users by username
        if search:
            users = [user for user in users if search.lower() in user['username'].lower()]

        # If no user_id is provided, returns all users
        if user_id is None:
            return users, 200
        # If a user_id is provided, returns the corresponding user
        else:
            for user in users:
                if user['userid'] == user_id:
                    return user, 200
            # If no user is found with the provided user_id, aborts with a 404 error
            abort(404, description="User not found")

    # Define the POST method
    def post(self):
        # Tries to get the JSON data from the request
        try:
            user_data = request.get_json()
            # Hash the password
            hashed_password = generate_password_hash(user_data['password'])
            # Tries to open and load the users.json file
            try:
                with open('users.json', 'r+') as f:
                    users = json.load(f)
            # If the file is not found, creates a new empty list of users
            except FileNotFoundError:
                users = []
                with open('users.json', 'w') as f:
                    json.dump(users, f)
            # If the list of users is not empty, gets the last user id and increments it by 1
            if users:
                last_user_id = int(users[-1]['userid'])
                new_user_id = str(last_user_id + 1)
            # If the list of users is empty, starts with '1'
            else:
                new_user_id = '1'
            # Creates a new user with the provided data and the new user id
            new_user = {
                'userid': new_user_id,
                'username': user_data['username'],
                'email': user_data['email'],
                'roles': user_data['roles'],
                'password': hashed_password,  # Store the hashed password
                'profile_picture': user_data['profile_picture'],
                'bio_text': user_data['bio_text'],
                'phone_number': user_data['phone_number'],
                'faculty': user_data['faculty']
            }
            # Adds the new user to the list of users
            users.append(new_user)
            # Writes the updated list of users to the users.json file
            with open('users.json', 'w') as f:
                json.dump(users, f)
            # Returns the new user with a 201 status code
            return new_user, 201
        # If an exception occurs, aborts with a 500 error
        except Exception as e:
            abort(500, description=str(e))

    # Define the PUT method
    def put(self, user_id):
        # Tries to get the JSON data from the request
        try:
            user_data = request.get_json()
            # Tries to open and load the users.json file
            with open('users.json', 'r+') as f:
                users = json.load(f)
                # Iterates over the list of users
                for i, user in enumerate(users):
                    # If the user id matches the provided user id, updates the user data
                    if user['userid'] == user_id:
                        users[i] = user_data
                        # Writes the updated list of users to the users.json file
                        f.seek(0)
                        json.dump(users, f)
                        # Returns the updated user data with a 200 status code
                        return user_data, 200
                # If no user is found with the provided user id, aborts with a 404 error
                abort(404, description="User not found")
        # If an exception occurs, aborts with a 500 error
        except Exception as e:
            abort(500, description=str(e))

    # Define the DELETE method
    def delete(self, user_id):
        # Tries to open and load the users.json file
        try:
            with open('users.json', 'r+') as f:
                users = json.load(f)
                # Iterates over the list of users
                for i, user in enumerate(users):
                    # If the user id matches the provided user id, deletes the user
                    if user['userid'] == user_id:
                        users.pop(i)
                        # Writes the updated list of users to the users.json file
                        f.seek(0)
                        f.truncate()
                        json.dump(users, f)
                        # Returns a success message with a 200 status code
                        return jsonify({"message": "User is deleted."}), 200
                # If no user is found with the provided user id, aborts with a 404 error
                abort(404, description="User not found")
        # If an exception occurs, aborts with a 500 error
        except Exception as e:
            abort(500, description=str(e))

# Add the User resource to the API
api.add_resource(User, '/user', '/user/<user_id>')


class Curhat(Resource):
    def get(self, curhat_id=None, search=None, page=1, per_page=5):
        try:
            with open('curhats.json', 'r') as f:
                curhats = json.load(f)
        except FileNotFoundError:
            abort(404, description="File not found")

        if search:
            curhats = [curhat for curhat in curhats if search.lower() in curhat['text'].lower()]

        # Sort curhats by date and time in descending order
        curhats = sorted(curhats, key=lambda x: (x['date'], x['time']), reverse=True)

        if curhat_id is None:
            # Implement pagination
            start = (page - 1) * per_page
            end = start + per_page
            return curhats[start:end], 200
        else:
            for curhat in curhats:
                if curhat['curhatid'] == curhat_id:
                    return curhat, 200
            abort(404, description="Curhat not found")

    def post(self):
        try:
            curhat_data = request.get_json()
            if 'userid' not in curhat_data:
                return {'message': 'User ID is required'}, 400
            if 'text' not in curhat_data:
                return {'message': 'Text is required'}, 400

            curhat_data = request.get_json()
            try:
                with open('curhats.json', 'r+') as f:
                    curhats = json.load(f)
            except FileNotFoundError:
                curhats = []
                with open('curhats.json', 'w') as f:
                    json.dump(curhats, f)
            if curhats:  # check if curhats list is not empty
                last_curhat_id = int(curhats[-1]['curhatid'])  # get the last curhat id
                new_curhat_id = str(last_curhat_id + 1)  # increment the last curhat id by 1
            else:
                new_curhat_id = '1'  # if curhats list is empty, start with '1'

            new_curhat = {
                'curhatid': new_curhat_id,
                'userid': curhat_data['userid'],
                'text': curhat_data['text'],
                'attachment': curhat_data['attachment'],
                'date': curhat_data['date'],
                'time': curhat_data['time']
            }
            curhats.append(new_curhat)
            with open('curhats.json', 'w') as f:
                f.seek(0)
                json.dump(curhats, f)
            return new_curhat, 201
        except Exception as e:
            abort(500, description=str(e))

    def put(self, curhat_id):
        try:
            curhat_data = request.get_json()
            with open('curhats.json', 'r+') as f:
                curhats = json.load(f)
                for i, curhat in enumerate(curhats):
                    if curhat['curhatid'] == curhat_id:
                        curhats[i] = curhat_data
                        f.seek(0)
                        json.dump(curhats, f)
                        return curhat_data, 200
                abort(404, description="Curhat not found")
        except Exception as e:
            abort(500, description=str(e))

    import json
    from flask import jsonify, abort

    def delete(self, curhat_id):
        try:
            # Open the file in read mode and load the data
            with open('curhats.json', 'r') as f:
                curhats = json.load(f)

            # Create a new list without the item to be deleted
            updated_curhats = [curhat for curhat in curhats if curhat.get('curhatid') != curhat_id]

            if len(updated_curhats) == len(curhats):
                # If the ID was not found, return a 404 response
                abort(404, description=f"Curhat with ID {curhat_id} not found.")

            # Open the file in write mode and dump the updated data back into the file
            with open('curhats.json', 'w') as f:
                if updated_curhats:
                    json.dump(updated_curhats, f, indent=4)
                else:
                    f.write("[]")  # Write an empty list if no curhats are left

            return jsonify({"message": "Curhat is deleted."}), 200

        except FileNotFoundError:
            # Handle the case where the file doesn't exist
            abort(404, description="Curhats file not found.")

        except json.JSONDecodeError:
            # Handle the case where the file has invalid JSON
            abort(500, description="Invalid JSON format in curhats file.")

        except Exception as e:
            # Log the exception for debugging purposes
            print(f"An error occurred: {str(e)}")
            abort(500, description="Internal Server Error.")


api.add_resource(Curhat, '/curhat', '/curhat/<curhat_id>')


class Comment(Resource):
    def get(self, comment_id=None, search=None, curhatid=None):
        try:
            with open('comments.json', 'r') as f:
                comments = json.load(f)
        except FileNotFoundError:
            abort(404, description="File not found")

        if search:
            comments = [comment for comment in comments if search.lower() in comment['text'].lower()]

        if curhatid is not None:
            comments = [comment for comment in comments if comment['curhatid'] == curhatid]

        if comment_id is None:
            return comments, 200
        else:
            for comment in comments:
                if comment['commentid'] == comment_id:
                    return comment, 200
            abort(404, description="Comment not found")

    def post(self):
        try:
            comment_data = request.get_json()
            if 'userid' not in comment_data:
                return {'message': 'User ID is required'}, 400
            if 'text' not in comment_data:
                return {'message': 'Text is required'}, 400
            if 'curhatid' not in comment_data:
                return {'message': 'Curhat ID is required'}, 400

            try:
                with open('comments.json', 'r+') as f:
                    comments = json.load(f)
            except FileNotFoundError:
                comments = []
                with open('comments.json', 'w') as f:
                    json.dump(comments, f)
            if comments:  # check if comments list is not empty
                last_comment_id = int(comments[-1]['commentid'])  # get the last comment id
                new_comment_id = str(last_comment_id + 1)  # increment the last comment id by 1
            else:
                new_comment_id = '1'  # if comments list is empty, start with '1'
            new_comment = {
                'commentid': new_comment_id,
                'userid': comment_data['userid'],
                'text': comment_data['text'],
                'attachment': comment_data['attachment'],
                'curhatid': comment_data['curhatid'],
                'date': comment_data['date'],
                'time': comment_data['time']

            }
            comments.append(new_comment)
            with open('comments.json', 'w') as f:
                f.seek(0)  # seek to the beginning of the file
                json.dump(comments, f)
            return new_comment, 201
        except Exception as e:
            abort(500, description=str(e))

    def put(self, comment_id):
        try:
            comment_data = request.get_json()
            with open('comments.json', 'r+') as f:
                comments = json.load(f)
                for i, comment in enumerate(comments):
                    if comment['commentid'] == comment_id:
                        comments[i] = comment_data
                        f.seek(0)
                        json.dump(comments, f)
                        return comment_data, 200
                abort(404, description="Comment not found")
        except Exception as e:
            abort(500, description=str(e))

    def delete(self, comment_id):
        try:
            with open('comments.json', 'r+') as f:
                comments = json.load(f)
                for i, comment in enumerate(comments):
                    if comment['commentid'] == comment_id:
                        comments.pop(i)
                        f.seek(0)
                        f.truncate()
                        json.dump(comments, f)
                        return jsonify({"message": "Comment is deleted."}), 200
                abort(404, description="Comment not found")
        except Exception as e:
            abort(500, description=str(e))


api.add_resource(Comment, '/comment', '/comment/<comment_id>')


class Project(Resource):

    def get(self, project_id=None, search=None, page=1, per_page=5):
        try:
            with open('projects.json', 'r') as f:
                projects = json.load(f)
        except FileNotFoundError:
            abort(404, description="File not found")

        if search:
            projects = [project for project in projects if search.lower() in project['project_bio'].lower()]

        if project_id is None:
            # Implement pagination
            start = (page - 1) * per_page
            end = start + per_page
            return projects[start:end], 200
        else:
            for project in projects:
                if project['projectid'] == project_id:
                    return project, 200
            abort(404, description="Project not found")

    def post(self):
        try:
            project_data = request.get_json()
            try:
                with open('projects.json', 'r+') as f:
                    projects = json.load(f)
            except FileNotFoundError:
                projects = []
                with open('projects.json', 'w') as f:
                    json.dump(projects, f)
            if projects:  # check if projects list is not empty
                last_project_id = int(projects[-1]['projectid'])  # get the last project id
                new_project_id = str(last_project_id + 1)  # increment the last project id by 1
            else:
                new_project_id = '1'  # if projects list is empty, start with '1'
            new_project = {
                'projectid': new_project_id,
                'project_profile_picture': project_data['project_profile_picture'],
                'project_picture': project_data['project_picture'],
                'project_bio': project_data['project_bio'],
                'author': project_data['author'],
                'contributor': project_data['contributor'],
                'date_created': project_data['date_created'],
                'time': project_data['time']
            }
            projects.append(new_project)
            with open('projects.json', 'w') as f:
                json.dump(projects, f)
            return new_project, 201
        except Exception as e:
            abort(500, description=str(e))

    def put(self, project_id):
        try:
            project_data = request.get_json()
            with open('projects.json', 'r+') as f:
                projects = json.load(f)
                for i, project in enumerate(projects):
                    if project['projectid'] == project_id:
                        projects[i] = project_data
                        f.seek(0)
                        json.dump(projects, f)
                        return project_data, 200
                abort(404, description="Project not found")
        except Exception as e:
            abort(500, description=str(e))

    def delete(self, project_id):
        try:
            with open('projects.json', 'r+') as f:
                projects = json.load(f)
                for i, project in enumerate(projects):
                    if project['projectid'] == project_id:
                        projects.pop(i)
                        f.seek(0)
                        f.truncate()
                        json.dump(projects, f)
                        return jsonify({"message": "Project is deleted."}), 200
                abort(404, description="Project not found")
        except Exception as e:
            abort(500, description=str(e))


api.add_resource(Project, '/project', '/project/<project_id>')


class ProjectUpdate(Resource):

    def get(self, project_update_id=None, search=None):
        try:
            with open('project_updates.json', 'r') as f:
                project_updates = json.load(f)
        except FileNotFoundError:
            abort(404, description="File not found")

        if search:
            project_updates = [project_update for project_update in project_updates if
                               search.lower() in project_update['description'].lower()]

        if project_update_id is None:
            return project_updates, 200
        else:
            for project_update in project_updates:
                if project_update['projectupdateid'] == project_update_id:
                    return project_update, 200
            abort(404, description="Project update not found")

    def post(self):
        try:
            project_update_data = request.get_json()
            try:
                with open('project_updates.json', 'r+') as f:
                    project_updates = json.load(f)
            except FileNotFoundError:
                project_updates = []
                with open('project_updates.json', 'w') as f:
                    json.dump(project_updates, f)
            if project_updates:  # check if project_updates list is not empty
                last_project_update_id = int(project_updates[-1]['projectupdateid'])  # get the last project update id
                new_project_update_id = str(last_project_update_id + 1)  # increment the last project update id by 1
            else:
                new_project_update_id = '1'  # if project_updates list is empty, start with '1'
            new_project_update = {
                'projectupdateid': new_project_update_id,
                'description': project_update_data['description'],
                'attachment_link': project_update_data['attachment_link'],
                'projectid': project_update_data['projectid'],
                'date': project_update_data['date'],
                'time': project_update_data['time']
            }
            project_updates.append(new_project_update)
            with open('project_updates.json', 'w') as f:
                json.dump(project_updates, f)
            return new_project_update, 201
        except Exception as e:
            abort(500, description=str(e))

    def put(self, project_update_id):
        try:
            project_update_data = request.get_json()
            with open('project_updates.json', 'r+') as f:
                project_updates = json.load(f)
                for i, project_update in enumerate(project_updates):
                    if project_update['projectupdateid'] == project_update_id:
                        project_updates[i] = project_update_data
                        f.seek(0)
                        json.dump(project_updates, f)
                        return jsonify(project_update_data), 200
                abort(404, description="Project update not found")
        except Exception as e:
            abort(500, description=str(e))

    def delete(self, project_update_id):
        try:
            with open('project_updates.json', 'r+') as f:
                project_updates = json.load(f)
                for i, project_update in enumerate(project_updates):
                    if project_update['projectupdateid'] == project_update_id:
                        project_updates.pop(i)
                        f.seek(0)
                        f.truncate()
                        json.dump(project_updates, f)
                        return jsonify({"message": "Project update is deleted."}), 200
                abort(404, description="Project update not found")
        except Exception as e:
            abort(500, description=str(e))


api.add_resource(ProjectUpdate, '/projectupdate', '/projectupdate/<project_update_id>')

if __name__ == '__main__':
    app.run(debug=True)
