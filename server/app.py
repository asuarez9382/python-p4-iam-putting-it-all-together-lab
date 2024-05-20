#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        
        request_json= request.get_json()

        # Save a new user to the database with their username, encrypted password, image URL, and bio.
        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')

        user = User(
            username=username,
            image_url = image_url,
            bio=bio)

        user.password_hash = password

        # Save the user's ID in the session object as user_id.
        # breakpoint()
        try:
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id
            # Return a JSON response with the user's ID, username, image URL, and bio; and an HTTP status code of 201 (Created).
            return user.to_dict(), 201
        # Return a JSON response with the error message, and an HTTP status code of 422 (Unprocessable Entity).
        except IntegrityError:
            return {'error': '422 Unprocessable Entity'}, 422
        

class CheckSession(Resource):
    
    def get(self):
        user = User.query.filter(User.id == session['user_id']).first()
        if user:
            return user.to_dict(), 200
        else:
            return {'message': '401: Not Authorized'}, 401

class Login(Resource):
    
    def post(self):
        
        request_json = request.get_json()
        
        username = request_json.get('username')
        password = request_json.get('password')
        
        user = User.query.filter(User.username == username).first()
        
        if user:
            if user.authenticate(password):
                session['user_id'] = user.id
                return user.to_dict(), 200
        else:
            return {'error':'401 Unauthorized'}, 401

class Logout(Resource):
    
    def delete(self):
        
        if session.get('user_id'):
            
            session['user_id'] = None
            
            return {}, 204
        
        return {'error': '401 Unauthorized'}, 401

class RecipeIndex(Resource):
    
    def get(self):

        if session.get('user_id'):

            user = User.query.filter(User.id == session['user_id']).first()

            return [recipe.to_dict() for recipe in user.recipes], 200
        
        return {'error': '401 Unauthorized'}, 401
    
    def post(self):

        if session.get('user_id'):

            request_json = request.get_json()

            title = request_json['title']
            instructions = request_json['instructions']
            minutes_to_complete = request_json['minutes_to_complete']

            try:

                recipe = Recipe(
                    title=title,
                    instructions=instructions,
                    minutes_to_complete=minutes_to_complete,
                    user_id=session['user_id'],
                )

                db.session.add(recipe)
                db.session.commit()

                return recipe.to_dict(), 201

            except IntegrityError:

                return {'error': '422 Unprocessable Entity'}, 422

        return {'error': '401 Unauthorized'}, 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)