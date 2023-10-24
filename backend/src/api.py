import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)



#db_drop_and_create_all()

# ROUTES

@app.route('/drinks', methods=['GET'])
def get_drinks():
    try:
        # Query all drinks from the database
        drinks = Drink.query.all()

        # Extract short representation of drinks
        drinks_short = [drink.short() for drink in drinks]

        # Return success response with status code 200
        return jsonify({
            'success': True,
            'drinks': drinks_short
        })
    except Exception as e:
        # If an exception occurs, abort with a 404 error
        abort(404, description=f"Resource not found: {str(e)}")


@app.route("/drinks-detail", methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drink_detail(jwt):
    try:
        # Query all drinks from the database
        drinks = Drink.query.all()

        # Extract long representation of drinks
        drinks_long = [drink.long() for drink in drinks]

        return jsonify({
            'success': True,
            'drinks': drinks_long
        })
    except Exception as e:
        # If an exception occurs, abort with a 404 error
        abort(404, description=f"Resource not found: {str(e)}")


@app.route("/drinks", methods=['POST'])
@requires_auth('post:drinks')
def add_drink(jwt):
    try:
        # Get JSON data from the request body
        body = request.get_json()

        # Check if required fields are present in the request body
        if not ('title' in body and 'recipe' in body):
            abort(422)

        title = body.get('title')
        recipe = body.get('recipe')

        # Create a new Drink instance and insert it into the database
        drink = Drink(title=title, recipe=json.dumps(recipe))
        drink.insert()

        # Return success response with status code 200
        return jsonify({
            'success': True,
            'drinks': [drink.long()],
        })

    except Exception as e:
        # If an exception occurs, abort with a 422 error
        abort(422, description=f"Unprocessable entity: {str(e)}")


@app.route("/drinks/<int:id>", methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(jwt, id):
    try:
        # Query the drink from the database by ID
        drink = Drink.query.get(id)

        # Check if the drink exists
        if not drink:
            abort(404, description="Drink not found")

        # Get JSON data from the request body
        body = request.get_json()

        title = body.get('title')
        recipe = body.get('recipe')

        # Update drink attributes if provided in the request body
        if title:
            drink.title = title
        if recipe:
            drink.recipe = json.dumps(recipe)

        # Update the drink in the database
        drink.update()

        # Return success response with status code 200
        return jsonify({
            'success': True,
            'drinks': [drink.long()]
        })
    except Exception as e:
        # If an exception occurs, abort with a 422 error
        abort(422, description=f"Unprocessable entity: {str(e)}")


@app.route("/drinks/<int:id>", methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(jwt, id):
    try:
        # Query the drink from the database by ID
        drink = Drink.query.get(id)

        # Check if the drink exists
        if not drink:
            abort(404, description="Drink not found")

        # Delete the drink from the database
        drink.delete()

        return jsonify({
            'success': True,
            'delete': id
        })
    except Exception as e:
        abort(422, description=f"Unprocessable entity: {str(e)}")


# Error Handling

@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404


@app.errorhandler(AuthError)
def handle_auth_error(ae):
    return jsonify({
        "success": False,
        "error": ae.status_code,
        'message': ae.error
    }), 401