from wsgiref.simple_server import make_server
from marshmallow import Schema, fields, post_load, ValidationError, validate
import json
import logging
from wsgiref import simple_server

import falcon


class User:
    """
    Base Model for the User, this is the base model for the User. Takes properties of the User which are; First Name, Last Name, Email, Password
    """

    def __init__(self, first_name, last_name, email, password):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password


class UserSchema(Schema):
    """
    This is the Schema for the User. Takes properties of the User which are; First Name, Last Name, Email, Password.
    The schema is used to validate the data coming in from the API.
    The schema inherits from the Schema class. Each property is validated against the schema and is a required field.
    """

    first_name = fields.Str(
        required=True, error_messages={"required": "This is required."}
    )
    last_name = fields.Str(
        required=True, error_messages={"required": "This is required."}
    )
    email = fields.Email(
        required=True, error_messages={"required": "This is required."}
    )
    password = fields.Str(
        required=True,
        error_messages={"required": "This is required."},
        validate=validate.Length(min=8),
    )  # validate.Length(min=8) is a custom validator, which checks if the password is at least 8 characters long

    @post_load
    def make_user(self, data, **kwargs):
        # **data is a dictionary of the data coming in from the API
        return User(**data)


user_schema = UserSchema()  # Initialization of the schema


class StorageEngine:
    """
    This handles the storage of the user, and is used to store the user in the database.
    It handles get and post requests to the API.
    """

    logger = logging.getLogger("users_app." + __name__)

    def add_user(self, user_data):
        # user_data is a dictionary of the data coming in from the API
        new_user = user_schema.load(user_data)
        return new_user.first_name


class StorageError(Exception):
    @staticmethod
    def handle(ex, req, resp, params):
        raise falcon.HTTPInternalServerError()


class RequireJSON:

    """
    Middleware used to validate the JSON coming in from the API. Validates that the incoming request is a JSON encoded request.
    The Middleware also validates that the request is a POST or PUT request and that the content type is JSON.
    """

    def process_request(self, req, resp):
        if not req.client_accepts_json:
            raise falcon.HTTPNotAcceptable(
                description="This API only supports responses encoded as JSON.",
                href="http://docs.examples.com/api/json",
            )

        if req.method in ("POST", "PUT"):
            if "application/json" not in req.content_type:
                raise falcon.HTTPUnsupportedMediaType(
                    title="This API only supports requests encoded as JSON.",
                    href="http://docs.examples.com/api/json",
                )


class JSONTranslator:
    """
    This is the class that handles the transaltion of the body in the request payload. It is used to translate the body of the request payload into a dictionary.
    """

    # req is the request object, resp is the response object. This method is used to translate the body of the request payload into a dictionary.
    def process_request(self, req, resp):
        if req.content_length in (None, 0):
            return

        body = req.stream.read()
        if not body:
            raise falcon.HTTPBadRequest(
                title="Empty request body",
                description="A valid JSON document is required.",
            )

        try:
            req.context.doc = json.loads(body.decode("utf-8"))

        except (ValueError, UnicodeDecodeError):
            description = (
                "Could not decode the request body. The "
                "JSON was incorrect or not encoded as "
                "UTF-8."
            )

            raise falcon.HTTPBadRequest(title="Malformed JSON", description=description)

    # req is the request object, resp is the response object. This method is used to translate the body of the response payload into a JSON.
    def process_response(self, req, resp, resource, req_succeeded):
        if not hasattr(resp.context, "result"):
            return

        resp.text = json.dumps(resp.context.result)


class UserResource:
    """
    Handles the requests to the API. This includes the POST and GET requests.
    """

    def __init__(self, db):  # db is the database model object
        self.db = db
        self.logger = logging.getLogger("users_app." + __name__)

    # req is the request object, resp is the response object. This method is used to handle the POST request.
    def on_post(self, req, resp):

        # Validate the JSON coming in from the API
        try:
            doc = (
                req.context.doc
            )  # doc is the dictionary of the body of the request payload
        except AttributeError as ex:  # AttributeError is raised if the doc attribute is not found in the req.context object
            self.logger.error(ex)
            raise falcon.HTTPBadRequest(
                title="Missing Body",
                description="A valid JSON must be submitted in the request body.",
            )

        # Validate the data coming in from the API
        try:
            # add_user is a method of the StorageEngine class
            self.db.add_user(doc)
            # resp.body is the body of the response payload
            resp.body = json.dumps({})
            # resp.status is the status code of the response, in this case it is 201
            resp.status = falcon.HTTP_201

        # If the data is not valid, then the following error is raised
        except ValidationError as err:  # ValidationError is raised if the data is not valid
            # resp.body is the body of the response payload, in this case it is the error message raised by the validation error from Marshmallow
            resp.body = json.dumps([{"error": "Bad request"}, (err.messages)])
            resp.status = falcon.HTTP_400
            print(err.messages)
            print(err.valid_data)


app = falcon.App(
    middleware=[  # app is the falcon application object
        RequireJSON(),  # RequireJSON is a class that validates the JSON coming in from the API
        JSONTranslator(),  # JSONTranslator is a class that translates the body of the request payload into a dictionary
    ]
)
db = StorageEngine()  # db is the database model object
user_handler = UserResource(db)  # user_handler is the UserResource class

app.add_route("/add_user", user_handler)  # add_user is the route of the API

# If a responder ever raises an instance of StorageError, pass control to
# the given handler.
app.add_error_handler(StorageError, StorageError.handle)


# If the script is run directly, run the application
if __name__ == "__main__":
    httpd = simple_server.make_server("127.0.0.1", 8080, app)
    httpd.serve_forever()
