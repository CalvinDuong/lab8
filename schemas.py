from marshmallow import Schema, fields

class UserRegisterSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    quote = fields.Str(required=True)
    
class UserLoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)

class UserTokenSchema(Schema):
    access_token = fields.Str()
    refresh_token = fields.Str()

