from mongoengine import Document, EmailField, StringField, IntField
from flask_bcrypt import generate_password_hash, check_password_hash
import string, random
"""
class RevokedToken(Document):
    id = IntField(required=True, unique=True)
    jti = StringField()
    @classmethod
    def is_jti_blacklisted(cls, jti):
        return bool(cls.is_jti_blacklisted)

"""

class User(Document):
    email = EmailField(required=True, unique=True)
    password = StringField(required=True, min_length=6)
    salt = StringField()

    def hash_password(self):
        chars = string.ascii_letters + string.punctuation
        size = 12
        self.salt = ''.join(random.choice(chars) for x in range(size))
        self.password = generate_password_hash(self.password + self.salt).decode('utf8')

    def check_password(self, password):
        return check_password_hash(self.password, password + self.salt)

    def serialize(self):
        return {
            'id': str(self.id),
            'email': self.email
        }
