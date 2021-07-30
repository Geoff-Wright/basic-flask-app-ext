from .db import db
from flask_bcrypt import generate_password_hash, check_password_hash
import string, random

class User(db.Document):
	email = db.EmailField(required=True, unique=True)
	password = db.StringField(required=True, min_length=6)
	salt = db.StringField()
	
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