from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    serialize_rules = ('-recipes.user', '-_password_hash',)

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', backref='user')

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f'<User {self.username}>'
class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        if not username or not password:
            return {"error": "Username and password are required"}, 422

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {"error": "Username already exists"}, 422

        new_user = User(username=username, image_url=image_url, bio=bio)
        new_user.password_hash = password
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id

        return {
            "id": new_user.id,
            "username": new_user.username,
            "image_url": new_user.image_url,
            "bio": new_user.bio
        }, 201

api.add_resource(Signup, '/signup')

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    __table_args__ = (
        db.CheckConstraint('length(instructions) >= 50'),
    )

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<Recipe {self.id}: {self.title}>'