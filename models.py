from app import app, db

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(100), unique=True, nullable=False)
    passhash=db.Column(db.String(256), nullable=False)
    name=db.Column(db.String(60),nullable=True)
    is_admin=db.Column(db.Boolean, nullable=False, default=False)

class Category(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(100), unique=True, nullable=False)
    # Relationship
    products=db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(100), unique=True, nullable=False)
    description=db.Column(db.Text, nullable=True)
    price=db.Column(db.Float, nullable=False)
    stockQty=db.Column(db.Integer, nullable=False)
    # Foreign key
    category_id=db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    # Relationship
    category=db.relationship('Category', backref='product', lazy=True)
    order=db.relationship('Order', backref='product', lazy=True)


class Cart(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id=db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity=db.Column(db.Integer, nullable=False)
    # Relationship
    user=db.relationship('User', backref='cart', lazy=True)
    product=db.relationship('Product', backref='cart', lazy=True)

class Transaction(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    datetime=db.Column(db.DateTime, nullable=False)
    # Relationship
    orders=db.relationship('Order', backref='transaction', lazy=True)

class Order(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    transaction_id=db.Column(db.Integer, db.ForeignKey('transaction.id'), nullable=False)
    product_id=db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity=db.Column(db.Integer, nullable=False)
    price=db.Column(db.Float, nullable=False)
    # Relationship
    transaction=db.relationship('Transaction', backref='order', lazy=True)
    product=db.relationship('Product', backref='order', lazy=True)


with app.app_context():
    db.create_all()
