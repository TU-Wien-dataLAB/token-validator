from validator import create_app
from validator.extensions import db

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8000, debug=False)
