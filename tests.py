import unittest
from app import app, db, User, Feedback

class TestApp(unittest.TestCase):

    def setUp(self):
        """Set up test environment."""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        self.app = app.test_client()
        db.create_all()

    def tearDown(self):
        """Tear down test environment."""
        db.session.remove()
        db.drop_all()

    def test_homepage(self):
        """Test homepage route."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Show homepage', response.data)

    def test_register(self):
        """Test user registration."""
        response = self.app.post('/register', data=dict(
            username='test_user',
            password='password123',
            email='test@example.com',
            first_name='Test',
            last_name='User'
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'User created successfully', response.data)

    def test_login(self):
        """Test user login."""
        user = User(username='test_user', password='password123')
        db.session.add(user)
        db.session.commit()

        response = self.app.post('/login', data=dict(
            username='test_user',
            password='password123'
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login successful', response.data)

    def test_user_profile(self):
        """Test user profile route."""
        user = User(username='test_user', password='password123')
        db.session.add(user)
        db.session.commit()

        response = self.app.get('/users/test_user')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Display user profile', response.data)

    def test_logout(self):
        """Test user logout."""
        with self.app as client:
            with client.session_transaction() as sess:
                sess['username'] = 'test_user'

            response = client.get('/logout', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'You have been logged out', response.data)

if __name__ == '__main__':
    unittest.main()
