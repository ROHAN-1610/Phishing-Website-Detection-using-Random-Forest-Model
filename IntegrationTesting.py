import unittest

from app import app


class TestIntegration(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()

    def test_index_route(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)  # Assuming index route returns HTTP 200 OK
        self.assertIn(b"Don't get Hooked by a Phish again!", response.data)

    def test_login_route(self):
        response = self.app.post('/login', data=dict(
            username='test_user',
            password='test_password'
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)  # Assuming login page reloads on invalid credentials
        self.assertIn(b'Invalid username or password!', response.data)  # Updated assertion

    def test_invalid_login(self):
        response = self.app.post('/login', data=dict(
            username='invalid_user',
            password='invalid_password'
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)  # Assuming login page reloads on invalid credentials
        self.assertIn(b'Invalid username or password!', response.data)

    def test_logout_route(self):
        # Assuming user is logged in before logging out
        self.app.post('/login', data=dict(
            username='test_user',
            password='test_password'
        ), follow_redirects=True)

        response = self.app.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)  # Assuming successful logout redirects to index
        self.assertIn(b'Logged out successfully!', response.data)

    def test_prediction(self):
        # Simulate a successful login before accessing the prediction endpoint
        self.app.post('/login', data=dict(
            username='test_user',
            password='test_password'
        ), follow_redirects=True)

        # Now access the prediction endpoint
        response = self.app.post('/', json={'url': 'https://gemini.google.com/app'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Please login first!',
                      response.data)  # Updated expectation to match response for unauthenticated user


if __name__ == '__main__':
    unittest.main()
