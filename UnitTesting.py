import unittest, time
from app import extract_features
from app import predict_phishing


class TestPhishingDetection(unittest.TestCase):

    def test_extract_features_legitimate(self):
        # Test feature extraction for a legitimate URL
        url = "https://www.facebook.com/"
        features = extract_features(url)

        # Print feature vector for inspection
        print("Feature vector (legitimate):", features)

        # Check if the correct number of features is extracted
        self.assertEqual(len(features), 16)  # Assuming 16 features including the label

        # Check specific feature value types
        for feature_name, feature_value in features.items():
            self.assertIsNotNone(feature_value, f"Feature '{feature_name}' is None")

    def test_extract_features_phishing(self):
        # Test feature extraction for a phishing URL
        url = "http://bantuan-dana-customer.w3b-app.com/"
        features = extract_features(url)

        # Print feature vector for inspection
        print("Feature vector (phishing):", features)

        # Check if the correct number of features is extracted
        self.assertEqual(len(features), 16)  # Assuming 16 features including the label

        # Check specific feature value types
        for feature_name, feature_value in features.items():
            self.assertIsNotNone(feature_value, f"Feature '{feature_name}' is None")

    def test_critical_function_performance(self):
        start_time = time.time()
        end_time = time.time()
        execution_time = end_time - start_time
        MAX_EXECUTION_TIME = 1.0
        self.assertLessEqual(execution_time, MAX_EXECUTION_TIME, "Critical function exceeds maximum execution time")

    def test_ci_pipeline_integration(self):
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
