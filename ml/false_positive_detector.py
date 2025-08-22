import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class FalsePositiveDetector:
    def __init__(self, model_path: str = 'models/fp_detector.pkl'):
        self.model_path = model_path
        self.vectorizer_path = 'models/text_vectorizer.pkl'
        self.model = None
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        self.is_trained = False
        
        # Load existing model if available
        self.load_model()
        
    def extract_features(self, vulnerability_data: Dict) -> Dict[str, Any]:
        """Extract features from vulnerability data for ML model"""
        features = {}
        
        # Response characteristics
        response_content = vulnerability_data.get('response_content', '')
        features['response_length'] = len(response_content)
        features['response_lines'] = response_content.count('\n')
        
        # Status code features
        status_code = vulnerability_data.get('status_code', 200)
        features['status_code'] = status_code
        features['is_error_status'] = 1 if status_code >= 400 else 0
        features['is_server_error'] = 1 if status_code >= 500 else 0
        
        # Vulnerability characteristics
        features['confidence_score'] = vulnerability_data.get('confidence', 0.5)
        features['payload_length'] = len(vulnerability_data.get('payload', ''))
        
        # Content analysis
        content_lower = response_content.lower()
        features['has_error_keywords'] = 1 if any(keyword in content_lower for keyword in 
                                                  ['error', 'exception', 'warning', 'debug', 'stack trace']) else 0
        features['has_db_keywords'] = 1 if any(keyword in content_lower for keyword in 
                                               ['mysql', 'postgresql', 'sql', 'database', 'oracle']) else 0
        features['has_script_tags'] = 1 if any(tag in content_lower for tag in 
                                               ['<script', 'javascript:', 'onerror=', 'onload=']) else 0
        
        # Endpoint characteristics
        endpoint = vulnerability_data.get('endpoint', '')
        features['endpoint_length'] = len(endpoint)
        features['has_parameters'] = 1 if '?' in endpoint else 0
        features['path_depth'] = endpoint.count('/')
        features['looks_like_api'] = 1 if '/api/' in endpoint.lower() else 0
        
        # Response time (if available)
        features['response_time'] = vulnerability_data.get('response_time', 0)
        features['is_slow_response'] = 1 if features['response_time'] > 5.0 else 0
        
        return features
    
    def create_training_data(self) -> pd.DataFrame:
        """Create synthetic training data for false positive detection"""
        # This creates realistic training data based on common patterns
        training_samples = []
        
        # True positives - real vulnerabilities
        true_positives = [
            # SQL Injection true positives
            {
                'response_content': "mysql_fetch_array(): supplied argument is not a valid MySQL result resource",
                'status_code': 500,
                'confidence': 0.95,
                'payload': "' OR 1=1--",
                'endpoint': "/login.php?user=admin",
                'vulnerability_type': 'SQL Injection',
                'response_time': 0.5,
                'is_false_positive': 0
            },
            {
                'response_content': "ORA-00942: table or view does not exist",
                'status_code': 500,
                'confidence': 0.90,
                'payload': "'; DROP TABLE users; --",
                'endpoint': "/search?q=test",
                'vulnerability_type': 'SQL Injection',
                'response_time': 0.3,
                'is_false_positive': 0
            },
            # XSS true positives
            {
                'response_content': "<script>alert('XSS')</script> was found in the response",
                'status_code': 200,
                'confidence': 0.95,
                'payload': "<script>alert('XSS')</script>",
                'endpoint': "/comment.php?text=hello",
                'vulnerability_type': 'XSS',
                'response_time': 0.2,
                'is_false_positive': 0
            },
            # Command injection true positives
            {
                'response_content': "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
                'status_code': 200,
                'confidence': 0.90,
                'payload': "; id",
                'endpoint': "/ping.php?host=google.com",
                'vulnerability_type': 'Command Injection',
                'response_time': 0.8,
                'is_false_positive': 0
            }
        ]
        
        # False positives - benign responses that look suspicious
        false_positives = [
            # Legitimate error messages that contain SQL keywords
            {
                'response_content': "Invalid input format. Please check your MySQL connection string in the documentation.",
                'status_code': 400,
                'confidence': 0.60,
                'payload': "' OR 1=1--",
                'endpoint': "/api/config",
                'vulnerability_type': 'SQL Injection',
                'response_time': 0.1,
                'is_false_positive': 1
            },
            {
                'response_content': "Error: The requested resource could not be found. This is a PostgreSQL tutorial page.",
                'status_code': 404,
                'confidence': 0.55,
                'payload': "'; DROP TABLE users; --",
                'endpoint': "/help/database-tutorial",
                'vulnerability_type': 'SQL Injection',
                'response_time': 0.05,
                'is_false_positive': 1
            },
            # Content that contains script tags but is harmless
            {
                'response_content': "Learn JavaScript: <script src='tutorial.js'></script> is used to include external scripts",
                'status_code': 200,
                'confidence': 0.70,
                'payload': "<script>alert('XSS')</script>",
                'endpoint': "/tutorial/javascript",
                'vulnerability_type': 'XSS',
                'response_time': 0.1,
                'is_false_positive': 1
            },
            # Security headers missing on non-sensitive endpoints
            {
                'response_content': "Welcome to our API documentation. Version 1.0",
                'status_code': 200,
                'confidence': 1.0,
                'payload': "N/A",
                'endpoint': "/docs",
                'vulnerability_type': 'Missing Security Headers',
                'response_time': 0.05,
                'is_false_positive': 1
            }
        ]
        
        # Combine and expand the datasets
        all_samples = true_positives + false_positives
        
        # Create variations of each sample
        expanded_samples = []
        for sample in all_samples:
            expanded_samples.append(sample)
            
            # Create variations with different confidence scores
            for conf_variation in [0.1, 0.2, 0.3]:
                variant = sample.copy()
                variant['confidence'] = max(0.1, sample['confidence'] - conf_variation)
                expanded_samples.append(variant)
        
        return pd.DataFrame(expanded_samples)
    
    def train_model(self, force_retrain: bool = False):
        """Train the false positive detection model"""
        if self.is_trained and not force_retrain:
            logger.info("Model already trained. Use force_retrain=True to retrain.")
            return
            
        logger.info("Training false positive detection model...")
        
        # Create training data
        training_df = self.create_training_data()
        logger.info(f"Created {len(training_df)} training samples")
        
        # Extract features
        feature_data = []
        text_data = []
        
        for _, row in training_df.iterrows():
            features = self.extract_features(row.to_dict())
            feature_data.append(features)
            text_data.append(row['response_content'])
        
        # Convert to DataFrame
        features_df = pd.DataFrame(feature_data)
        
        # Vectorize text data
        text_vectors = self.vectorizer.fit_transform(text_data).toarray()
        
        # Combine features
        X = np.column_stack([features_df.values, text_vectors])
        y = training_df['is_false_positive'].values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"Model trained with accuracy: {accuracy:.3f}")
        logger.info("\nClassification Report:")
        logger.info(f"\n{classification_report(y_test, y_pred)}")
        
        # Save model
        self.save_model()
        self.is_trained = True
    
    def predict_false_positive(self, vulnerability_data: Dict) -> float:
        """Predict probability that a vulnerability is a false positive"""
        if not self.is_trained:
            logger.warning("Model not trained. Training now...")
            self.train_model()
        
        # Extract features
        features = self.extract_features(vulnerability_data)
        text_content = vulnerability_data.get('response_content', '')
        
        # Vectorize text
        text_vector = self.vectorizer.transform([text_content]).toarray()
        
        # Combine features
        feature_array = np.array(list(features.values())).reshape(1, -1)
        X = np.column_stack([feature_array, text_vector])
        
        # Predict
        fp_probability = self.model.predict_proba(X)[0][1]  # Probability of being false positive
        
        return float(fp_probability)
    
    def enhance_vulnerability(self, vulnerability_dict: Dict) -> Dict:
        """Enhance vulnerability with false positive analysis"""
        # Add response content if not present
        if 'response_content' not in vulnerability_dict:
            vulnerability_dict['response_content'] = vulnerability_dict.get('evidence', '')
        
        # Predict false positive probability
        fp_prob = self.predict_false_positive(vulnerability_dict)
        
        # Update vulnerability data
        vulnerability_dict['false_positive_probability'] = fp_prob
        vulnerability_dict['is_likely_false_positive'] = fp_prob > 0.7
        
        # Adjust confidence based on false positive probability
        original_confidence = vulnerability_dict.get('confidence', 0.5)
        adjusted_confidence = original_confidence * (1 - fp_prob)
        vulnerability_dict['adjusted_confidence'] = adjusted_confidence
        
        # Add ML analysis notes
        if fp_prob > 0.8:
            vulnerability_dict['ml_notes'] = "High probability of false positive - manual review recommended"
        elif fp_prob > 0.5:
            vulnerability_dict['ml_notes'] = "Moderate false positive risk - consider context"
        else:
            vulnerability_dict['ml_notes'] = "Low false positive risk - likely genuine vulnerability"
        
        return vulnerability_dict
    
    def save_model(self):
        """Save the trained model to disk"""
        os.makedirs('models', exist_ok=True)
        if self.model:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.vectorizer, self.vectorizer_path)
            logger.info(f"Model saved to {self.model_path}")
    
    def load_model(self):
        """Load a pre-trained model from disk"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
                self.model = joblib.load(self.model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
                self.is_trained = True
                logger.info("Pre-trained model loaded successfully")
            else:
                logger.info("No pre-trained model found. Will train on first use.")
        except Exception as e:
            logger.warning(f"Could not load pre-trained model: {e}")

# Usage example and testing
if __name__ == "__main__":
    # Test the false positive detector
    detector = FalsePositiveDetector()
    
    # Train the model
    detector.train_model()
    
    # Test with sample vulnerability
    test_vulnerability = {
        'response_content': "mysql_fetch_array(): supplied argument is not a valid MySQL result resource in /var/www/html/login.php",
        'status_code': 500,
        'confidence': 0.85,
        'payload': "' OR 1=1--",
        'endpoint': "/login?user=admin",
        'vulnerability_type': 'SQL Injection',
        'response_time': 0.3
    }
    
    enhanced_vuln = detector.enhance_vulnerability(test_vulnerability)
    
    print("Enhanced Vulnerability Analysis:")
    print(f"Original Confidence: {enhanced_vuln.get('confidence', 'N/A')}")
    print(f"False Positive Probability: {enhanced_vuln['false_positive_probability']:.3f}")
    print(f"Adjusted Confidence: {enhanced_vuln['adjusted_confidence']:.3f}")
    print(f"ML Notes: {enhanced_vuln['ml_notes']}")

