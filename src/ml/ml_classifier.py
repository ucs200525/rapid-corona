"""
ML Classifier - DDoS attack detection using Random Forest
Lightweight classifier optimized for real-time packet filtering
"""

import logging
import time
import joblib
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

logger = logging.getLogger(__name__)


@dataclass
class PredictionResult:
    """Result of ML classification"""
    is_attack: bool
    attack_probability: float
    attack_type: str
    confidence: float
    inference_time_ms: float
    feature_importance: Optional[Dict[str, float]] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'is_attack': self.is_attack,
            'attack_probability': self.attack_probability,
            'attack_type': self.attack_type,
            'confidence': self.confidence,
            'inference_time_ms': self.inference_time_ms,
        }


@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: np.ndarray
    training_time: float
    n_samples: int
    n_features: int
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'training_time': self.training_time,
            'n_samples': self.n_samples,
            'n_features': self.n_features,
        }


class DDoSClassifier:
    """
    Random Forest based DDoS attack classifier
    Optimized for real-time inference with low latency
    """
    
    def __init__(self, 
                 model_type: str = 'random_forest',
                 n_estimators: int = 100,
                 max_depth: int = 15,
                 n_jobs: int = -1):
        """
        Initialize the classifier
        
        Args:
            model_type: 'random_forest' or 'gradient_boosting'
            n_estimators: Number of trees
            max_depth: Maximum tree depth
            n_jobs: Number of parallel jobs (-1 = all cores)
        """
        self.model_type = model_type
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.n_jobs = n_jobs
        
        # Initialize model
        if model_type == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                n_jobs=n_jobs,
                random_state=42,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
            )
        else:
            self.model = GradientBoostingClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                random_state=42,
                min_samples_split=5,
            )
        
        # Metadata
        self.is_trained = False
        self.feature_names: List[str] = []
        self.scaler = None
        self.metrics: Optional[ModelMetrics] = None
        self.training_date: Optional[str] = None
        
        # Attack type mapping for multi-class
        self.attack_types = [
            'BENIGN', 'DrDoS_UDP', 'DrDoS_DNS', 'DrDoS_LDAP',
            'DrDoS_MSSQL', 'DrDoS_NTP', 'Syn', 'HTTP_Flood'
        ]
        
        # Inference stats
        self.total_predictions = 0
        self.total_inference_time = 0.0
    
    def train(self, 
              X_train: np.ndarray, 
              y_train: np.ndarray,
              X_val: Optional[np.ndarray] = None,
              y_val: Optional[np.ndarray] = None,
              feature_names: Optional[List[str]] = None) -> ModelMetrics:
        """
        Train the classifier
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
            feature_names: List of feature names
            
        Returns:
            ModelMetrics object with training results
        """
        logger.info(f"Training {self.model_type} classifier...")
        logger.info(f"Training samples: {len(X_train)}, Features: {X_train.shape[1]}")
        
        start_time = time.time()
        
        # Train model
        self.model.fit(X_train, y_train)
        
        training_time = time.time() - start_time
        logger.info(f"Training completed in {training_time:.2f}s")
        
        # Store feature names
        if feature_names:
            self.feature_names = feature_names
        
        # Evaluate on validation set or training set
        eval_X = X_val if X_val is not None else X_train
        eval_y = y_val if y_val is not None else y_train
        
        y_pred = self.model.predict(eval_X)
        
        # Calculate metrics
        self.metrics = ModelMetrics(
            accuracy=accuracy_score(eval_y, y_pred),
            precision=precision_score(eval_y, y_pred, average='weighted', zero_division=0),
            recall=recall_score(eval_y, y_pred, average='weighted', zero_division=0),
            f1_score=f1_score(eval_y, y_pred, average='weighted', zero_division=0),
            confusion_matrix=confusion_matrix(eval_y, y_pred),
            training_time=training_time,
            n_samples=len(X_train),
            n_features=X_train.shape[1],
        )
        
        logger.info(f"Accuracy: {self.metrics.accuracy:.4f}")
        logger.info(f"Precision: {self.metrics.precision:.4f}")
        logger.info(f"Recall: {self.metrics.recall:.4f}")
        logger.info(f"F1 Score: {self.metrics.f1_score:.4f}")
        
        self.is_trained = True
        self.training_date = time.strftime('%Y-%m-%d %H:%M:%S')
        
        return self.metrics
    
    def predict(self, X: np.ndarray) -> PredictionResult:
        """
        Make prediction on input features
        
        Args:
            X: Feature array of shape (1, n_features) or (n_features,)
            
        Returns:
            PredictionResult object
        """
        if not self.is_trained:
            logger.warning("Model not trained, returning default prediction")
            return PredictionResult(
                is_attack=False,
                attack_probability=0.0,
                attack_type='UNKNOWN',
                confidence=0.0,
                inference_time_ms=0.0,
            )
        
        # Ensure 2D array
        if X.ndim == 1:
            X = X.reshape(1, -1)
        
        start_time = time.time()
        
        # Get prediction and probabilities
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        
        inference_time = (time.time() - start_time) * 1000  # ms
        
        # Update stats
        self.total_predictions += 1
        self.total_inference_time += inference_time
        
        # Determine attack type
        is_attack = prediction == 1
        attack_prob = probabilities[1] if len(probabilities) > 1 else probabilities[0]
        confidence = max(probabilities) * 100
        
        # For binary classification, infer attack type from features
        if is_attack:
            attack_type = self._infer_attack_type(X[0])
        else:
            attack_type = 'BENIGN'
        
        return PredictionResult(
            is_attack=is_attack,
            attack_probability=float(attack_prob),
            attack_type=attack_type,
            confidence=float(confidence),
            inference_time_ms=inference_time,
        )
    
    def predict_batch(self, X: np.ndarray) -> List[PredictionResult]:
        """
        Make predictions on a batch of samples
        
        Args:
            X: Feature array of shape (n_samples, n_features)
            
        Returns:
            List of PredictionResult objects
        """
        if not self.is_trained:
            return []
        
        start_time = time.time()
        
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        
        inference_time = (time.time() - start_time) * 1000 / len(X)
        
        results = []
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            is_attack = pred == 1
            attack_prob = probs[1] if len(probs) > 1 else probs[0]
            
            results.append(PredictionResult(
                is_attack=is_attack,
                attack_probability=float(attack_prob),
                attack_type=self._infer_attack_type(X[i]) if is_attack else 'BENIGN',
                confidence=float(max(probs) * 100),
                inference_time_ms=inference_time,
            ))
        
        return results
    
    def _infer_attack_type(self, features: np.ndarray) -> str:
        """
        Infer attack type from features (heuristic for binary classification)
        
        Args:
            features: Single sample features
            
        Returns:
            Inferred attack type string
        """
        # Use feature indices based on CIC feature order
        # SYN Flag Count is at index 43
        # ACK Flag Count is at index 46
        # Flow Packets/s is at index 14
        
        try:
            syn_count = features[43] if len(features) > 43 else 0
            ack_count = features[46] if len(features) > 46 else 0
            packets_per_sec = features[14] if len(features) > 14 else 0
            bytes_per_sec = features[13] if len(features) > 13 else 0
            
            # Heuristic classification
            if syn_count > 100 and ack_count < 10:
                return 'SYN_Flood'
            elif packets_per_sec > 10000 and bytes_per_sec > 1000000:
                return 'UDP_Flood'
            elif packets_per_sec > 5000:
                return 'DrDoS_UDP'
            else:
                return 'DDoS_Generic'
                
        except Exception:
            return 'DDoS_Generic'
    
    def get_feature_importance(self, top_n: int = 20) -> Dict[str, float]:
        """
        Get feature importance from the trained model
        
        Args:
            top_n: Number of top features to return
            
        Returns:
            Dictionary of feature name -> importance
        """
        if not self.is_trained:
            return {}
        
        importances = self.model.feature_importances_
        
        if self.feature_names and len(self.feature_names) == len(importances):
            importance_dict = dict(zip(self.feature_names, importances))
        else:
            importance_dict = {f'feature_{i}': imp for i, imp in enumerate(importances)}
        
        # Sort by importance and return top N
        sorted_importance = dict(
            sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)[:top_n]
        )
        
        return sorted_importance
    
    def save(self, filepath: str) -> bool:
        """
        Save trained model to file
        
        Args:
            filepath: Path to save model
            
        Returns:
            True if successful
        """
        if not self.is_trained:
            logger.error("Cannot save untrained model")
            return False
        
        try:
            save_dict = {
                'model': self.model,
                'model_type': self.model_type,
                'feature_names': self.feature_names,
                'scaler': self.scaler,
                'metrics': self.metrics,
                'training_date': self.training_date,
                'n_estimators': self.n_estimators,
                'max_depth': self.max_depth,
            }
            
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(save_dict, filepath)
            logger.info(f"Model saved to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False
    
    def load(self, filepath: str) -> bool:
        """
        Load trained model from file
        
        Args:
            filepath: Path to model file
            
        Returns:
            True if successful
        """
        try:
            if not Path(filepath).exists():
                logger.error(f"Model file not found: {filepath}")
                return False
            
            save_dict = joblib.load(filepath)
            
            self.model = save_dict['model']
            self.model_type = save_dict.get('model_type', 'random_forest')
            self.feature_names = save_dict.get('feature_names', [])
            self.scaler = save_dict.get('scaler')
            self.metrics = save_dict.get('metrics')
            self.training_date = save_dict.get('training_date')
            self.n_estimators = save_dict.get('n_estimators', 100)
            self.max_depth = save_dict.get('max_depth', 15)
            self.is_trained = True
            
            logger.info(f"Model loaded from {filepath}")
            logger.info(f"Training date: {self.training_date}")
            if self.metrics:
                logger.info(f"Accuracy: {self.metrics.accuracy:.4f}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def get_stats(self) -> Dict:
        """Get classifier statistics"""
        avg_inference = (
            self.total_inference_time / self.total_predictions 
            if self.total_predictions > 0 else 0
        )
        
        return {
            'is_trained': self.is_trained,
            'model_type': self.model_type,
            'n_estimators': self.n_estimators,
            'max_depth': self.max_depth,
            'n_features': len(self.feature_names),
            'training_date': self.training_date,
            'total_predictions': self.total_predictions,
            'avg_inference_ms': avg_inference,
            'metrics': self.metrics.to_dict() if self.metrics else None,
        }


def train_ddos_classifier(data_dir: str = 'data/cic-ddos-2019',
                          model_path: str = 'data/models/ddos_classifier.joblib',
                          max_files: int = 5,
                          samples_per_file: int = 50000) -> DDoSClassifier:
    """
    Train a DDoS classifier using CIC-DDoS-2019 dataset
    
    Args:
        data_dir: Directory containing CIC CSV files
        model_path: Path to save trained model
        max_files: Maximum number of CSV files to load
        samples_per_file: Maximum samples per file
        
    Returns:
        Trained DDoSClassifier
    """
    from .data_loader import CICDataLoader
    
    logger.info("="*60)
    logger.info("DDoS Classifier Training")
    logger.info("="*60)
    
    # Load and prepare data
    loader = CICDataLoader(data_dir)
    data = loader.prepare_data(
        max_files=max_files,
        samples_per_file=samples_per_file,
        binary=True,
        scale=True,
    )
    
    if not data:
        logger.error("Failed to load training data")
        return None
    
    # Create and train classifier
    classifier = DDoSClassifier(
        model_type='random_forest',
        n_estimators=100,
        max_depth=15,
    )
    
    # Store scaler for inference
    classifier.scaler = data['scaler']
    
    # Train
    metrics = classifier.train(
        X_train=data['X_train'],
        y_train=data['y_train'],
        X_val=data['X_val'],
        y_val=data['y_val'],
        feature_names=data['feature_names'],
    )
    
    # Evaluate on test set
    logger.info("\nTest Set Evaluation:")
    y_pred = classifier.model.predict(data['X_test'])
    test_accuracy = accuracy_score(data['y_test'], y_pred)
    logger.info(f"Test Accuracy: {test_accuracy:.4f}")
    logger.info(f"\nClassification Report:\n{classification_report(data['y_test'], y_pred)}")
    
    # Save model
    classifier.save(model_path)
    
    # Print feature importance
    logger.info("\nTop 10 Important Features:")
    for name, importance in list(classifier.get_feature_importance(10).items()):
        logger.info(f"  {name}: {importance:.4f}")
    
    return classifier


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Try to train classifier
    classifier = train_ddos_classifier(
        max_files=2,
        samples_per_file=10000,
    )
    
    if classifier:
        # Test prediction
        test_features = np.random.randn(1, len(classifier.feature_names))
        result = classifier.predict(test_features)
        print(f"\nTest Prediction: {result}")
