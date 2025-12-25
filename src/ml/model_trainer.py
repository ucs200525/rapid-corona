"""
Model Trainer - Training script for DDoS classifier
Provides command-line interface for training and evaluation
"""

import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def train_model(args):
    """Train the DDoS classifier"""
    from .data_loader import CICDataLoader, create_synthetic_dataset
    from .ml_classifier import DDoSClassifier
    
    logger.info("="*70)
    logger.info("DDoS Classifier Training - Phase 2")
    logger.info("="*70)
    
    # Check if dataset exists
    data_path = Path(args.data_path)
    loader = CICDataLoader(str(data_path))
    csv_files = loader.find_csv_files()
    
    if not csv_files and not args.synthetic:
        logger.error(f"No CSV files found in {data_path}")
        logger.info("Options:")
        logger.info("  1. Download CIC-DDoS-2019 dataset to data/cic-ddos-2019/")
        logger.info("  2. Use --synthetic flag to train on synthetic data")
        return None
    
    # Load data
    if csv_files:
        logger.info(f"Loading CIC-DDoS-2019 dataset from {data_path}")
        data = loader.prepare_data(
            max_files=args.max_files,
            samples_per_file=args.samples_per_file,
            binary=not args.multiclass,
            scale=True,
        )
    else:
        logger.info("Using synthetic dataset for training")
        df = create_synthetic_dataset(args.samples_per_file * 2)
        
        # Prepare synthetic data
        X, y_str, feature_names = loader.preprocess(df)
        y = loader.encode_labels(y_str, binary=True)
        
        from sklearn.model_selection import train_test_split
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
        )
        
        X_train, _ = loader.scale_features(X_train, fit=True)
        X_val, _ = loader.scale_features(X_val, fit=False)
        X_test, _ = loader.scale_features(X_test, fit=False)
        
        data = {
            'X_train': X_train,
            'X_val': X_val,
            'X_test': X_test,
            'y_train': y_train,
            'y_val': y_val,
            'y_test': y_test,
            'feature_names': feature_names,
            'scaler': loader.scaler,
        }
    
    if not data:
        logger.error("Failed to prepare training data")
        return None
    
    logger.info(f"Training samples: {len(data['X_train'])}")
    logger.info(f"Validation samples: {len(data['X_val'])}")
    logger.info(f"Test samples: {len(data['X_test'])}")
    logger.info(f"Features: {len(data['feature_names'])}")
    
    # Create and train classifier
    classifier = DDoSClassifier(
        model_type=args.model_type,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
    )
    
    # Store scaler
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
    logger.info("\n" + "="*50)
    logger.info("Test Set Evaluation")
    logger.info("="*50)
    
    from sklearn.metrics import accuracy_score, classification_report
    
    y_pred = classifier.model.predict(data['X_test'])
    test_accuracy = accuracy_score(data['y_test'], y_pred)
    
    logger.info(f"Test Accuracy: {test_accuracy:.4f}")
    logger.info(f"\nClassification Report:\n{classification_report(data['y_test'], y_pred)}")
    
    # Feature importance
    logger.info("\n" + "="*50)
    logger.info("Top 15 Important Features")
    logger.info("="*50)
    for name, importance in list(classifier.get_feature_importance(15).items()):
        logger.info(f"  {name}: {importance:.4f}")
    
    # Save model
    model_path = Path(args.model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    
    if classifier.save(str(model_path)):
        logger.info(f"\n✓ Model saved to {model_path}")
    
    return classifier


def evaluate_model(args):
    """Evaluate a trained model"""
    from .ml_classifier import DDoSClassifier
    from .data_loader import CICDataLoader
    
    classifier = DDoSClassifier()
    if not classifier.load(args.model_path):
        logger.error("Failed to load model")
        return
    
    logger.info(f"Model loaded: {classifier.training_date}")
    logger.info(f"Training metrics: {classifier.metrics.to_dict()}")
    
    # Load test data if provided
    if args.data_path:
        loader = CICDataLoader(args.data_path)
        data = loader.prepare_data(max_files=1, samples_per_file=10000)
        
        if data:
            from sklearn.metrics import accuracy_score
            y_pred = classifier.model.predict(data['X_test'])
            accuracy = accuracy_score(data['y_test'], y_pred)
            logger.info(f"Test Accuracy: {accuracy:.4f}")


def benchmark_inference(args):
    """Benchmark inference latency"""
    import numpy as np
    import time
    from .ml_classifier import DDoSClassifier
    
    classifier = DDoSClassifier()
    if not classifier.load(args.model_path):
        logger.error("Failed to load model")
        return
    
    n_features = len(classifier.feature_names) if classifier.feature_names else 64
    
    logger.info("="*50)
    logger.info("Inference Latency Benchmark")
    logger.info("="*50)
    
    batch_sizes = [1, 10, 100, 1000]
    
    for batch_size in batch_sizes:
        X = np.random.randn(batch_size, n_features).astype(np.float32)
        
        # Warmup
        for _ in range(10):
            classifier.model.predict(X)
        
        # Benchmark
        n_iterations = 100
        start = time.time()
        for _ in range(n_iterations):
            classifier.model.predict(X)
        elapsed = time.time() - start
        
        avg_time = (elapsed / n_iterations) * 1000  # ms
        per_sample = avg_time / batch_size
        throughput = batch_size / (elapsed / n_iterations)
        
        logger.info(f"Batch size {batch_size:4d}: "
                   f"Avg {avg_time:.3f}ms, "
                   f"Per sample {per_sample:.4f}ms, "
                   f"Throughput {throughput:.0f} samples/s")


def main():
    parser = argparse.ArgumentParser(
        description='DDoS Classifier Training and Evaluation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train the classifier')
    train_parser.add_argument('--data-path', default='data/cic-ddos-2019',
                             help='Path to CIC-DDoS-2019 dataset')
    train_parser.add_argument('--model-path', default='data/models/ddos_classifier.joblib',
                             help='Path to save trained model')
    train_parser.add_argument('--model-type', choices=['random_forest', 'gradient_boosting'],
                             default='random_forest', help='Model type')
    train_parser.add_argument('--n-estimators', type=int, default=100,
                             help='Number of trees')
    train_parser.add_argument('--max-depth', type=int, default=15,
                             help='Maximum tree depth')
    train_parser.add_argument('--max-files', type=int, default=5,
                             help='Maximum CSV files to load')
    train_parser.add_argument('--samples-per-file', type=int, default=50000,
                             help='Maximum samples per file')
    train_parser.add_argument('--multiclass', action='store_true',
                             help='Use multi-class classification')
    train_parser.add_argument('--synthetic', action='store_true',
                             help='Use synthetic data if real dataset unavailable')
    
    # Evaluate command
    eval_parser = subparsers.add_parser('evaluate', help='Evaluate trained model')
    eval_parser.add_argument('--model-path', default='data/models/ddos_classifier.joblib',
                            help='Path to trained model')
    eval_parser.add_argument('--data-path', help='Path to test dataset')
    
    # Benchmark command
    bench_parser = subparsers.add_parser('benchmark', help='Benchmark inference latency')
    bench_parser.add_argument('--model-path', default='data/models/ddos_classifier.joblib',
                             help='Path to trained model')
    
    args = parser.parse_args()
    
    if args.command == 'train':
        train_model(args)
    elif args.command == 'evaluate':
        evaluate_model(args)
    elif args.command == 'benchmark':
        benchmark_inference(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
