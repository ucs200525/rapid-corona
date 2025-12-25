"""
CIC-DDoS-2019 Dataset Loader
Handles loading, preprocessing, and preparing the dataset for ML training
"""

import logging
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, List, Optional, Dict
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import warnings

warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)


# CIC-DDoS-2019 attack types (label mapping)
ATTACK_LABELS = {
    'BENIGN': 0,
    'DrDoS_DNS': 1,
    'DrDoS_LDAP': 2,
    'DrDoS_MSSQL': 3,
    'DrDoS_NTP': 4,
    'DrDoS_NetBIOS': 5,
    'DrDoS_SNMP': 6,
    'DrDoS_SSDP': 7,
    'DrDoS_UDP': 8,
    'Syn': 9,
    'TFTP': 10,
    'UDP-lag': 11,
    'WebDDoS': 12,
    'Portmap': 13,
    'NetBIOS': 14,
    'LDAP': 15,
    'MSSQL': 16,
    'UDP': 17,
}

# Key features from CIC-DDoS-2019 that we'll use for classification
# Selected for being computable from real-time traffic
SELECTED_FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Total',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max',
    'Fwd IAT Min',
    'Bwd IAT Total',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    'Fwd PSH Flags',
    'Bwd PSH Flags',
    'Fwd URG Flags',
    'Bwd URG Flags',
    'Fwd Header Length',
    'Bwd Header Length',
    'Fwd Packets/s',
    'Bwd Packets/s',
    'Min Packet Length',
    'Max Packet Length',
    'Packet Length Mean',
    'Packet Length Std',
    'Packet Length Variance',
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'URG Flag Count',
    'CWE Flag Count',
    'ECE Flag Count',
    'Down/Up Ratio',
    'Average Packet Size',
    'Avg Fwd Segment Size',
    'Avg Bwd Segment Size',
    'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk',
    'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets',
    'Subflow Fwd Bytes',
    'Subflow Bwd Packets',
    'Subflow Bwd Bytes',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
    'act_data_pkt_fwd',
    'min_seg_size_forward',
    'Active Mean',
    'Active Std',
    'Active Max',
    'Active Min',
    'Idle Mean',
    'Idle Std',
    'Idle Max',
    'Idle Min',
]


class CICDataLoader:
    """Load and preprocess CIC-DDoS-2019 dataset"""
    
    def __init__(self, data_dir: str = 'data/cic-ddos-2019'):
        """
        Initialize the data loader
        
        Args:
            data_dir: Directory containing CIC-DDoS-2019 CSV files
        """
        self.data_dir = Path(data_dir)
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.feature_names = SELECTED_FEATURES.copy()
        self._fitted = False
        
    def find_csv_files(self) -> List[Path]:
        """Find all CSV files in the data directory"""
        csv_files = list(self.data_dir.rglob('*.csv'))
        logger.info(f"Found {len(csv_files)} CSV files in {self.data_dir}")
        return csv_files
    
    def load_single_csv(self, filepath: Path, sample_size: Optional[int] = None) -> pd.DataFrame:
        """
        Load a single CSV file with proper handling
        
        Args:
            filepath: Path to CSV file
            sample_size: Optional sample size per file
            
        Returns:
            DataFrame with loaded data
        """
        try:
            # Read CSV - CIC dataset has varying column names with spaces
            df = pd.read_csv(filepath, low_memory=False, encoding='utf-8')
            
            # Strip whitespace from column names
            df.columns = df.columns.str.strip()
            
            # Sample if needed
            if sample_size and len(df) > sample_size:
                df = df.sample(n=sample_size, random_state=42)
            
            logger.info(f"Loaded {len(df)} samples from {filepath.name}")
            return df
            
        except Exception as e:
            logger.error(f"Error loading {filepath}: {e}")
            return pd.DataFrame()
    
    def load_dataset(self, 
                     max_files: Optional[int] = None,
                     samples_per_file: Optional[int] = 50000,
                     balance_classes: bool = True) -> pd.DataFrame:
        """
        Load the complete dataset from multiple CSV files
        
        Args:
            max_files: Maximum number of files to load
            samples_per_file: Maximum samples per file
            balance_classes: Whether to balance attack/benign classes
            
        Returns:
            Combined DataFrame
        """
        csv_files = self.find_csv_files()
        
        if not csv_files:
            logger.warning(f"No CSV files found in {self.data_dir}")
            return pd.DataFrame()
        
        if max_files:
            csv_files = csv_files[:max_files]
        
        dfs = []
        for filepath in csv_files:
            df = self.load_single_csv(filepath, samples_per_file)
            if not df.empty:
                dfs.append(df)
        
        if not dfs:
            return pd.DataFrame()
        
        # Combine all dataframes
        combined_df = pd.concat(dfs, ignore_index=True)
        logger.info(f"Combined dataset: {len(combined_df)} total samples")
        
        # Balance classes if requested
        if balance_classes and ' Label' in combined_df.columns:
            combined_df = self._balance_classes(combined_df)
        
        return combined_df
    
    def _balance_classes(self, df: pd.DataFrame, 
                         benign_ratio: float = 0.3) -> pd.DataFrame:
        """
        Balance benign and attack samples
        
        Args:
            df: Input DataFrame
            benign_ratio: Target ratio of benign samples
            
        Returns:
            Balanced DataFrame
        """
        label_col = ' Label' if ' Label' in df.columns else 'Label'
        
        benign_mask = df[label_col].str.strip().str.upper() == 'BENIGN'
        attack_df = df[~benign_mask]
        benign_df = df[benign_mask]
        
        # Calculate target benign count
        target_benign = int(len(attack_df) * benign_ratio / (1 - benign_ratio))
        target_benign = min(target_benign, len(benign_df))
        
        if target_benign < len(benign_df):
            benign_df = benign_df.sample(n=target_benign, random_state=42)
        
        balanced_df = pd.concat([attack_df, benign_df], ignore_index=True)
        balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        logger.info(f"Balanced dataset: {len(attack_df)} attacks, {len(benign_df)} benign")
        return balanced_df
    
    def preprocess(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Preprocess the dataset for ML training
        
        Args:
            df: Raw DataFrame
            
        Returns:
            Tuple of (features array, labels array, feature names)
        """
        if df.empty:
            return np.array([]), np.array([]), []
        
        # Get label column
        label_col = ' Label' if ' Label' in df.columns else 'Label'
        
        # Extract labels
        labels = df[label_col].str.strip().values
        
        # Find available features (column names may have spaces)
        available_features = []
        for feature in self.feature_names:
            if feature in df.columns:
                available_features.append(feature)
            elif f' {feature}' in df.columns:
                available_features.append(f' {feature}')
        
        if not available_features:
            logger.error("No matching features found in dataset")
            logger.info(f"Dataset columns: {list(df.columns[:20])}")
            return np.array([]), np.array([]), []
        
        logger.info(f"Using {len(available_features)} features")
        
        # Extract features
        X = df[available_features].copy()
        
        # Clean feature names (remove leading spaces)
        X.columns = X.columns.str.strip()
        self.feature_names = list(X.columns)
        
        # Handle missing values - replace with 0
        X = X.fillna(0)
        
        # Handle infinity values
        X = X.replace([np.inf, -np.inf], 0)
        
        # Convert to numeric
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
        
        # Convert to numpy array
        X_array = X.values.astype(np.float32)
        
        # Clip extreme values
        X_array = np.clip(X_array, -1e10, 1e10)
        
        return X_array, labels, self.feature_names
    
    def encode_labels(self, labels: np.ndarray, binary: bool = True) -> np.ndarray:
        """
        Encode string labels to numeric
        
        Args:
            labels: String labels array
            binary: If True, encode as binary (0=benign, 1=attack)
            
        Returns:
            Encoded labels
        """
        if binary:
            # Binary classification: BENIGN = 0, Attack = 1
            encoded = np.array([
                0 if str(label).strip().upper() == 'BENIGN' else 1 
                for label in labels
            ])
        else:
            # Multi-class classification
            if not self._fitted:
                self.label_encoder.fit(labels)
                self._fitted = True
            encoded = self.label_encoder.transform(labels)
        
        return encoded
    
    def scale_features(self, X_train: np.ndarray, 
                       X_test: Optional[np.ndarray] = None,
                       fit: bool = True) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Scale features using StandardScaler
        
        Args:
            X_train: Training features
            X_test: Optional test features
            fit: Whether to fit the scaler (True for training)
            
        Returns:
            Scaled feature arrays
        """
        if fit:
            X_train_scaled = self.scaler.fit_transform(X_train)
        else:
            X_train_scaled = self.scaler.transform(X_train)
        
        X_test_scaled = None
        if X_test is not None:
            X_test_scaled = self.scaler.transform(X_test)
        
        return X_train_scaled, X_test_scaled
    
    def prepare_data(self, 
                     test_size: float = 0.2,
                     val_size: float = 0.1,
                     binary: bool = True,
                     scale: bool = True,
                     max_files: Optional[int] = None,
                     samples_per_file: int = 50000) -> Dict:
        """
        Complete data preparation pipeline
        
        Args:
            test_size: Fraction for test set
            val_size: Fraction for validation set
            binary: Binary classification mode
            scale: Whether to scale features
            max_files: Maximum CSV files to load
            samples_per_file: Samples per file
            
        Returns:
            Dictionary with train/val/test splits and metadata
        """
        # Load dataset
        df = self.load_dataset(
            max_files=max_files,
            samples_per_file=samples_per_file,
            balance_classes=True
        )
        
        if df.empty:
            logger.error("Failed to load dataset")
            return {}
        
        # Preprocess
        X, y_str, feature_names = self.preprocess(df)
        
        if len(X) == 0:
            logger.error("Preprocessing failed")
            return {}
        
        # Encode labels
        y = self.encode_labels(y_str, binary=binary)
        
        logger.info(f"Dataset shape: {X.shape}")
        logger.info(f"Label distribution: {np.bincount(y)}")
        
        # Split data
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=(test_size + val_size), 
            random_state=42, stratify=y
        )
        
        val_fraction = val_size / (test_size + val_size)
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=(1 - val_fraction),
            random_state=42, stratify=y_temp
        )
        
        # Scale features
        if scale:
            X_train, _ = self.scale_features(X_train, fit=True)
            X_val, _ = self.scale_features(X_val, fit=False)
            X_test, _ = self.scale_features(X_test, fit=False)
        
        logger.info(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        
        return {
            'X_train': X_train,
            'X_val': X_val,
            'X_test': X_test,
            'y_train': y_train,
            'y_val': y_val,
            'y_test': y_test,
            'feature_names': feature_names,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder if not binary else None,
            'binary_mode': binary,
            'original_labels': y_str,
        }
    
    def get_attack_label_name(self, encoded_label: int, binary: bool = True) -> str:
        """
        Get human-readable label name from encoded label
        
        Args:
            encoded_label: Numeric label
            binary: Whether binary mode was used
            
        Returns:
            Label name string
        """
        if binary:
            return 'BENIGN' if encoded_label == 0 else 'ATTACK'
        else:
            return self.label_encoder.inverse_transform([encoded_label])[0]


def create_synthetic_dataset(n_samples: int = 10000) -> pd.DataFrame:
    """
    Create synthetic dataset for testing when CIC dataset is unavailable
    
    Args:
        n_samples: Number of samples to generate
        
    Returns:
        Synthetic DataFrame mimicking CIC-DDoS-2019 structure
    """
    np.random.seed(42)
    
    # Generate benign traffic features
    n_benign = n_samples // 2
    n_attack = n_samples - n_benign
    
    data = []
    
    # Benign traffic characteristics
    for _ in range(n_benign):
        sample = {
            'Flow Duration': np.random.exponential(1000000),
            'Total Fwd Packets': np.random.poisson(10),
            'Total Backward Packets': np.random.poisson(8),
            'Total Length of Fwd Packets': np.random.exponential(1000),
            'Total Length of Bwd Packets': np.random.exponential(800),
            'Fwd Packet Length Mean': np.random.exponential(100),
            'Bwd Packet Length Mean': np.random.exponential(80),
            'Flow Bytes/s': np.random.exponential(10000),
            'Flow Packets/s': np.random.exponential(100),
            'SYN Flag Count': np.random.poisson(1),
            'ACK Flag Count': np.random.poisson(5),
            'Average Packet Size': np.random.exponential(200),
            ' Label': 'BENIGN'
        }
        data.append(sample)
    
    # Attack traffic characteristics (higher rates, different patterns)
    attack_types = ['DrDoS_UDP', 'Syn', 'DrDoS_DNS', 'DrDoS_LDAP']
    for _ in range(n_attack):
        attack_type = np.random.choice(attack_types)
        sample = {
            'Flow Duration': np.random.exponential(100000),  # Shorter
            'Total Fwd Packets': np.random.poisson(100),  # More packets
            'Total Backward Packets': np.random.poisson(2),  # Few responses
            'Total Length of Fwd Packets': np.random.exponential(10000),
            'Total Length of Bwd Packets': np.random.exponential(100),
            'Fwd Packet Length Mean': np.random.exponential(200),
            'Bwd Packet Length Mean': np.random.exponential(20),
            'Flow Bytes/s': np.random.exponential(100000),  # Higher
            'Flow Packets/s': np.random.exponential(1000),  # Higher
            'SYN Flag Count': np.random.poisson(50) if attack_type == 'Syn' else np.random.poisson(2),
            'ACK Flag Count': np.random.poisson(1),
            'Average Packet Size': np.random.exponential(100),
            ' Label': attack_type
        }
        data.append(sample)
    
    df = pd.DataFrame(data)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    logger.info(f"Created synthetic dataset with {len(df)} samples")
    return df


if __name__ == '__main__':
    # Test the data loader
    logging.basicConfig(level=logging.INFO)
    
    loader = CICDataLoader()
    
    # Try loading real dataset
    csv_files = loader.find_csv_files()
    
    if csv_files:
        print("Loading real CIC-DDoS-2019 dataset...")
        data = loader.prepare_data(max_files=2, samples_per_file=10000)
        if data:
            print(f"Loaded {len(data['X_train'])} training samples")
            print(f"Features: {len(data['feature_names'])}")
    else:
        print("No dataset found. Creating synthetic dataset for testing...")
        df = create_synthetic_dataset(1000)
        print(df.head())
        print(f"\nLabel distribution:\n{df[' Label'].value_counts()}")
