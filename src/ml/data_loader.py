import gzip
import numpy as np
from sklearn.decomposition import PCA


def load_multi_mnist(digits=(3, 8), num_features=15, num_samples=300, num_workers=3):
    with gzip.open('../mnist_data/train-images-idx3-ubyte.gz', 'rb') as f:
        f.read(16)
        train_images = np.frombuffer(f.read(), dtype=np.uint8)
        train_images = train_images.reshape(-1, 784).astype(np.float32) / 255.0
    with gzip.open('../mnist_data/train-labels-idx1-ubyte.gz', 'rb') as f:
        f.read(8)
        train_labels = np.frombuffer(f.read(), dtype=np.uint8)
    with gzip.open('../mnist_data/t10k-images-idx3-ubyte.gz', 'rb') as f:
        f.read(16)
        test_images = np.frombuffer(f.read(), dtype=np.uint8)
        test_images = test_images.reshape(-1, 784).astype(np.float32) / 255.0
    with gzip.open('../mnist_data/t10k-labels-idx1-ubyte.gz', 'rb') as f:
        f.read(8)
        test_labels = np.frombuffer(f.read(), dtype=np.uint8)

    train_digit_mask = np.isin(train_labels, digits)
    test_digit_mask = np.isin(test_labels, digits)

    train_images = train_images[train_digit_mask]
    train_labels = train_labels[train_digit_mask]
    test_images = test_images[test_digit_mask]
    test_labels = test_labels[test_digit_mask]

    for i, digit in enumerate(digits):
        train_labels[train_labels == digit] = i
        test_labels[test_labels == digit] = i

    unique_labels = np.unique(train_labels)
    samples_per_class = num_samples // len(unique_labels)
    selected_indices = []
    for label in unique_labels:
        indices = np.where(train_labels == label)[0][:samples_per_class]
        selected_indices.extend(indices)

    np.random.shuffle(selected_indices)

    train_images = train_images[selected_indices]
    train_labels = train_labels[selected_indices]

    test_samples_per_class = min(100, num_samples // (10 * len(unique_labels)))
    test_indices = []
    for label in unique_labels:
        indices = np.where(test_labels == label)[0][:test_samples_per_class]
        test_indices.extend(indices)

    np.random.shuffle(test_indices)
    test_images = test_images[test_indices]
    test_labels = test_labels[test_indices]

    pca = PCA(n_components=num_features)
    train_images_reduced = pca.fit_transform(train_images)
    test_images_reduced = pca.transform(test_images)

    total_samples = len(train_images_reduced)
    samples_per_worker = total_samples // num_workers
    train_images_reduced = train_images_reduced[:min(
        samples_per_worker, len(train_images_reduced))]
    train_labels = train_labels[:min(
        samples_per_worker, len(train_images_reduced))]

    print(f"Dataset: {digits}, Features: {num_features}")
    print(
        f"Training samples: {len(train_images_reduced)}, Test samples: {len(test_images_reduced)}")
    return (train_images_reduced, train_labels), (test_images_reduced, test_labels)
