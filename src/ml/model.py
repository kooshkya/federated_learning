import numpy as np
from typing import List


class SimpleNeuralNetwork:
    def __init__(self, input_size: int, hidden_size: int, output_size: int):
        self.input_size  = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size

        self.W1 = np.random.randn(self.input_size,  self.hidden_size) * 0.1
        self.b1 = np.zeros(self.hidden_size)
        self.W2 = np.random.randn(self.hidden_size, self.output_size) * 0.1
        self.b2 = np.zeros(self.output_size)

        self.vW1, self.vb1 = np.zeros_like(self.W1), np.zeros_like(self.b1)
        self.vW2, self.vb2 = np.zeros_like(self.W2), np.zeros_like(self.b2)

        self.z1, self.a1 = None, None
        self.z2, self.a2 = None, None

    def _relu(self, x: np.ndarray) -> np.ndarray:
        return np.maximum(0, x)

    def _softmax(self, x: np.ndarray) -> np.ndarray:
        exp_x = np.exp(x - np.max(x, axis=1, keepdims=True))
        return exp_x / np.sum(exp_x, axis=1, keepdims=True)

    def forward(self, X: np.ndarray) -> np.ndarray:
        self.z1 = X @ self.W1 + self.b1
        self.a1 = self._relu(self.z1)
        self.z2 = self.a1 @ self.W2 + self.b2
        self.a2 = self._softmax(self.z2)
        return self.a2

    def compute_loss(self, y_one_hot: np.ndarray, y_pred: np.ndarray) -> float:
        eps = 1e-15
        return -np.mean(np.sum(y_one_hot * np.log(y_pred + eps), axis=1))

    def backward(self, X: np.ndarray, y_one_hot: np.ndarray):
        m = X.shape[0]
        dz2 = (self.a2 - y_one_hot) / m
        dW2 = self.a1.T @ dz2
        db2 = np.sum(dz2, axis=0)
        da1 = dz2 @ self.W2.T
        dz1 = da1 * (self.z1 > 0)
        dW1 = X.T @ dz1
        db1 = np.sum(dz1, axis=0)
        return dW1, db1, dW2, db2

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.argmax(self.forward(X), axis=1)

    def train(self, X: np.ndarray, y: np.ndarray,
              epochs: int, learning_rate: float, momentum: float):
        num_classes = self.output_size
        y_one_hot = np.eye(num_classes)[y]

        for epoch in range(epochs):
            self.forward(X)
            dW1, db1, dW2, db2 = self.backward(X, y_one_hot)

            self.vW1 = momentum * self.vW1 - learning_rate * dW1
            self.vb1 = momentum * self.vb1 - learning_rate * db1
            self.vW2 = momentum * self.vW2 - learning_rate * dW2
            self.vb2 = momentum * self.vb2 - learning_rate * db2

            self.W1 += self.vW1
            self.b1 += self.vb1
            self.W2 += self.vW2
            self.b2 += self.vb2

            clip_threshold = 0.5
            np.clip(self.W1, -clip_threshold, clip_threshold, out=self.W1)
            np.clip(self.W2, -clip_threshold, clip_threshold, out=self.W2)

            if epoch % 10 == 0 or epoch == epochs - 1:
                loss = self.compute_loss(y_one_hot, self.a2)
                accuracy = self.evaluate(X, y)
                print(f"  Epoch {epoch:3d}, Loss: {loss:.4f}, Accuracy: {accuracy:.4f}")

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> float:
        y_pred = self.predict(X)
        return np.mean(y_pred == y)

    def get_weights(self) -> List[np.ndarray]:
        """Return all trainable weights as a flat list of arrays."""
        return [self.W1, self.b1, self.W2, self.b2]

    def set_weights(self, weights: List[np.ndarray]):
        """Set model weights from a list of arrays (same order as get_weights)."""
        self.W1 = weights[0].reshape(self.input_size,  self.hidden_size)
        self.b1 = weights[1].reshape(self.hidden_size)
        self.W2 = weights[2].reshape(self.hidden_size, self.output_size)
        self.b2 = weights[3].reshape(self.output_size)
