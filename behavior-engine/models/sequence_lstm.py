"""
LSTM Sequence Bot Classifier
Learns human navigation patterns and scores how likely a session is automated.

Key insight: Humans navigate pages in context-aware sequences
(landing page → product → cart → checkout). Bots often jump directly
to API endpoints with no page-load context.
"""
import numpy as np
import torch
import torch.nn as nn
import os
import logging
import hashlib
from collections import Counter

logger = logging.getLogger(__name__)

MODEL_PATH = os.environ.get("LSTM_MODEL_PATH", "/models/sequence_lstm.pt")

# Vocabulary: map endpoint paths to indices
MAX_VOCAB = 2048
MAX_SEQ_LEN = 20
EMBED_DIM = 64
HIDDEN_DIM = 128
NUM_LAYERS = 2


class BotSequenceDetector(nn.Module):
    def __init__(self, vocab_size: int, embed_dim: int, hidden_dim: int, num_layers: int):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(
            embed_dim, hidden_dim, num_layers,
            batch_first=True, dropout=0.3, bidirectional=True
        )
        self.attention = nn.MultiheadAttention(hidden_dim * 2, num_heads=4, batch_first=True)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        emb = self.embedding(x)                         # (B, T, E)
        lstm_out, _ = self.lstm(emb)                    # (B, T, H*2)
        attn_out, _ = self.attention(lstm_out, lstm_out, lstm_out)  # (B, T, H*2)
        pooled = attn_out.mean(dim=1)                   # (B, H*2)
        return self.classifier(pooled).squeeze(-1)      # (B,)


class EndpointVocabulary:
    """Maps endpoint strings to integer indices."""
    def __init__(self):
        self.vocab = {"<PAD>": 0, "<UNK>": 1}
        self.freq = Counter()

    def tokenize(self, endpoint: str) -> int:
        # Normalize: strip query params, lowercase
        path = endpoint.split("?")[0].lower().rstrip("/") or "/"
        if path not in self.vocab:
            if len(self.vocab) >= MAX_VOCAB:
                # Vocab full — map unknown paths to <UNK> (index 1) rather than
                # growing past MAX_VOCAB and causing an IndexError in the embedding.
                return 1
            self.vocab[path] = len(self.vocab)
        self.freq[path] += 1
        return self.vocab.get(path, 1)

    def encode_sequence(self, endpoints: list[str]) -> list[int]:
        encoded = [self.tokenize(e) for e in endpoints[-MAX_SEQ_LEN:]]
        # Pad to MAX_SEQ_LEN
        while len(encoded) < MAX_SEQ_LEN:
            encoded.insert(0, 0)  # left-pad
        return encoded


class SequenceBotClassifier:
    def __init__(self):
        self.vocab = EndpointVocabulary()
        self.model: BotSequenceDetector | None = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.feedback: list[tuple[list[str], bool]] = []
        self._load_or_init()

    def _load_or_init(self):
        self.model = BotSequenceDetector(MAX_VOCAB, EMBED_DIM, HIDDEN_DIM, NUM_LAYERS)
        if os.path.exists(MODEL_PATH):
            try:
                state = torch.load(MODEL_PATH, map_location=self.device)
                self.model.load_state_dict(state)
                logger.info("Loaded LSTM sequence model from disk")
            except Exception as e:
                logger.warning(f"Failed to load LSTM model: {e}")
        self.model.to(self.device)
        self.model.eval()

    def predict(self, endpoints: list[str]) -> float:
        """
        Returns bot probability [0.0, 1.0] for this sequence.
        Falls back to heuristic rules for short sequences.
        """
        if not endpoints:
            return 0.5

        # Heuristic fallback for very short sequences
        if len(endpoints) < 3:
            return self._heuristic_score(endpoints)

        encoded = self.vocab.encode_sequence(endpoints)
        x = torch.tensor([encoded], dtype=torch.long, device=self.device)

        with torch.no_grad():
            prob = self.model(x).item()

        return float(prob)

    def _heuristic_score(self, endpoints: list[str]) -> float:
        """
        Rule-based fallback:
        - Only API endpoints with no page load → likely bot
        - Repeated identical endpoints → likely bot
        - Single endpoint immediately → suspicious
        """
        api_only = all("/api/" in e for e in endpoints)
        all_same = len(set(endpoints)) == 1

        if all_same and len(endpoints) > 2:
            return 0.85
        if api_only:
            return 0.65
        return 0.3

    def record_feedback(self, session_id: str, is_bot: bool):
        # Append (endpoints=[], label) — session_id alone isn't enough to retrain;
        # callers that have the endpoint sequence should use record_sequence_feedback.
        # At minimum, store so retrain() doesn't silently skip every cycle.
        self.feedback.append(([], is_bot))

    def retrain(self):
        """Fine-tune on labeled feedback data."""
        if len(self.feedback) < 200:
            return

        logger.info(f"Fine-tuning LSTM on {len(self.feedback)} labeled samples")
        optimizer = torch.optim.Adam(self.model.parameters(), lr=1e-4)
        criterion = nn.BCELoss()
        self.model.train()

        for epoch in range(5):
            total_loss = 0
            for endpoints, label in self.feedback:
                encoded = self.vocab.encode_sequence(endpoints)
                x = torch.tensor([encoded], dtype=torch.long, device=self.device)
                y = torch.tensor([float(label)], device=self.device)
                optimizer.zero_grad()
                pred = self.model(x)
                loss = criterion(pred, y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            logger.info(f"Epoch {epoch+1}: loss={total_loss/len(self.feedback):.4f}")

        self.model.eval()
        torch.save(self.model.state_dict(), MODEL_PATH)
        logger.info("LSTM model retrained and saved")
