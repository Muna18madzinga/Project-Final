"""
Reinforcement Learning Policy Engine
Uses Deep Q-Network (DQN) for adaptive security policy decisions
"""

import logging
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from collections import deque
import random
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class PolicyState:
    """State representation for RL agent"""
    risk_score: float
    anomaly_score: float
    trust_level: float
    failed_attempts: int
    new_device: bool
    unusual_location: bool
    time_of_day: float
    active_threats_count: int
    user_behavior_score: float
    historical_risk_avg: float

@dataclass
class PolicyAction:
    """Policy action with metadata"""
    action_id: int
    action_name: str
    description: str
    timestamp: datetime

@dataclass
class Transition:
    """Experience replay transition"""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool

class PolicyNetwork(nn.Module):
    """Deep Q-Network for policy decisions"""

    def __init__(self, state_dim: int = 10, action_dim: int = 6):
        super(PolicyNetwork, self).__init__()

        self.network = nn.Sequential(
            nn.Linear(state_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, action_dim)
        )

        self._init_weights()

    def _init_weights(self):
        """Initialize network weights"""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)

    def forward(self, state):
        """Forward pass"""
        return self.network(state)

class DuelingPolicyNetwork(nn.Module):
    """Dueling DQN architecture for better policy learning"""

    def __init__(self, state_dim: int = 10, action_dim: int = 6):
        super(DuelingPolicyNetwork, self).__init__()

        # Shared feature extraction
        self.feature_layer = nn.Sequential(
            nn.Linear(state_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 128),
            nn.ReLU()
        )

        # Value stream
        self.value_stream = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1)
        )

        # Advantage stream
        self.advantage_stream = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, action_dim)
        )

    def forward(self, state):
        """Forward pass with dueling architecture"""
        features = self.feature_layer(state)

        value = self.value_stream(features)
        advantage = self.advantage_stream(features)

        # Combine value and advantage
        # Q(s,a) = V(s) + (A(s,a) - mean(A(s,a)))
        q_values = value + (advantage - advantage.mean(dim=1, keepdim=True))

        return q_values

class RLPolicyAgent:
    """Reinforcement Learning Policy Agent using DQN"""

    # Action definitions
    ACTIONS = {
        0: {'name': 'allow', 'description': 'Allow access without additional checks'},
        1: {'name': 'challenge_mfa', 'description': 'Require MFA verification'},
        2: {'name': 'require_step_up_auth', 'description': 'Require additional authentication factors'},
        3: {'name': 'deny', 'description': 'Deny access completely'},
        4: {'name': 'quarantine', 'description': 'Quarantine user session for review'},
        5: {'name': 'monitor_closely', 'description': 'Allow but monitor all activities'}
    }

    def __init__(self, state_dim: int = 10, action_dim: int = 6, model_dir: str = 'models'):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.model_dir = model_dir

        # Device
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # DQN components
        self.use_dueling = True  # Use Dueling DQN for better performance

        if self.use_dueling:
            self.policy_net = DuelingPolicyNetwork(state_dim, action_dim).to(self.device)
            self.target_net = DuelingPolicyNetwork(state_dim, action_dim).to(self.device)
        else:
            self.policy_net = PolicyNetwork(state_dim, action_dim).to(self.device)
            self.target_net = PolicyNetwork(state_dim, action_dim).to(self.device)

        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        # Training parameters
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=0.0005)
        self.memory = deque(maxlen=10000)  # Experience replay buffer
        self.batch_size = 64
        self.gamma = 0.99  # Discount factor
        self.epsilon = 1.0  # Exploration rate
        self.epsilon_decay = 0.995
        self.epsilon_min = 0.01
        self.target_update_frequency = 10  # Update target network every N episodes

        # Training statistics
        self.training_episodes = 0
        self.total_rewards = []
        self.loss_history = []
        self.action_history = defaultdict(int)

        # Performance metrics
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0

        # Load existing model if available
        self.load_model()

        logger.info(f"RL Policy Agent initialized (Dueling DQN: {self.use_dueling})")

    def get_state_vector(self, context: Dict) -> np.ndarray:
        """Convert context dictionary to state vector"""

        state_components = [
            float(context.get('risk_score', 0.5)),
            float(context.get('anomaly_score', 0.0)),
            float(context.get('trust_level', 1.0)),
            min(float(context.get('failed_attempts', 0)) / 10.0, 1.0),
            float(context.get('new_device', False)),
            float(context.get('unusual_location', False)),
            float(context.get('time_of_day', 12)) / 24.0,
            min(float(len(context.get('active_threats', []))) / 10.0, 1.0),
            float(context.get('user_behavior_score', 0.5)),
            float(context.get('historical_risk_avg', 0.5))
        ]

        # Ensure correct dimension
        while len(state_components) < self.state_dim:
            state_components.append(0.0)

        state = np.array(state_components[:self.state_dim], dtype=np.float32)

        return state

    def select_action(self, state: np.ndarray, training: bool = False) -> int:
        """Select action using epsilon-greedy policy"""

        # Epsilon-greedy exploration
        if training and random.random() < self.epsilon:
            action = random.randrange(self.action_dim)
            logger.debug(f"Exploration: selected random action {action}")
            return action

        # Exploitation: select best action
        with torch.no_grad():
            state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            q_values = self.policy_net(state_tensor)
            action = q_values.argmax().item()

        self.action_history[action] += 1

        return action

    def get_action_name(self, action_id: int) -> str:
        """Get action name from ID"""
        return self.ACTIONS.get(action_id, {}).get('name', 'unknown')

    def store_transition(self, state: np.ndarray, action: int, reward: float,
                        next_state: np.ndarray, done: bool):
        """Store experience in replay memory"""
        self.memory.append(Transition(state, action, reward, next_state, done))

    def train_step(self) -> Optional[float]:
        """Perform one training step"""

        if len(self.memory) < self.batch_size:
            return None

        # Sample batch from memory
        batch = random.sample(self.memory, self.batch_size)

        # Unpack batch
        states = torch.FloatTensor([t.state for t in batch]).to(self.device)
        actions = torch.LongTensor([t.action for t in batch]).to(self.device)
        rewards = torch.FloatTensor([t.reward for t in batch]).to(self.device)
        next_states = torch.FloatTensor([t.next_state for t in batch]).to(self.device)
        dones = torch.FloatTensor([t.done for t in batch]).to(self.device)

        # Compute current Q-values
        current_q_values = self.policy_net(states).gather(1, actions.unsqueeze(1))

        # Compute target Q-values
        with torch.no_grad():
            # Double DQN: use policy net to select action, target net to evaluate
            next_actions = self.policy_net(next_states).argmax(1)
            next_q_values = self.target_net(next_states).gather(1, next_actions.unsqueeze(1)).squeeze()
            target_q_values = rewards + (1 - dones) * self.gamma * next_q_values

        # Compute loss (Huber loss is more robust than MSE)
        loss = nn.SmoothL1Loss()(current_q_values.squeeze(), target_q_values)

        # Optimize
        self.optimizer.zero_grad()
        loss.backward()

        # Gradient clipping for stability
        torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), max_norm=1.0)

        self.optimizer.step()

        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

        # Record loss
        self.loss_history.append(loss.item())

        return loss.item()

    def update_target_network(self):
        """Update target network with policy network weights"""
        self.target_net.load_state_dict(self.policy_net.state_dict())
        logger.info("Target network updated")

    def calculate_reward(self, outcome: Dict) -> float:
        """
        Calculate reward based on action outcome

        Reward structure:
        +1.0: Successfully blocked real threat (True Positive)
        -2.0: Missed real threat (False Negative) - SEVERE
        -0.5: Blocked legitimate user (False Positive)
        +0.2: Correctly allowed legitimate user (True Negative)
        -0.2: User friction without threat (e.g., unnecessary MFA challenge)
        +0.5: Early threat detection before damage
        """

        reward = 0.0

        # Threat handling rewards
        if outcome.get('threat_blocked'):
            reward += 1.0
            self.true_positives += 1
            logger.info("Reward +1.0: Threat blocked successfully")

        if outcome.get('false_negative'):
            reward -= 2.0
            self.false_negatives += 1
            logger.warning("Reward -2.0: Missed threat (false negative)")

        if outcome.get('false_positive'):
            reward -= 0.5
            self.false_positives += 1
            logger.warning("Reward -0.5: False positive (blocked legitimate user)")

        if outcome.get('true_negative'):
            reward += 0.2
            self.true_negatives += 1

        # User experience penalties
        if outcome.get('user_denied_access') and not outcome.get('threat_blocked'):
            reward -= 0.2

        if outcome.get('unnecessary_friction'):
            reward -= 0.1

        # Bonus rewards
        if outcome.get('early_detection'):
            reward += 0.5
            logger.info("Reward +0.5: Early threat detection")

        if outcome.get('prevented_data_breach'):
            reward += 2.0
            logger.info("Reward +2.0: Prevented data breach")

        return reward

    def train_episode(self, num_steps: int = 100):
        """Train for one episode"""

        episode_reward = 0.0
        losses = []

        for step in range(num_steps):
            # Sample random state for training
            state = np.random.rand(self.state_dim).astype(np.float32)

            # Select action
            action = self.select_action(state, training=True)

            # Simulate outcome (in production, use real outcomes)
            outcome = self._simulate_outcome(state, action)
            reward = self.calculate_reward(outcome)

            # Next state
            next_state = np.random.rand(self.state_dim).astype(np.float32)
            done = (step == num_steps - 1)

            # Store transition
            self.store_transition(state, action, reward, next_state, done)

            # Train
            loss = self.train_step()
            if loss is not None:
                losses.append(loss)

            episode_reward += reward

        self.training_episodes += 1
        self.total_rewards.append(episode_reward)

        # Update target network periodically
        if self.training_episodes % self.target_update_frequency == 0:
            self.update_target_network()

        avg_loss = np.mean(losses) if losses else 0.0

        logger.info(f"Episode {self.training_episodes}: Reward={episode_reward:.2f}, Loss={avg_loss:.4f}, Epsilon={self.epsilon:.3f}")

        return episode_reward, avg_loss

    def _simulate_outcome(self, state: np.ndarray, action: int) -> Dict:
        """Simulate action outcome for training (replace with real feedback)"""

        risk_score = state[0]

        # Simulate outcomes based on risk and action
        is_real_threat = risk_score > 0.7

        outcome = {
            'threat_blocked': False,
            'false_positive': False,
            'false_negative': False,
            'true_negative': False,
            'user_denied_access': False,
            'unnecessary_friction': False,
            'early_detection': False
        }

        if action == 3:  # Deny
            outcome['user_denied_access'] = True
            if is_real_threat:
                outcome['threat_blocked'] = True
            else:
                outcome['false_positive'] = True

        elif action == 0:  # Allow
            if is_real_threat:
                outcome['false_negative'] = True
            else:
                outcome['true_negative'] = True

        elif action in [1, 2]:  # MFA challenges
            if is_real_threat:
                outcome['threat_blocked'] = True
                outcome['early_detection'] = True
            else:
                outcome['unnecessary_friction'] = True
                outcome['true_negative'] = True

        return outcome

    def evaluate_policy(self, num_episodes: int = 10) -> Dict:
        """Evaluate current policy"""

        total_reward = 0.0
        action_counts = defaultdict(int)

        for _ in range(num_episodes):
            state = np.random.rand(self.state_dim).astype(np.float32)
            action = self.select_action(state, training=False)
            action_counts[action] += 1

            outcome = self._simulate_outcome(state, action)
            reward = self.calculate_reward(outcome)
            total_reward += reward

        avg_reward = total_reward / num_episodes

        return {
            'average_reward': avg_reward,
            'action_distribution': dict(action_counts),
            'epsilon': self.epsilon,
            'training_episodes': self.training_episodes
        }

    def save_model(self, filename: Optional[str] = None):
        """Save model to disk"""

        os.makedirs(self.model_dir, exist_ok=True)

        if filename is None:
            filename = f'rl_policy_model_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pt'

        filepath = os.path.join(self.model_dir, filename)

        torch.save({
            'policy_net_state_dict': self.policy_net.state_dict(),
            'target_net_state_dict': self.target_net.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'epsilon': self.epsilon,
            'training_episodes': self.training_episodes,
            'total_rewards': self.total_rewards,
            'loss_history': self.loss_history,
            'action_history': dict(self.action_history),
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'true_negatives': self.true_negatives,
            'false_negatives': self.false_negatives
        }, filepath)

        logger.info(f"Model saved to {filepath}")

    def load_model(self, filename: Optional[str] = None):
        """Load model from disk"""

        if filename is None:
            # Find most recent model
            if not os.path.exists(self.model_dir):
                logger.info("No existing model found")
                return

            models = [f for f in os.listdir(self.model_dir) if f.startswith('rl_policy_model') and f.endswith('.pt')]
            if not models:
                logger.info("No existing model found")
                return

            filename = sorted(models)[-1]

        filepath = os.path.join(self.model_dir, filename)

        if not os.path.exists(filepath):
            logger.info(f"Model file not found: {filepath}")
            return

        try:
            checkpoint = torch.load(filepath, map_location=self.device)

            self.policy_net.load_state_dict(checkpoint['policy_net_state_dict'])
            self.target_net.load_state_dict(checkpoint['target_net_state_dict'])
            self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
            self.epsilon = checkpoint['epsilon']
            self.training_episodes = checkpoint['training_episodes']
            self.total_rewards = checkpoint['total_rewards']
            self.loss_history = checkpoint['loss_history']
            self.action_history = defaultdict(int, checkpoint.get('action_history', {}))
            self.true_positives = checkpoint.get('true_positives', 0)
            self.false_positives = checkpoint.get('false_positives', 0)
            self.true_negatives = checkpoint.get('true_negatives', 0)
            self.false_negatives = checkpoint.get('false_negatives', 0)

            logger.info(f"Model loaded from {filepath} (Episode {self.training_episodes})")

        except Exception as e:
            logger.error(f"Failed to load model: {e}")

    def get_model_info(self) -> Dict:
        """Get model information and statistics"""

        accuracy = 0.0
        precision = 0.0
        recall = 0.0

        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if total > 0:
            accuracy = (self.true_positives + self.true_negatives) / total

        if (self.true_positives + self.false_positives) > 0:
            precision = self.true_positives / (self.true_positives + self.false_positives)

        if (self.true_positives + self.false_negatives) > 0:
            recall = self.true_positives / (self.true_positives + self.false_negatives)

        return {
            'model_type': 'Dueling DQN' if self.use_dueling else 'DQN',
            'state_dim': self.state_dim,
            'action_dim': self.action_dim,
            'training_episodes': self.training_episodes,
            'epsilon': self.epsilon,
            'avg_reward_last_100': np.mean(self.total_rewards[-100:]) if self.total_rewards else 0.0,
            'avg_loss_last_100': np.mean(self.loss_history[-100:]) if self.loss_history else 0.0,
            'action_distribution': dict(self.action_history),
            'performance_metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'true_positives': self.true_positives,
                'false_positives': self.false_positives,
                'true_negatives': self.true_negatives,
                'false_negatives': self.false_negatives
            }
        }

# Global RL agent instance
_rl_agent = None

def get_rl_policy_agent() -> RLPolicyAgent:
    """Get global RL policy agent instance"""
    global _rl_agent
    if _rl_agent is None:
        _rl_agent = RLPolicyAgent()
    return _rl_agent
