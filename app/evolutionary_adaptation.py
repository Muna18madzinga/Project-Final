"""
Evolutionary Adaptation Algorithm - Chapter 3.5 Algorithm Design
Model retraining with genetic algorithms using DEAP library for population management.
Implements evolutionary techniques for non-stationary data adaptation.
"""

import logging
import numpy as np
import torch
import torch.nn as nn
from typing import Dict, List, Any, Tuple, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
import copy
import random
from collections import deque
import json

# DEAP (Distributed Evolutionary Algorithms in Python)
from deap import base, creator, tools, algorithms
import mlflow

from .architecture.analytics_layer import HybridAnomalyDetector, AnalyticsEngine
from .data_preprocessing import DatasetProcessor

logger = logging.getLogger(__name__)

@dataclass
class EvolutionaryConfig:
    """Configuration for evolutionary adaptation."""
    population_size: int = 20
    generations: int = 30
    mutation_rate: float = 0.05
    crossover_rate: float = 0.7
    selection_tournament_size: int = 3
    elitism_rate: float = 0.1
    fitness_metric: str = 'macro_f1'  # 'macro_f1', 'accuracy', 'loss'

@dataclass
class Individual:
    """Individual in the evolutionary population."""
    model_weights: Dict[str, torch.Tensor]
    architecture_params: Dict[str, Any]
    fitness: float
    generation: int
    mutation_history: List[str]

@dataclass
class EvolutionResult:
    """Result of evolutionary adaptation."""
    best_individual: Individual
    best_fitness: float
    generation_stats: List[Dict[str, float]]
    adaptation_time: float
    convergence_generation: int
    population_diversity: List[float]

class ModelEvolutionOperators:
    """Genetic operators for neural network evolution."""

    def __init__(self, model_template: nn.Module):
        self.model_template = model_template
        self.weight_mutation_std = 0.05
        self.architecture_mutations = [
            'adjust_hidden_dim',
            'adjust_dropout',
            'adjust_learning_rate',
            'adjust_num_layers'
        ]

    def create_individual(self, model: nn.Module) -> Individual:
        """Create an individual from a PyTorch model."""
        # Extract model weights
        model_weights = {}
        for name, param in model.named_parameters():
            model_weights[name] = param.data.clone()

        # Extract architecture parameters
        architecture_params = {
            'hidden_dim': getattr(model, 'hidden_dim', 256),
            'num_lstm_layers': getattr(model.lstm, 'num_layers', 3),
            'num_transformer_layers': getattr(model.transformer, 'num_layers', 2),
            'dropout': 0.3,  # Default dropout
        }

        return Individual(
            model_weights=model_weights,
            architecture_params=architecture_params,
            fitness=0.0,
            generation=0,
            mutation_history=[]
        )

    def mutate_individual(self, individual: Individual,
                         mutation_strength: float = 0.05) -> Individual:
        """
        Mutate individual with Gaussian perturbations.
        Implements mutation from Chapter 3.5: Gaussian perturbations (std=0.05).
        """
        mutated = copy.deepcopy(individual)

        # Weight mutations
        for name, weights in mutated.model_weights.items():
            if random.random() < 0.3:  # 30% chance to mutate each weight tensor
                # Gaussian noise with configurable standard deviation
                noise = torch.randn_like(weights) * mutation_strength
                mutated.model_weights[name] = weights + noise
                mutated.mutation_history.append(f"weight_mutation_{name}")

        # Architecture mutations
        if random.random() < 0.2:  # 20% chance for architecture mutation
            mutation_type = random.choice(self.architecture_mutations)
            self._apply_architecture_mutation(mutated, mutation_type)
            mutated.mutation_history.append(f"arch_mutation_{mutation_type}")

        return mutated

    def _apply_architecture_mutation(self, individual: Individual,
                                   mutation_type: str):
        """Apply architecture-specific mutations."""
        if mutation_type == 'adjust_hidden_dim':
            # Adjust hidden dimension (±32 units)
            current = individual.architecture_params['hidden_dim']
            delta = random.choice([-32, -16, 16, 32])
            individual.architecture_params['hidden_dim'] = max(64, min(512, current + delta))

        elif mutation_type == 'adjust_dropout':
            # Adjust dropout rate (±0.1)
            current = individual.architecture_params.get('dropout', 0.3)
            delta = random.uniform(-0.1, 0.1)
            individual.architecture_params['dropout'] = max(0.0, min(0.7, current + delta))

        elif mutation_type == 'adjust_num_layers':
            # Adjust number of LSTM layers
            current = individual.architecture_params['num_lstm_layers']
            if random.random() < 0.5 and current > 1:
                individual.architecture_params['num_lstm_layers'] = current - 1
            elif current < 5:
                individual.architecture_params['num_lstm_layers'] = current + 1

    def crossover_individuals(self, parent1: Individual,
                            parent2: Individual) -> Tuple[Individual, Individual]:
        """
        Perform uniform crossover on parameters.
        Implements crossover from Chapter 3.5: Uniform crossover on parameters.
        """
        child1 = copy.deepcopy(parent1)
        child2 = copy.deepcopy(parent2)

        # Weight crossover
        for name in parent1.model_weights.keys():
            if name in parent2.model_weights:
                # Uniform crossover at tensor level
                if random.random() < 0.5:
                    # Blend weights
                    alpha = random.uniform(0.3, 0.7)
                    child1.model_weights[name] = (
                        alpha * parent1.model_weights[name] +
                        (1 - alpha) * parent2.model_weights[name]
                    )
                    child2.model_weights[name] = (
                        alpha * parent2.model_weights[name] +
                        (1 - alpha) * parent1.model_weights[name]
                    )

        # Architecture parameter crossover
        for param in parent1.architecture_params.keys():
            if param in parent2.architecture_params:
                if random.random() < 0.5:
                    child1.architecture_params[param] = parent2.architecture_params[param]
                    child2.architecture_params[param] = parent1.architecture_params[param]

        return child1, child2

    def create_model_from_individual(self, individual: Individual) -> nn.Module:
        """Create a PyTorch model from an individual."""
        # Create model with evolved architecture
        model = HybridAnomalyDetector(
            input_dim=49,  # UNSW-NB15 features
            hidden_dim=individual.architecture_params['hidden_dim'],
            num_lstm_layers=individual.architecture_params['num_lstm_layers'],
            num_transformer_layers=individual.architecture_params['num_transformer_layers'],
            dropout=individual.architecture_params.get('dropout', 0.3)
        )

        # Load evolved weights
        for name, param in model.named_parameters():
            if name in individual.model_weights:
                param.data = individual.model_weights[name].clone()

        return model

class FitnessEvaluator:
    """Fitness evaluation for evolved models."""

    def __init__(self, validation_data: Tuple[torch.Tensor, torch.Tensor],
                 device: str = 'cpu'):
        self.X_val, self.y_val = validation_data
        self.device = torch.device(device)

    def evaluate_fitness(self, individual: Individual) -> float:
        """
        Evaluate fitness using macro F1-score - regularization term.
        Implements fitness evaluation from Chapter 3.5.
        """
        try:
            # Create model from individual
            model_ops = ModelEvolutionOperators(None)
            model = model_ops.create_model_from_individual(individual)
            model.to(self.device)
            model.eval()

            # Evaluate on validation data
            with torch.no_grad():
                # Convert to sequences for LSTM-Transformer model
                X_sequences = self._create_sequences(self.X_val, sequence_length=10)
                y_sequences = self.y_val[:len(X_sequences)]

                X_tensor = torch.FloatTensor(X_sequences).to(self.device)
                y_tensor = torch.LongTensor(y_sequences).to(self.device)

                # Model predictions
                outputs = model(X_tensor)
                predictions = (outputs > 0.5).float().squeeze()

                # Calculate metrics
                macro_f1 = self._calculate_macro_f1(predictions.cpu().numpy(),
                                                  y_tensor.cpu().numpy())

                # Regularization term (model complexity penalty)
                complexity_penalty = self._calculate_complexity_penalty(individual)

                # Final fitness: macro F1-score - regularization
                fitness = macro_f1 - complexity_penalty

                return fitness

        except Exception as e:
            logger.error(f"Fitness evaluation failed: {e}")
            return 0.0  # Assign low fitness for failed evaluations

    def _create_sequences(self, X: torch.Tensor, sequence_length: int) -> np.ndarray:
        """Create sequences from tensor data."""
        sequences = []
        X_np = X.numpy()

        for i in range(len(X_np) - sequence_length + 1):
            sequences.append(X_np[i:i+sequence_length])

        return np.array(sequences)

    def _calculate_macro_f1(self, predictions: np.ndarray,
                          targets: np.ndarray) -> float:
        """Calculate macro F1-score."""
        from sklearn.metrics import f1_score

        try:
            # Handle binary classification
            if len(np.unique(targets)) == 2:
                return f1_score(targets, predictions, average='binary')
            else:
                return f1_score(targets, predictions, average='macro', zero_division=0)
        except Exception:
            return 0.0

    def _calculate_complexity_penalty(self, individual: Individual) -> float:
        """Calculate model complexity penalty."""
        # Architecture complexity
        hidden_dim = individual.architecture_params.get('hidden_dim', 256)
        num_layers = (individual.architecture_params.get('num_lstm_layers', 3) +
                     individual.architecture_params.get('num_transformer_layers', 2))

        # Normalize complexity penalty
        complexity = (hidden_dim / 512.0) * 0.1 + (num_layers / 10.0) * 0.1

        return min(complexity, 0.2)  # Cap at 0.2

class EvolutionaryAdaptationEngine:
    """
    Main evolutionary adaptation engine implementing Chapter 3.5 algorithm.
    Evolutionary Model Retraining: Model retraining with genetic algorithms.
    """

    def __init__(self, config: EvolutionaryConfig = None):
        self.config = config or EvolutionaryConfig()
        self.evolution_history = deque(maxlen=1000)
        self.best_models = deque(maxlen=10)  # Keep best models from each run

        # DEAP setup
        self._setup_deap()

    def _setup_deap(self):
        """Setup DEAP genetic algorithm framework."""
        # Create fitness and individual classes
        creator.create("FitnessMax", base.Fitness, weights=(1.0,))  # Maximize fitness
        creator.create("Individual", Individual, fitness=creator.FitnessMax)

        # Create toolbox
        self.toolbox = base.Toolbox()

        # Register selection, crossover, and mutation
        self.toolbox.register("select", tools.selTournament,
                            tournsize=self.config.selection_tournament_size)
        self.toolbox.register("mate", self._crossover_wrapper)
        self.toolbox.register("mutate", self._mutation_wrapper)

    def _crossover_wrapper(self, ind1, ind2):
        """Wrapper for DEAP crossover."""
        model_ops = ModelEvolutionOperators(None)
        child1, child2 = model_ops.crossover_individuals(ind1, ind2)
        return child1, child2

    def _mutation_wrapper(self, individual):
        """Wrapper for DEAP mutation."""
        model_ops = ModelEvolutionOperators(None)
        mutated = model_ops.mutate_individual(individual, self.config.mutation_rate)
        return mutated,  # DEAP expects tuple

    def adapt_model(self, base_model: nn.Module,
                   new_data_batch: Tuple[torch.Tensor, torch.Tensor],
                   validation_data: Tuple[torch.Tensor, torch.Tensor]) -> EvolutionResult:
        """
        Evolutionary Model Adaptation as per Chapter 3.5 pseudocode:

        Input: Earlier model M, new data batch B
        Output: Model adapted M'

        1. Population: Generate 20 copies of M (mutate weights/architecture)
        2. Fitness: Assess on B using macro F1-score - regularization term
        3. For generations=30:
           - Choose top 60% through tournament selection
           - Crossover: Uniform crossover on parameters
           - Mutate: Gaussian perturbations (std=0.05)
           - Elitism: Conserve top individual
        4. Return best M' with version control in MLflow
        """
        logger.info("Starting evolutionary model adaptation")
        start_time = datetime.now()

        # Setup fitness evaluator
        fitness_evaluator = FitnessEvaluator(validation_data)

        # Create initial population (20 copies of M with mutations)
        population = self._create_initial_population(base_model)

        # Evolution statistics tracking
        generation_stats = []
        diversity_history = []

        with mlflow.start_run(run_name=f"evolutionary_adaptation_{start_time.strftime('%Y%m%d_%H%M%S')}"):
            # Log parameters
            mlflow.log_params({
                'population_size': self.config.population_size,
                'generations': self.config.generations,
                'mutation_rate': self.config.mutation_rate,
                'crossover_rate': self.config.crossover_rate,
                'fitness_metric': self.config.fitness_metric
            })

            # Evolution loop: For generations=30
            for generation in range(self.config.generations):
                logger.info(f"Generation {generation + 1}/{self.config.generations}")

                # Evaluate fitness for all individuals
                fitnesses = []
                for individual in population:
                    fitness = fitness_evaluator.evaluate_fitness(individual)
                    individual.fitness = fitness
                    fitnesses.append(fitness)

                # Statistics for this generation
                gen_stats = {
                    'generation': generation,
                    'best_fitness': max(fitnesses),
                    'mean_fitness': np.mean(fitnesses),
                    'std_fitness': np.std(fitnesses),
                    'worst_fitness': min(fitnesses)
                }
                generation_stats.append(gen_stats)

                # Calculate population diversity
                diversity = self._calculate_population_diversity(population)
                diversity_history.append(diversity)

                # Log to MLflow
                mlflow.log_metrics({
                    'best_fitness': gen_stats['best_fitness'],
                    'mean_fitness': gen_stats['mean_fitness'],
                    'population_diversity': diversity
                }, step=generation)

                logger.info(f"Generation {generation + 1} - Best: {gen_stats['best_fitness']:.4f}, "
                          f"Mean: {gen_stats['mean_fitness']:.4f}, Diversity: {diversity:.4f}")

                # Selection: Choose top 60% through tournament selection
                elite_count = int(self.config.population_size * self.config.elitism_rate)
                selection_count = int(self.config.population_size * 0.6)

                # Elitism: Conserve top individual(s)
                population.sort(key=lambda x: x.fitness, reverse=True)
                elite = population[:elite_count]

                # Tournament selection for breeding
                selected = []
                for _ in range(selection_count - elite_count):
                    tournament = random.sample(population, self.config.selection_tournament_size)
                    winner = max(tournament, key=lambda x: x.fitness)
                    selected.append(copy.deepcopy(winner))

                # Combine elite and selected
                breeding_population = elite + selected

                # Generate offspring through crossover and mutation
                offspring = []

                # Add elite directly (no modification)
                offspring.extend([copy.deepcopy(ind) for ind in elite])

                # Generate new individuals through crossover
                while len(offspring) < self.config.population_size:
                    if len(breeding_population) >= 2:
                        parent1, parent2 = random.sample(breeding_population, 2)

                        if random.random() < self.config.crossover_rate:
                            # Crossover: Uniform crossover on parameters
                            child1, child2 = self._crossover_wrapper(parent1, parent2)
                            offspring.extend([child1, child2])
                        else:
                            # No crossover, just copy parents
                            offspring.extend([copy.deepcopy(parent1), copy.deepcopy(parent2)])
                    else:
                        # Not enough parents, mutate existing individuals
                        parent = random.choice(breeding_population)
                        child = copy.deepcopy(parent)
                        offspring.append(child)

                # Mutate offspring (except elite)
                for i in range(elite_count, len(offspring)):
                    if random.random() < self.config.mutation_rate:
                        # Mutate: Gaussian perturbations (std=0.05)
                        offspring[i] = self._mutation_wrapper(offspring[i])[0]
                        offspring[i].generation = generation + 1

                # Ensure population size
                population = offspring[:self.config.population_size]

                # Early convergence check
                if self._check_convergence(generation_stats, window=5):
                    logger.info(f"Convergence detected at generation {generation + 1}")
                    break

            # Find best individual from final population
            final_fitnesses = [fitness_evaluator.evaluate_fitness(ind) for ind in population]
            best_idx = np.argmax(final_fitnesses)
            best_individual = population[best_idx]
            best_individual.fitness = final_fitnesses[best_idx]

            # Create best model
            model_ops = ModelEvolutionOperators(None)
            best_model = model_ops.create_model_from_individual(best_individual)

            # Save best model with MLflow version control
            mlflow.pytorch.log_model(best_model, "evolved_model")
            mlflow.log_metric('final_best_fitness', best_individual.fitness)

            adaptation_time = (datetime.now() - start_time).total_seconds()

            result = EvolutionResult(
                best_individual=best_individual,
                best_fitness=best_individual.fitness,
                generation_stats=generation_stats,
                adaptation_time=adaptation_time,
                convergence_generation=len(generation_stats),
                population_diversity=diversity_history
            )

            # Store in history
            self.evolution_history.append(result)
            self.best_models.append(best_model)

            logger.info(f"Evolutionary adaptation completed in {adaptation_time:.2f} seconds")
            logger.info(f"Best fitness achieved: {best_individual.fitness:.4f}")

            return result

    def _create_initial_population(self, base_model: nn.Module) -> List[Individual]:
        """Create initial population with 20 copies of base model (with mutations)."""
        population = []
        model_ops = ModelEvolutionOperators(base_model)

        for i in range(self.config.population_size):
            # Create individual from base model
            individual = model_ops.create_individual(base_model)

            # Apply initial mutation to create diversity
            if i > 0:  # Keep first individual as-is (elite from previous)
                individual = model_ops.mutate_individual(individual,
                                                       mutation_strength=self.config.mutation_rate * 2)

            individual.generation = 0
            population.append(individual)

        logger.info(f"Created initial population of {len(population)} individuals")
        return population

    def _calculate_population_diversity(self, population: List[Individual]) -> float:
        """Calculate population diversity based on fitness variance."""
        fitnesses = [ind.fitness for ind in population]
        if len(set(fitnesses)) <= 1:
            return 0.0

        # Normalize fitness values
        min_fitness = min(fitnesses)
        max_fitness = max(fitnesses)

        if max_fitness - min_fitness == 0:
            return 0.0

        normalized_fitness = [(f - min_fitness) / (max_fitness - min_fitness)
                            for f in fitnesses]

        # Calculate coefficient of variation
        mean_fitness = np.mean(normalized_fitness)
        std_fitness = np.std(normalized_fitness)

        diversity = std_fitness / (mean_fitness + 1e-8)
        return diversity

    def _check_convergence(self, generation_stats: List[Dict],
                         window: int = 5) -> bool:
        """Check if evolution has converged."""
        if len(generation_stats) < window:
            return False

        recent_stats = generation_stats[-window:]
        best_fitnesses = [stats['best_fitness'] for stats in recent_stats]

        # Check if improvement is minimal
        fitness_improvement = max(best_fitnesses) - min(best_fitnesses)
        return fitness_improvement < 0.001  # Convergence threshold

    def get_adaptation_stats(self) -> Dict[str, Any]:
        """Get evolutionary adaptation statistics."""
        if not self.evolution_history:
            return {'total_adaptations': 0}

        recent_results = list(self.evolution_history)[-10:]  # Last 10 adaptations

        avg_adaptation_time = np.mean([r.adaptation_time for r in recent_results])
        avg_best_fitness = np.mean([r.best_fitness for r in recent_results])
        avg_generations = np.mean([r.convergence_generation for r in recent_results])

        return {
            'total_adaptations': len(self.evolution_history),
            'recent_adaptations': len(recent_results),
            'avg_adaptation_time': avg_adaptation_time,
            'avg_best_fitness': avg_best_fitness,
            'avg_generations_to_convergence': avg_generations,
            'best_models_stored': len(self.best_models),
            'config': {
                'population_size': self.config.population_size,
                'generations': self.config.generations,
                'mutation_rate': self.config.mutation_rate,
                'crossover_rate': self.config.crossover_rate
            }
        }

    def save_evolution_results(self, output_dir: str):
        """Save evolution results and best models."""
        import os
        from pathlib import Path

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save evolution history
        history_data = []
        for result in self.evolution_history:
            history_data.append({
                'best_fitness': result.best_fitness,
                'adaptation_time': result.adaptation_time,
                'convergence_generation': result.convergence_generation,
                'generation_stats': result.generation_stats,
                'population_diversity': result.population_diversity
            })

        with open(output_path / 'evolution_history.json', 'w') as f:
            json.dump(history_data, f, indent=2, default=str)

        # Save best models
        for i, model in enumerate(self.best_models):
            model_path = output_path / f'best_model_{i}.pth'
            torch.save(model.state_dict(), model_path)

        logger.info(f"Evolution results saved to {output_dir}")

# Global evolutionary adaptation engine instance
_evolutionary_engine = None

def get_evolutionary_engine() -> EvolutionaryAdaptationEngine:
    """Get global evolutionary adaptation engine instance."""
    global _evolutionary_engine
    if _evolutionary_engine is None:
        _evolutionary_engine = EvolutionaryAdaptationEngine()
    return _evolutionary_engine