import json
import os
import random
import subprocess
from datetime import datetime
from typing import Tuple, List, Any

from fuzzingbook.Fuzzer import Runner, PrintRunner
from fuzzingbook.GreyboxFuzzer import Seed, PowerSchedule, Mutator, getPathID
from fuzzingbook.MutationFuzzer import FunctionCoverageRunner

Outcome = str


class Fuzzer:
    def __init__(self) -> None:
        pass

    def fuzz(self) -> str:
        return ""

    def run(self, runner: Runner = Runner()) \
            -> Tuple[subprocess.CompletedProcess, Outcome]:
        return runner.run(self.fuzz())

    def runs(self, runner: Runner = PrintRunner(), trials: int = 10) \
            -> List[Tuple[subprocess.CompletedProcess, Outcome]]:
        return [self.run(runner) for i in range(trials)]


class AdvancedMutationFuzzer(Fuzzer):
    def __init__(self, seeds: List[str], mutator: Mutator, schedule: PowerSchedule) -> None:
        self.seeds = seeds
        self.mutator = mutator
        self.schedule = schedule
        self.inputs: List[str] = []
        self.max_trials = 1
        self.reset()

    def reset(self) -> None:
        self.population = list(map(lambda x: Seed(x), self.seeds))
        self.seed_index = 0

    def create_candidate(self) -> str:
        seed = self.schedule.choose(self.population)
        candidate = seed.data
        trials = min(len(candidate), 1 << random.randint(1, 5), self.max_trials)
        for i in range(trials):
            candidate = self.mutator.mutate(candidate)
        return candidate

    def fuzz(self) -> str:
        if self.seed_index < len(self.seeds):
            self.inp = self.seeds[self.seed_index]
            self.seed_index += 1
        else:
            self.inp = self.create_candidate()
        self.inputs.append(self.inp)
        return self.inp

    def save_population(self, prefix: str) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = "zeeguu/core/test/fuzzing_test/results"
        filename = f"{path}/{prefix}-corpus-{timestamp}.json"
        if not os.path.exists(path):
            os.makedirs(path)

        with open(filename, "w") as f:
            json.dump([str(member) for member in self.population], f, indent=2)


class GecGreyboxFuzzer(AdvancedMutationFuzzer):
    def __init__(self, seeds: List[str], mutator: Mutator, schedule: PowerSchedule, max_population=100):
        super().__init__(seeds, mutator, schedule)
        self.max_population = max_population

    def reset(self):
        super().reset()
        self.coverages_seen = set()
        self.population = []

    def add_to_population(self, seed: Seed):
        if len(self.population) < self.max_population:
            self.population.append(seed)
        else:
            min_seed_energy = min(s.energy for s in self.population)
            for i in range(len(self.population)):
                if self.population[i].energy == min_seed_energy:
                    self.population[i] = seed
                    break

    def run(self, runner: FunctionCoverageRunner) -> Tuple[subprocess.CompletedProcess, Outcome, bool]:
        result, outcome = super().run(runner)
        new_coverage = frozenset(runner.coverage())
        coverage_increased = False
        if new_coverage not in self.coverages_seen:
            coverage_increased = True
            seed = Seed(self.inp)
            seed.coverage = runner.coverage()
            self.coverages_seen.add(new_coverage)
            self.add_to_population(seed)
        return result, outcome, coverage_increased

class UnguidedFuzzer(AdvancedMutationFuzzer):
    def __init__(self, seeds: List[str], mutator: Mutator, schedule: PowerSchedule, max_population=100):
        super().__init__(seeds, mutator, schedule)
        self.max_population = max_population

    def reset(self):
        super().reset()
        self.population = []

    def add_to_population(self, seed: Seed):
        if len(self.population) < self.max_population:
            self.population.append(seed)

    def run(self, runner: FunctionCoverageRunner) -> Tuple[subprocess.CompletedProcess, Outcome]:
        result, outcome = super().run(runner)
        seed = Seed(self.inp)
        self.add_to_population(seed)
        return result, outcome


class CountingGreyboxFuzzer(GecGreyboxFuzzer):
    def reset(self):
        super().reset()
        self.schedule.path_frequency = {}

    def run(self, runner: FunctionCoverageRunner) -> Tuple[Any, str, bool]:
        result, outcome, coverage_increased = super().run(runner)
        path_id = getPathID(runner.coverage())
        if path_id not in self.schedule.path_frequency:
            self.schedule.path_frequency[path_id] = 1
        else:
            self.schedule.path_frequency[path_id] += 1
        return result, outcome, coverage_increased
