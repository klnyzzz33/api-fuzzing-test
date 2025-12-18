import json
import os
import random
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Tuple, List, Any, Set, Union

from fuzzingbook.Coverage import Location
from fuzzingbook.Fuzzer import Runner, PrintRunner
from fuzzingbook.GreyboxFuzzer import PowerSchedule, Mutator, getPathID
from fuzzingbook.MutationFuzzer import FunctionCoverageRunner

Outcome = str


@dataclass
class TestResult:
    original_sentence: str
    corpus_result_mapping: list[dict[str, Any]]
    coverage: set[frozenset[tuple[str, int]]]

    def to_json(self, filename: str) -> None:
        data = asdict(self)
        data["coverage"] = [list(cov) for cov in self.coverage]
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def from_json(filename: str):
        with open(filename, "r") as f:
            data = json.load(f)
        data["coverage"] = {frozenset(tuple(x) for x in cov) for cov in data["coverage"]}
        return TestResult(**data)


class Seed:
    def __init__(self, data: str) -> None:
        self.data = data

        self.coverage: Set[Location] = set()
        self.distance: Union[int, float] = -1
        self.energy = 0.0

    def __str__(self) -> str:
        return self.data

    __repr__ = __str__

    def __eq__(self, other):
        if not isinstance(other, Seed):
            return False
        return self.data == other.data

    def __hash__(self):
        return hash(self.data)


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
        self.coverages_seen = set()

    def reset(self) -> None:
        self.population = list(map(lambda x: Seed(x), self.seeds))
        self.seed_index = 0
        self.expected_results = {}

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

    def save_population(self, postfix: str, original_sentence: str) -> None:
        result = TestResult(
            original_sentence=original_sentence,
            corpus_result_mapping=[{"input": str(seed), "output": self.expected_results[seed.data]}
                                   for seed in self.population],
            coverage=self.coverages_seen
        )
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = "zeeguu/core/test/fuzzing_test/results"
        filename = f"{path}/corpus-{timestamp}-{postfix}.json"
        if not os.path.exists(path):
            os.makedirs(path)
        result.to_json(filename)


class UnguidedFuzzer(AdvancedMutationFuzzer):
    def __init__(self, seeds: List[str], mutator: Mutator, schedule: PowerSchedule, max_population=100):
        super().__init__(seeds, mutator, schedule)
        self.max_population = max_population

    def reset(self):
        super().reset()
        self.population = []

    def add_to_population(self, seed: Seed, result: subprocess.CompletedProcess):
        if len(self.population) < self.max_population:
            self.population.append(seed)
            self.expected_results[seed.data] = result

    def run(self, runner: FunctionCoverageRunner) -> Tuple[subprocess.CompletedProcess, Outcome]:
        result, outcome = super().run(runner)
        new_coverage = frozenset(runner.coverage())
        if new_coverage not in self.coverages_seen:
            self.coverages_seen.add(new_coverage)
        seed = Seed(self.inp)
        if seed not in self.population:
            self.add_to_population(seed, result)
        return result, outcome


class GecGreyboxFuzzer(AdvancedMutationFuzzer):
    def __init__(self, seeds: List[str], mutator: Mutator, schedule: PowerSchedule, max_population=100):
        super().__init__(seeds, mutator, schedule)
        self.max_population = max_population

    def reset(self):
        super().reset()
        self.coverages_seen = set()
        self.population = []

    def add_to_population(self, seed: Seed, result: subprocess.CompletedProcess):
        if len(self.population) < self.max_population:
            self.population.append(seed)
            self.expected_results[seed.data] = result
        else:
            min_seed_energy = min(s.energy for s in self.population)
            for i in range(len(self.population)):
                if self.population[i].energy == min_seed_energy:
                    self.expected_results.pop(self.population[i].data)
                    self.population[i] = seed
                    self.expected_results[seed.data] = result
                    break

    def run(self, runner: FunctionCoverageRunner) -> Tuple[subprocess.CompletedProcess, Outcome, bool]:
        result, outcome = super().run(runner)
        new_coverage = frozenset(runner.coverage())
        coverage_increased = False
        if new_coverage not in self.coverages_seen:
            coverage_increased = True
            self.coverages_seen.add(new_coverage)
            seed = Seed(self.inp)
            seed.coverage = runner.coverage()
            if seed not in self.population:
                self.add_to_population(seed, result)
        return result, outcome, coverage_increased


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
