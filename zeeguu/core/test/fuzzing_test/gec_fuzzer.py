import random
import subprocess
from typing import Tuple, List

from fuzzingbook.Fuzzer import Runner, PrintRunner
from fuzzingbook.GreyboxFuzzer import Seed, PowerSchedule, Mutator
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
        super().__init__()
        self.seeds = seeds
        self.mutator = mutator
        self.schedule = schedule
        self.inputs: List[str] = []
        self.population: List[Seed] = []
        self.seed_index: int = 0
        self.max_trials: int = 1
        self.inp: str = ""
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


class GecGreyboxFuzzer(AdvancedMutationFuzzer):
    def __init__(self, seeds: List[str], mutator: Mutator, schedule: PowerSchedule):
        super().__init__(seeds, mutator, schedule)
        self.coverages_seen: set = set()

    def reset(self):
        super().reset()
        self.coverages_seen = set()

    def run(self, runner: FunctionCoverageRunner) -> Tuple[subprocess.CompletedProcess, Outcome]:
        result, outcome = super().run(runner)
        new_coverage = frozenset(runner.coverage())
        if new_coverage not in self.coverages_seen:
            seed = Seed(self.inp)
            seed.coverage = runner.coverage()
            self.coverages_seen.add(new_coverage)
            self.population.append(seed)
        return result, outcome
