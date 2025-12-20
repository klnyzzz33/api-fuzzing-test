from typing import List, Any

from fuzzingbook.Grammars import random
from fuzzingbook.GreyboxFuzzer import Mutator


class GecMutator(Mutator):
    def __init__(self, insert_dictionary: List[str], replace_dictionary: dict[str, List[str]]) -> None:
        super().__init__()
        self.insert_dictionary = insert_dictionary
        self.replace_dictionary = replace_dictionary

        self.mutators = [
            self.delete_random_character,
            self.insert_random_character,
            self.insert_from_dictionary,
            self.switch_words,
            self.replace_word,
            self.remove_word,
        ]

        self.mutator_weights = [
            0.75,
            0.75,
            1.0,
            1.0,
            1.0,
            0.25,
        ]

    def mutate(self, inp: Any) -> Any:
        """Return s with a random mutation applied."""
        weights = self.mutator_weights.copy()

        if len(inp.split()) <= 2:
            weights[-1] = 0

        mutator = random.choices(self.mutators, weights=weights, k=1)[0]
        return mutator(inp)

    def insert_from_dictionary(self, s: str) -> str:
        """Returns s with a randomly chosen dictionary word inserted at a random position"""
        words = s.split()
        pos = random.randint(0, len(words))
        random_keyword = random.choice(self.insert_dictionary)
        words.insert(pos, random_keyword)
        return " ".join(words)

    def switch_words(self, s: str) -> str:
        """Returns s with two randomly chosen words swapped"""
        words = s.split()
        if len(words) < 2:
            return s
        pos1 = random.randint(0, len(words) - 1)
        pos2 = random.randint(0, len(words) - 1)
        while pos1 == pos2:
            pos2 = random.randint(0, len(words) - 1)
        words[pos1], words[pos2] = words[pos2], words[pos1]
        return " ".join(words)

    def replace_word(self, s: str) -> str:
        """Returns s with a randomly selected word replaced using a predefined replacement dictionary"""
        words = s.split()
        keys = list(self.replace_dictionary.keys())
        chosen_keys = [k for k in keys if k in words]
        if not chosen_keys:
            return s
        chosen_key = random.choice(chosen_keys)
        random_replace = random.choice(self.replace_dictionary[chosen_key])
        words[words.index(chosen_key)] = random_replace
        return " ".join(words)

    def remove_word(self, s: str) -> str:
        """Returns s with a randomly removed word"""
        words = s.split()
        chosen_word = random.choice(words)
        words.remove(chosen_word)
        return " ".join(words)
