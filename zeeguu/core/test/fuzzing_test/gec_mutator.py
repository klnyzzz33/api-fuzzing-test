from typing import List

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
            self.replace_word
        ]

    def insert_from_dictionary(self, s: str) -> str:
        """Returns s with a randomly chosen dictionary word inserted at a random position"""
        tokens = s.split()
        pos = random.randint(0, len(tokens))
        random_keyword = random.choice(self.insert_dictionary)
        tokens.insert(pos, random_keyword)
        return " ".join(tokens)

    def switch_words(self, s: str) -> str:
        """Returns s with two randomly chosen words swapped"""
        tokens = s.split()
        if len(tokens) < 2:
            return s
        pos1 = random.randint(0, len(tokens) - 1)
        pos2 = random.randint(0, len(tokens) - 1)
        while pos1 == pos2:
            pos2 = random.randint(0, len(tokens) - 1)
        tokens[pos1], tokens[pos2] = tokens[pos2], tokens[pos1]
        return " ".join(tokens)

    def replace_word(self, s: str) -> str:
        """Returns s with a randomly selected word replaced using a predefined replacement dictionary"""
        tokens = s.split()
        keys = list(self.replace_dictionary.keys())
        chosen_keys = [k for k in keys if k in tokens]
        if not chosen_keys:
            return s
        chosen_key = random.choice(chosen_keys)
        random_replace = random.choice(self.replace_dictionary[chosen_key])
        tokens[tokens.index(chosen_key)] = random_replace
        return " ".join(tokens)
