from fuzzingbook.Grammars import Grammar, START_SYMBOL, nonterminals, random, ExpansionError

from zeeguu.core.nlp_pipeline import SPACY_EN_MODEL
from zeeguu.core.nlp_pipeline.automatic_gec_tagging import AutoGECTagging
from zeeguu.core.test.fuzzing_test.setup import test_env

GEC_INPUT_GRAMMAR: Grammar = {
    "<start>":
        ["<word_dict_list>###<sentence>"],

    # ------------------------------
    # WORD DICTIONARY LIST
    # ------------------------------
    "<word_dict_list>":
        ["[<word_entry_list>]"],

    "<word_entry_list>":
        ["<word_entry>",
         "<word_entry>,<word_entry_list>"],

    "<word_entry>":
        ['{"word":"<token>","isInSentence":<bool>}'],

    "<bool>":
        ["true"],

    # ------------------------------
    # TOKENS
    # ------------------------------
    "<token>":
        ["<noun>", "<verb>", "<prep>", "<adj>",
         "<adv>", "<pron>", "<punct>", "<weird>"],

    "<noun>":
        ["cat", "cats", "book", "books", "airplane", "plane"],

    "<verb>":
        ["go", "goes", "went", "run", "runs", "running",
         "eat", "eats", "eating"],

    "<prep>":
        ["in", "on", "at", "with", "without", "before", "after"],

    "<adj>":
        ["big", "small", "tiny", "large", "larger"],

    "<adv>":
        ["quickly", "slowly", "silently"],

    "<pron>":
        ["he", "she", "they", "them", "me", "I"],

    "<punct>":
        [".", ",", ";", ":", "!"],

    "<weird>":
        ["wher", "wheere", "evrywhere", "air-plane", "runnning", "123abc"],

    # ------------------------------
    # SENTENCE GENERATOR
    # ------------------------------
    "<sentence>":
        ["<sent_parts>", "<sent_parts> <sentence>"],

    "<sent_parts>":
        ["<token>", "<token> <token>"],

}


def gec_grammar_fuzzer(grammar: Grammar,
                       start_symbol: str = START_SYMBOL,
                       max_nonterminals: int = 10,
                       max_expansion_trials: int = 100,
                       log: bool = False) -> str:
    """Produce a string from `grammar`.
       `start_symbol`: use a start symbol other than `<start>` (default).
       `max_nonterminals`: the maximum number of nonterminals
         still left for expansion
       `max_expansion_trials`: maximum # of attempts to produce a string
       `log`: print expansion progress if True"""

    term = start_symbol
    expansion_trials = 0

    while len(nonterminals(term)) > 0:
        symbol_to_expand = random.choice(nonterminals(term))
        expansions = grammar[symbol_to_expand]
        expansion = random.choice(expansions)
        # In later chapters, we allow expansions to be tuples,
        # with the expansion being the first element
        if isinstance(expansion, tuple):
            expansion = expansion[0]

        new_term = term.replace(symbol_to_expand, expansion, 1)

        if len(nonterminals(new_term)) < max_nonterminals:
            term = new_term
            if log:
                print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
            expansion_trials = 0
        else:
            expansion_trials += 1
            if expansion_trials >= max_expansion_trials:
                raise ExpansionError("Cannot expand " + repr(term))

    return term


def test_gec_tagging_labels(test_env):
    for i in range(10):
        str = gec_grammar_fuzzer(grammar=GEC_INPUT_GRAMMAR)
        print(str)

    agt = AutoGECTagging(SPACY_EN_MODEL, 'en')
    d = [{"word": "Cats", "isInSentence": True},
         {"word": "are", "isInSentence": True},
         {"word": "amzaing", "isInSentence": True}]
    print(agt.anottate_clues(d, original_sentence="Cats are amazing."))
