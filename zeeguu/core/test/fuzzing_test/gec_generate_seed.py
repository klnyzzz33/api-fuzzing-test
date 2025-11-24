from fuzzingbook.Grammars import Grammar, START_SYMBOL, nonterminals, random, ExpansionError


def gec_generate_seed(grammar: Grammar,
                      start_symbol: str = START_SYMBOL,
                      max_nonterminals: int = 10,
                      max_expansion_trials: int = 100,
                      log: bool = False) -> str:
    term = start_symbol
    expansion_trials = 0
    while len(nonterminals(term)) > 0:
        symbol_to_expand = random.choice(nonterminals(term))
        expansions = grammar[symbol_to_expand]
        expansion = random.choice(expansions)
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
