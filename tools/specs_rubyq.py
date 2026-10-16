#!/usr/bin/env python3
"""specs_rubyq.py — quizy Ruby: Enumerable, mutability, blocks, watki."""
from gen_tasks import quiz

def q(tid, title, brief, choices, answer, explain, *, area="Enumerable", difficulty=2, points=110):
    return quiz("quiz-rb-" + tid, "ruby", title, brief, choices, answer, explain,
                difficulty=difficulty, points=points, area=area,
                vm_check="ruby -e \"puts 'ok'\"")

QUIZZES = [
    q("map-vs-each", "map or each?",
      "```ruby\n[1, 2, 3].map { |x| x * 2 }\n[1, 2, 3].each { |x| x * 2 }\n```\nWhat is the difference?",
      ["`map` returns a new array, `each` returns the original one and only runs the block",
       "They are the same, `each` just reads better",
       "`each` is faster and returns an array",
       "`map` mutates the original array"],
      [0],
      "`map` builds a new collection from the block's return values. `each` is for side effects "
      "and gives the receiver back, which is why `arr.each { ... }.map { ... }` is a bug: the "
      "second block runs on the original array."),

    q("select-vs-reject", "select or reject?",
      "```ruby\nevents.select { |e| e[:severity] == 'high' }\nevents.reject { |e| e[:severity] == 'high' }\n```\nWhat does `reject` return?",
      ["Everything the block rejected — the complement of `select`",
       "The same as `select`",
       "The first matching element only",
       "`nil`, because `reject` needs a block"],
      [0],
      "`reject` is `select` with the sense flipped. Reading `if` and `unless` the same way makes "
      "this second nature — and it is what keeps a filter condition free of a `!`."),

    q("symbol-vs-string", "String or symbol?",
      "```ruby\nROLES = { 'admin' => 1, 'user' => 2 }\n```\nWhat is wrong with a hash key like this?",
      ["A string key is a fresh object every time, so a typo in a lookup silently misses",
       "Hashes cannot use strings as keys at all",
       "The keys are frozen automatically",
       "The syntax is invalid"],
      [0],
      "Ruby interns symbols, so `:admin` is one object for the whole program and a typo raises "
      "`NameError` instead of quietly returning `nil`. Symbols are the default for hash keys and "
      "for method names for exactly this reason."),

    q("frozen-string", "What does frozen_string_literal do?",
      "```ruby\n# frozen_string_literal: true\ns = \"lab\"\ns << \"-prod\"\n```\nWhat happens?",
      ["`FrozenError` — string literals are immutable, so nothing can mutate a literal by accident",
       "The string becomes `lab-prod`",
       "The string becomes a symbol",
       "Nothing, the comment is ignored"],
      [0],
      "Without the magic comment, `s << \"x\"` would modify a literal — and because two literals "
      "with the same content can be the same object, one method could change another's string. "
      "Ruby 3.4 freezes them by default."),

    q("block-vs-proc", "Block or proc?",
      "```ruby\ndef run(&blk); blk.call; end\nrun { puts 1 }\n```\nWhat does `&blk` capture?",
      ["The block as a `Proc` object, so it can be stored and called later",
       "The return value of the block",
       "A lambda with keyword-argument checking",
       "Nothing — `&` is only for arrays"],
      [0],
      "`&` converts the block into a `Proc`; the reverse is `&proc` or `.to_proc`. A `Proc` is "
      "lenient about arity and `return` semantics — a `lambda` is strict about both, which is why "
      "callbacks that must not underflow usually want a lambda."),

    q("start-end-range", "Endless range?",
      "```ruby\n(1..).first(3)\n```\nWhat does `(1..)` mean?",
      ["An endless range — 1, 2, 3, and on; lazy enumeration keeps it finite in practice",
       "A syntax error in Ruby 2.x",
       "A range from 1 to the current line number",
       "An infinite loop, and `first` will hang"],
      [0],
      "Endless ranges arrived in 2.6 and are genuinely lazy for `Enumerator` methods like `first` "
      "and `lazy`. An endless *array* would hang, but a range is defined by its start."),

    q("string-mutation", "What does << do to a string?",
      "```ruby\ndef tag(name)\n  name << \"-prod\"\nend\na = \"lab\"\ntag(a)\nputs a\n```\nWhat is printed?",
      ["`lab-prod` — `<<` mutates the caller's string in place",
       "`lab` — the argument is copied",
       "`-prod` — only the argument is printed",
       "It raises because the parameter should be frozen"],
      [0],
      "Strings are mutable objects and `<<` is `concat`. This aliasing bug is why a method that "
      "means \"read this\" should take a frozen string, use `name.dup`, or just not mutate at all."),

    q("nil-vs-false", "Falsy values in Ruby",
      "```ruby\ndef value; nil; end\nputs value || 'default'\n```\nWhat is printed?",
      ["`default` — only `nil` and `false` are falsy, and `0` and `\"\"` are truthy",
       "`nil` — an absent value wins",
       "`0` — zero is falsy in Ruby",
       "`false` — every empty value is falsy"],
      [0],
      "Ruby has two falsy values. An empty string, `0` and an empty array are all **true**, so "
      "`if list.empty?` is right and `if list` is wrong. That is the opposite of JavaScript."),

    q("gsub-block", "What does gsub return?",
      "```ruby\nline.gsub(/\\d{4}/) { |m| '*' * m.size }\n```\nWhat is the result?",
      ["A new string with every match replaced by the block's value",
       "`nil`",
       "The original string, mutated in place",
       "An array of the matches"],
      [0],
      "`gsub` (and `sub`, `gsub!`, `sub!`) come in two forms: a replacement string where `\\1` is a "
      "capture, and a block where the match is an argument. The bang versions mutate and return "
      "`nil` when nothing changed — the classic `if s.gsub!(...)` trap."),

    q("sort-by", "How do you sort by a key?",
      "```ruby\n[events].sort_by { |e| e[:time] }\n```\nWhy not `sort`?",
      ["`sort` compares the elements themselves, which fails for hashes; `sort_by` compares keys",
       "`sort` is deprecated in Ruby 3",
       "`sort` sorts by insertion order",
       "`sort_by` is faster but gives the same order"],
      [0],
      "`sort` needs `elements <=> elements`, and `Hash` does not define it. `sort_by` computes the "
      "key once per element and sorts by that — so `sort_by { |h| h.size }` is cheap, while "
      "`sort { |a, b| a.size <=> b.size }` calls `size` repeatedly."),

    q("freeze-deep", "Does freeze go deep?",
      "```ruby\nh = { a: [1, 2] }.freeze\nh[:a] << 3\n```\nWhat happens?",
      ["It works — `freeze` is shallow, so the inner array is still mutable",
       "`FrozenError` on the hash",
       "The whole structure becomes immutable",
       "The hash is deep-copied on `freeze`"],
      [0],
      "`freeze` locks the object itself, not what it points at. Deep immutability needs "
      "`h.transform_values(&:freeze).freeze` or a library, and a frozen hash whose values are not "
      "frozen is a half-guarantee that reads as a full one."),

    q("unless-else", "unless with else?",
      "```ruby\nunless ok\n  retry\nelse\n  finish\nend\n```\nWhat runs when `ok` is true?",
      ["`finish` — `unless` takes an `else` branch too",
       "Nothing; `else` is not allowed",
       "`retry`, because `else` is inverted",
       "A syntax error"],
      [0],
      "`unless` is `if not`, including the `else`. Ruby's own style guide suggests `until` for "
      "loops but leaves `unless` alone — and `else` inside it can genuinely surprise a reader."),

    q("array-uniq", "How does uniq decide?",
      "```ruby\n[1, '1', 1.0].uniq\n```\nHow many elements?",
      ["Three — `1` (Integer) and `1.0` (Float) are different keys",
       "Two — they compare equal",
       "One — they are numerically equal",
       "It raises on mixed types"],
      [0],
      "`uniq` uses `eql?` plus `hash`, and `1.eql?(1.0)` is false while `1 == 1.0` is true. That "
      "is exactly why `1 == 1.0` is true but `{1 => :a}[1.0]` is `nil`."),

    q("prepend-vs-include", "prepend or include?",
      "```ruby\nmodule Logged\n  def call(*a); log; super; end\nend\n```\nYou `prepend` it to a class. Why?",
      ["`prepend` puts your method **before** the class's, so `super` reaches the original",
       "`prepend` is an alias for `include`",
       "`include` would not find the method at all",
       "`prepend` only works on modules used at the top level"],
      [0],
      "`include` puts the module **below** the class in the lookup chain, so the class's own method "
      "wins. `prepend` puts it above, which is what you want for cross-cutting concerns like "
      "logging or authorisation."),

    q("rescue-narrow", "What does a bare rescue catch?",
      "```ruby\nbegin\n  risky\nrescue\n  log\nend\n```\nWhich exceptions?",
      ["Only `StandardError` and its descendants — not `NoMemoryError` or `SystemExit`",
       "Everything, including signals",
       "Only the ones listed in the `rescue` clause",
       "Nothing without an explicit class name"],
      [0],
      "A bare `rescue` is `rescue => e` is `rescue StandardError => e`. `Exception` and "
      "`Interrupt` sit outside it on purpose — swallowing those makes a program unstoppable."),

    q("string-interp-security", "Interpolation and code",
      "```ruby\nUser.where(\"name = '#{params[:name]}'\")\n```\nWhat is the risk?",
      ["A quote in the input closes the literal and injects SQL",
       "Interpolation always escapes quotes",
       "Nothing — Ruby escapes `#{` automatically",
       "It is a performance problem only"],
      [0],
      "Ruby does not escape inside interpolation, and the quote above is even worse: a `'` in the "
      "input ends the SQL string literal. Parameterised queries — `where(name: params[:name])` — "
      "are the fix."),

    q("each-with-index", "Index without each_with_index?",
      "```ruby\n[10, 20].each_with_index.select { |_, i| i.even? }.map(&:first)\n```\nWhat is the result?",
      ["`[10]` — the element at index 0",
       "`[10, 20]` — both have even indices counted per element",
       "`[20]`",
       "An `Enumerator::Lazy` that has to be forced"],
      [0],
      "`select` and `map` return arrays here, so the result is a real array. `each_with_index` "
      "yields `[[value, index]]`, which is why `&:first` is the first step of the idiom."),

    q("exception-cause", "What is `cause`?",
      "```ruby\nbegin\n  raise 'outer'\nrescue => e\n  puts e.cause.inspect\nend\n```\nWhat is printed?",
      ["`nil` — nothing was being handled when the error was raised, so there is no cause",
       "`RuntimeError`",
       "`NameError`",
       "It raises a second error"],
      [0],
      "`Exception#cause` is the exception that was being handled when this one was raised — that is "
      "how a library error keeps a link to the `Timeout::Error` underneath it. A `raise` at the top "
      "level has nothing to link back to, so `cause` is `nil`."),

    q("thread-vs-fork", "Thread or fork?",
      "```ruby\nThread.new { heavy }\nProcess.fork { heavy }\n```\nWhich one gets its own memory?",
      ["`fork` — a separate address space; a thread shares the heap",
       "Both, threads get a copy-on-write heap",
       "`Thread.new` — each thread is a process",
       "Neither; Ruby runs both in the same OS process"],
      [0],
      "A thread is a different stack in the same heap, which is why a data race in Ruby shows up "
      "as a corrupted hash rather than a segfault. `fork` copies the address space (copy-on-write), "
      "at the cost of memory."),

    q("string-split-limit", "Split limit?",
      "```ruby\n'a b c'.split(' ', 2)\n```\nWhat is the result?",
      ["`['a', 'b c']` — the second field keeps the rest of the string",
       "`['a', 'b', 'c']`",
       "`['a', 'b', 'c', '']`",
       "`['a']`"],
      [0],
      "A positive limit caps the number of fields and leaves the tail intact in the last one. A "
      "limit of `0` means no limit at all, which is the asymmetry that surprises people."),

    q("symbol-intern", "Why are symbols faster?",
      "```ruby\n:name.to_s\n```\nWhy is a symbol lookup cheaper than a string one?",
      ["A symbol is one interned object for the whole program, so equality is an identity check",
       "Symbols are stored in binary search of the binary",
       "Symbols skip the GC",
       "Strings are always interned in Ruby"],
      [0],
      "Interning means one object per name, so `==` is a pointer comparison. A string literal may "
      "be a distinct object each time, and comparing them costs a memcmp. The cost moves to "
      "dynamic symbols, which are garbage-collected and no longer interned forever."),

    q("hash-key-mutation", "Why is this a bug?",
      "```ruby\nh = {}.compare_by_identity\nk = 'a'.dup\nh[k] = 1\nh[k] = 2\nputs h.size\n```\nWhat is printed?",
      ["`1` — identity keys compare object identity, and `k` is the same object both times",
       "`2` — strings are hashed by content",
       "`1` — the second write overwrites the first",
       "It raises"],
      [0],
      "With a normal hash, `h.size` is 1 too, because the content is equal. The difference shows "
      "with two equal-but-distinct string objects: a normal hash collapses them, `compare_by_identity` "
      "keeps them apart. Mutable string keys are the classic trap either way."),

    q("ensure-return", "What does ensure return?",
      "```ruby\ndef f\n  1\nensure\n  2\nend\nputs f\n```\nWhat is printed?",
      ["`1` — `ensure` runs, but its value is discarded",
       "`2`",
       "`nil`",
       "It raises a warning and prints nothing"],
      [0],
      "`ensure` runs on every path, including the exception path, but its value is never the "
      "return value. A `return` inside `ensure` *does* win, which is how a method accidentally "
      "swallows an exception."),

    q("module-function", "module_function?",
      "```ruby\nmodule Util\n  def self.helper; 1; end\nend\n```\nWhat is `module_function` for?",
      ["It makes the methods available both as `Util.helper` and as private instance methods when included",
       "It makes the module a singleton",
       "It marks the methods as private constants",
       "It makes the module require-able"],
      [0],
      "`module_function` is the module-level equivalent of `def self.x` plus `private` on the "
      "instance copy. It is how a module offers a helper to a class and the same helper to callers "
      "without duplicating the definition."),
]
