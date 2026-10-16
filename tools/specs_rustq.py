#!/usr/bin/env python3
"""specs_rustq.py — quizy Rust: ownership, borrowing, lifetimes, unsafe."""
from gen_tasks import quiz

def q(tid, title, brief, choices, answer, explain, *, area="Ownership", difficulty=3, points=120):
    return quiz("quiz-rs-" + tid, "rust", title, brief, choices, answer, explain,
                difficulty=difficulty, points=points, area=area)

QUIZZES = [
    q("move-vs-copy", "Copy or move?",
      "```rust\nlet s = String::from(\"lab\");\nlet t = s;\nprintln!(\"{}\", s);\n```\nWhat does the compiler say?",
      ["Moved value: `s` was moved into `t`, so using it again is an error",
       "It compiles — `String` is `Copy`",
       "It compiles and prints `lab` twice",
       "It panics at runtime"],
      [0],
      "`String` owns a heap buffer, so it is not `Copy`. After the move `s` is no longer valid and "
      "the compiler refuses to read it. `i32` would have been copied instead — that is the whole "
      "difference between a value type and a handle to memory you do not own."),

    q("borrow-rules", "How many mutable borrows at once?",
      "```rust\nlet mut v = vec![1, 2, 3];\nlet a = &mut v;\nlet b = &mut v;\nprintln!(\"{:?} {:?}\", a, b);\n```\nWhy is this rejected?",
      ["Two mutable borrows of the same value are not allowed at the same time",
       "You cannot borrow a `Vec` at all",
       "The borrow checker cannot see inside a `Vec`",
       "It is allowed; the second borrow shadows the first"],
      [0],
      "Aliasing mutable references would let two holders write through the same memory with no "
      "way to coordinate. NLL lets the second borrow wait until `a` is last used, but here both are "
      "live at the `println!`."),

    q("slice-vs-ref", "What is the type of this?",
      "```rust\nfn f(s: &str) -> usize { s.len() }\nlet x = f(\"anvil\");\n```\nWhat is `x`?",
      ["`5` — the length of the string literal",
       "`&str` — a reference to a compile-time constant",
       "`usize` — a reference, not a length",
       "It does not compile: `&str` has no `len`"],
      [0],
      "`&str` is a fat pointer: a pointer plus a length, so `.len()` is free. That is why a slice "
      "of a string literal is `&'static str` — the bytes live in the binary."),

    q("drop-order", "When does the value drop?",
      "```rust\nlet a = String::from(\"a\");\n{\n    let b = String::from(\"b\");\n    println!(\"{}{}\", a, b);\n}\n```\nIn what order are the two strings freed?",
      ["`b` first, then `a`",
       "`a` first, then `b`",
       "Both at the end of the program",
       "In an unspecified order"],
      [0],
      "Rust drops a value at the end of its scope, so the inner `b` goes first. `b` outlives `a` "
      "only inside the block; nothing here borrows anything, so the compiler has no reason to "
      "extend a lifetime."),

    q("result-question", "Result or Option?",
      "```rust\nfn first_char(s: &str) -> Option<char> {\n    s.chars().next()\n}\n```\nWhy is this `Option` and not `Result`?",
      ["A missing first character is a normal outcome, not an error condition",
       "`Option` is the new name for `Result` in edition 2024",
       "`Result` cannot hold characters",
       "It could be either; the choice is arbitrary"],
      [0],
      "`Option` is for \"maybe there is a value\", `Result` is for \"the operation can fail with a "
      "reason\". An empty string is not an error — it is a valid string that happens to have no "
      "characters."),

    q("unwrap-panic", "What does unwrap do on None?",
      "```rust\nlet x: Option<i32> = None;\nlet y = x.unwrap();\n```\nWhat happens?",
      ["The program panics with a message mentioning `None`",
       "`y` becomes 0",
       "`y` becomes `None`",
       "The compiler rejects the code"],
      [0],
      "`unwrap` is `expect(\"called unwrap on a None value\")`. It is fine in tests and in code "
      "where the invariant is already proven, and a bug everywhere else — `?` propagates the "
      "problem to the caller instead."),

    q("string-cmp", "String comparison in Rust",
      "```rust\nprintln!(\"{}\", \"10\" < \"9\");\n```\nWhat is printed?",
      ["`true` — `&str` compares lexicographically, so `1` beats `9`",
       "`false` — numbers compare numerically",
       "`false` — comparing strings is a compile error",
       "`true` — both are converted to numbers first"],
      [0],
      "`&str` compares by bytes, and `b'1'` is less than `b'9'`. Numeric comparison needs parsing: "
      "`\"10\".parse::<i32>()? < 9`."),

    q("vec-into-iter", "What does into_iter move?",
      "```rust\nlet v = vec![1, 2, 3];\nlet mut it = v.into_iter();\nprintln!(\"{:?}\", v);\n```\nWhat happens?",
      ["The borrow checker rejects it: `into_iter` consumes the `Vec`",
       "It prints `[1, 2, 3]` — `into_iter` only borrows",
       "It prints `[]`",
       "It compiles and prints `[1, 2, 3]`"],
      [0],
      "`into_iter` takes ownership. The `Vec` is gone afterwards, and the compiler will not let "
      "you print it. `iter()` borrows and leaves the `Vec` usable."),

    q("closure-move", "What does `move` do in a closure?",
      "```rust\nlet name = String::from(\"kija\");\nlet f = move || println!(\"{}\", name);\nf();\n```\nWhy is `move` needed?",
      ["Without it the closure would borrow `name`, and a closure outliving the borrow fails",
       "`move` makes the closure run in a new thread",
       "`move` makes the closure take ownership of nothing",
       "It is only needed for `Fn`, not `FnMut`"],
      [0],
      "A closure that outlives the scope capturing a borrowed value cannot compile. `move` makes "
      "the closure own the capture instead, so its lifetime is independent."),

    q("trait-object", "Static or dynamic dispatch?",
      "```rust\nfn call(x: &dyn Shape) -> f64 { x.area() }\n```\nWhat kind of dispatch is this?",
      ["Dynamic — the vtable pointer is in the fat pointer, resolved at call time",
       "Static — the type is known at compile time",
       "Both; the compiler picks the faster one",
       "None: `dyn` cannot be used in an argument position"],
      [0],
      "`&dyn Shape` is a fat pointer: data plus vtable, so the call is resolved at runtime and the "
      "code needs linking. `fn call<T: Shape>(x: &T)` monomorphises and the call is inlined."),

    q("index-out-of-bounds", "Panic or return an error?",
      "```rust\nlet v = vec![1, 2];\nprintln!(\"{}\", v[5]);\n```\nWhat happens?",
      ["A panic: `Index` on a `Vec` is a debug-asserted bounds check",
       "It prints `0`",
       "It returns `Err`",
       "It prints nothing and continues"],
      [0],
      "Indexing panics. `v.get(5)` is the fallible version and returns `Option`. Which one you "
      "want depends on whether the index came from a source you control."),

    q("shadowing", "What is shadowing?",
      "```rust\nlet x = 5;\nlet x = x + 1;\n```\nWhat is `x` now, and what is its type?",
      ["`6`, and the second `let` created a **new** binding with an inferred type",
       "`6`, and the original binding was changed in place",
       "`5` — the second `let` is ignored",
       "It does not compile: `x` is already defined"],
      [0],
      "Shadowing introduces a new variable that lives until the end of the block, and it can have "
      "a different type. `let x: &str = x;` is a common way to reinterpret a value."),

    q("mut-reference-scope", "How long does the borrow last?",
      "```rust\nlet mut v = vec![1];\nlet first = &v[0];\nv.push(2);\nprintln!(\"{}\", first);\n```\nWhat happens?",
      ["It is rejected: `v` is borrowed while `first` is used",
       "It is accepted: `v` can grow while a slice points into it",
       "It panics at runtime",
       "It prints `1` and reallocates safely"],
      [0],
      "`push` may reallocate, which would invalidate `first`. The borrow checker cannot know that "
      "`first` is never read before the push, so it rejects the program."),

    q("rc-refcell", "What does RefCell add?",
      "```rust\nuse std::cell::RefCell;\nlet n = RefCell::new(1);\n*n.borrow_mut() += 1;\n```\nWhat does `RefCell` buy you?",
      ["Interior mutability — the compiler cannot check it, so it is checked at runtime",
       "Thread safety for free",
       "A cheaper `Mutex` with no locking",
       "Nothing; it is a convenience wrapper"],
      [0],
      "`RefCell` moves the check from compile time to runtime: a `borrow_mut` while a `borrow` is "
      "alive panics instead of failing to compile. That is what `Rc<RefCell<T>>` is built from, "
      "and it is why you see panics in single-threaded code."),

    q("unwrap-or-default", "unwrap_or vs unwrap_or_else",
      "```rust\nlet n: Option<u32> = None;\nlet a = n.unwrap_or(compute());\nlet b = n.unwrap_or_else(|| compute());\n```\nWhat is the difference?",
      ["`unwrap_or` always evaluates `compute()`; `unwrap_or_else` only calls it when needed",
       "They are exactly the same",
       "`unwrap_or_else` returns `None` when absent",
       "`unwrap_or` panics on `None`"],
      [0],
      "`unwrap_or` takes an already-computed value, so the argument is evaluated eagerly — a real "
      "cost when it is a database call. The closure form is lazy."),

    q("iter-vs-collect", "What is the type of collect()?",
      "```rust\nlet v: Vec<i32> = (1..=5).collect();\n```\nWhat makes this work?",
      ["The target type is annotated, and `FromIterator<i32>` is implemented for `Vec`",
       "`collect` always returns a `Vec`",
       "You must call `.to_vec()` instead",
       "It only works for ranges"],
      [0],
      "`collect` is generic over the target: `impl FromIterator<A> for Vec<A>`. The annotation on "
      "`v` is what picks the implementation — without it the compiler cannot infer the type."),

    q("lifetime-elision-output", "Longest of two strings",
      "```rust\nfn longest(a: &str, b: &str) -> &str {\n    if a.len() > b.len() { a } else { b }\n}\n```\nDoes this compile without a lifetime annotation?",
      ["Yes — one input lifetime is elided and applies to the output",
       "No — the output lifetime is ambiguous",
       "No — you need `'static`",
       "Yes, but only because the return type is `&str`"],
      [0],
      "With exactly one input lifetime, elision assigns it to every output lifetime. With two or "
      "more input lifetimes and a reference in the output, the compiler asks you to say which one."),

    q("error-conversion", "The ? operator",
      "```rust\nfn f() -> Result<i32, std::num::ParseIntError> {\n    let n = \"12\".parse::<i32>()?;\n    Ok(n + 1)\n}\n```\nWhat does `?` do on a parse failure?",
      ["Returns early with the error converted into the function's error type",
       "Panics, because `?` has no way to report the error",
       "Substitutes 0 and continues",
       "Wraps the error in a string"],
      [0],
      "`?` returns `Err` from the function, applying `From` to convert the error type. It is the "
      "one operator that makes early-return error handling read like the happy path."),

    q("unsafe-what", "What does unsafe allow?",
      "```rust\nlet p: *const i32;\nunsafe { std::ptr::read(p) }\n```\nWhat exactly is `unsafe` promising?",
      ["The author checked the five things the compiler cannot: valid pointers, no data races, no UB",
       "The compiler skips all checks for that block and its callers",
       "The block is excluded from the optimiser",
       "The code runs without stack checks"],
      [0],
      "`unsafe` is a promise, not a switch. The invariants the compiler cannot verify — valid and "
      "aligned pointers, initialised memory, no aliasing data race — become the author's "
      "responsibility, and breaking them is undefined behaviour."),

    q("mutability-of-bindings", "Where does mut live?",
      "```rust\nlet v = vec![1, 2];\nv.push(3);\n```\nWhat is the error?",
      ["`v` is not declared `mut`, so the binding itself cannot be reassigned or mutated",
       "`push` needs `&mut`, and a `Vec` never has one",
       "It compiles; `push` takes `&self`",
       "The error is about the missing type annotation"],
      [0],
      "`mut` lives on the binding, not on the type. Rust's default is immutability, and `let mut v` "
      "is the only place you opt in."),

    q("char-vs-byte", "Bytes or characters?",
      "```rust\nprintln!(\"{}\", \"ł\".len());\n```\nWhat is printed?",
      ["`2` — `len()` on a `str` counts UTF-8 bytes",
       "`1` — `len()` counts characters",
       "`1` — `len()` counts grapheme clusters",
       "`4` — UTF-16 code units"],
      [0],
      "`str::len` is bytes, because that is what indexing a `str` gives you. For characters use "
      "`.chars().count()`, and for what a human would call a letter use `graphemes`."),

    q("format-macro", "Which formatting is right?",
      "```rust\nprintln!(\"{}\", 255);\nprintln!(\"{:x}\", 255);\n```\nWhat do the two lines print?",
      ["`255` and `ff`",
       "`255` and `255`",
       "`{:x}` is a compile error on an integer",
       "`ff` and `255`"],
      [0],
      "`{}` is `Display`, `{:x}` is `LowerHex`. Format specs are a type-level choice, so "
      "`{:x}` on a `String` does not compile rather than printing nonsense."),

    q("ownership-of-return", "Who owns the return value?",
      "```rust\nfn first_word(s: String) -> String {\n    s.split(' ').next().unwrap().to_string()\n}\n```\nIs a clone happening here?",
      ["Yes — `split` borrows and `to_string` allocates a new `String`",
       "No — the buffer is moved out",
       "No — Rust returns memory without copying",
       "It depends on the length of the string"],
      [0],
      "`split` yields `&str` slices of the original, so the original is dropped at the end of the "
      "function and the caller needs its own copy. Returning `&str` tied to the input would "
      "require a lifetime instead."),

    q("clone-derive", "What is the cost of `clone()`?",
      "```rust\n#[derive(Clone)]\nstruct Session { data: Vec<u8> }\nlet b = a.clone();\n```\nWhat did that do?",
      ["A deep copy — a new `Vec`, a new heap buffer, all bytes copied",
       "A shallow copy — both point at the same buffer",
       "A move — `a` is no longer valid",
       "A reference-count bump"],
      [0],
      "`#[derive(Clone)]` calls `clone` on every field, and `Vec::clone` allocates. That is why "
      "borrowing is the default and `clone` shows up in profiles."),

    q("arc-vs-rc", "Rc or Arc?",
      "```rust\nlet a = std::rc::Rc::new(5);\n```\nWhen do you need `Arc` instead?",
      ["When the value is shared across threads — `Rc` is not `Send`",
       "When you want one more reference count",
       "`Rc` is deprecated in edition 2021",
       "`Arc` is faster for single-threaded code"],
      [0],
      "`Rc` uses a non-atomic count and is therefore neither `Send` nor `Sync`. `Arc` pays for "
      "atomicity; `Rc` is the correct choice until you actually cross a thread boundary."),

    q("iterator-laziness", "Nothing ran yet",
      "```rust\nlet v = vec![1, 2, 3];\nlet evens = v.iter().filter(|x| *x % 2 == 0);\nprintln!(\"{}\", evens.count());\nprintln!(\"{:?}\", v);\n```\nHow many times does the closure run?",
      ["Once per element, and only at `count()`",
       "Three times at `filter`, and again at `count`",
       "Never — `count` short-circuits",
       "Once, at the `let` binding"],
      [0],
      "Iterators are lazy: `filter` builds nothing until something consumes it. `count()` only "
      "needs the length, so most adapters are skipped entirely — the optimiser rewrites it into a "
      "count over the source."),

    q("generic-monomorphisation", "Zero-cost generics?",
      "```rust\nfn first<T: Copy>(v: &[T]) -> Option<T> { v.first().copied() }\n```\nWhat does the compiler do with the two uses `first::<u8>` and `first::<u32>`?",
      ["Generates two copies of the function, each specialised",
       "Keeps one copy and boxes the value at runtime",
       "Converts it to a trait object",
       "It rejects the function as too generic"],
      [0],
      "Monomorphisation: one machine-code copy per concrete type, with the generic code inlined "
      "and specialised. Generics are free at runtime and cost binary size."),

    q("default-vs-swap", "What is a default value?",
      "```rust\nstruct Config { retries: u32 }\nimpl Default for Config { fn default() -> Self { Config { retries: 3 } } }\n```\nWhat is `Default` for?",
      ["One canonical starting value, so `Config::default()` always means the same thing",
       "Zero values for every field",
       "Values loaded from a file",
       "Making every field `pub`"],
      [0],
      "`Default` is a policy: \"the sensible starting point\". A struct whose `Default` is all "
      "zeros and one whose default is a working configuration are both fine, as long as it is "
      "documented which one you get."),

    q("panic-abort", "What does panic do to the program?",
      "```rust\nfn f() { panic!(\"boom\"); }\n```\nWhat actually happens?",
      ["The current thread unwinds (or aborts, with `panic=abort`); nothing else is skipped",
       "The function returns `None` and the caller continues",
       "The compiler inserts a `Result` you must handle",
       "A warning is printed and execution continues"],
      [0],
      "A panic is not an exception you can catch in normal code. Unwinding runs the destructors "
      "on the way out, which is the guarantee that makes RAII leak-free."),

    q("newtype-privacy", "Why a newtype?",
      "```rust\nstruct Meters(f64);\nstruct Feet(f64);\n```\nWhat does this buy you?",
      ["The types cannot be mixed up: `Feet` never goes where `Meters` is expected",
       "It makes the struct smaller in memory",
       "It skips the bounds check on the float",
       "It lets the compiler inline the field"],
      [0],
      "A bare `f64` is accepted anywhere a `f64` is expected, so a metres/feet mix-up compiles and "
      "ships. A newtype with a private field makes the distinction unrepresentable — this is the "
      "type-driven-design version of the same idea as a branded `Id`."),

    q("slice-iter-cost", "What does `&v[1..3]` do?",
      "```rust\nlet v = vec![1, 2, 3, 4, 5];\nlet s = &v[1..3];\n```\nWhat is `s`?",
      ["A slice of two elements, borrowed — no copy, no allocation",
       "A new `Vec` with the two elements copied",
       "An owned `Vec` of length 2",
       "A reference to the whole `Vec` with an offset"],
      [0],
      "A slice is a fat pointer: a pointer plus a length. Slicing a `Vec` keeps a borrow of the "
      "buffer, so no allocation happens and the `Vec` cannot grow while the slice is alive."),

    q("display-vs-debug", "Display or Debug?",
      "```rust\nstruct Id(u32);\nprintln!(\"{}\", Id(7));\n```\nWhat is the error?",
      ["`Id` has no `Display`, and `{}` requires it",
       "It prints `7`",
       "It prints `Id(7)`",
       "You must use `{:?}` with a `String`"],
      [0],
      "`{}` needs `Display`, `{:?}` needs `Debug`. Deriving `Debug` gives you `Id(7)` in logs; "
      "`Display` is the deliberate human-facing formatting you write by hand."),

    q("associated-fn", "What is an associated function?",
      "```rust\nimpl Config {\n    fn new() -> Self { Config { retries: 3 } }\n}\nlet c = Config::new();\n```\nDoes `new` take `self`?",
      ["No — it is called on the type, not on a value",
       "Yes, `new` takes `self` by value",
       "Yes, but `self` is ignored",
       "It is a free function in disguise"],
      [0],
      "`fn new() -> Self` is called as `Config::new()`. A method with `self` is called on a value: "
      "`config.retries()`. `new` is a convention, not a keyword — you can name it anything."),

    q("overflow-debug", "What is checked by default?",
      "```rust\nlet x: u8 = 255;\nlet y = x + 1;\n```\nWhat happens in a normal build?",
      ["A panic: integer overflow is checked in debug and wraps in release",
       "It wraps silently in every build",
       "It always panics",
       "It is a compile error"],
      [0],
      "Arithmetic overflow panics in debug. In release it wraps, because the checks cost real time. "
      "`overflowing_add` tells you which mode you are in, and `checked_add` handles both."),
]
