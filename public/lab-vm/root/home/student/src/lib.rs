// vm-rust-lifetime
//
// `longest` zwraca referencje do lokalnej zmiennej, wiec borrow checker
// to odrzuca. Popraw sygnature tak, aby program sie kompilowal i
// zwracal dluzszy z dwoch napisow.
//
//     rustc --crate-type lib --edition 2021 src/lib.rs
pub fn longest(word: &str) -> &str {
    let best = if word.len() > 3 { word } else { "..." };
    &best[1..]
}
