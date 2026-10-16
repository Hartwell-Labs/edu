// vm-rust-borrow
//
// Ten program NIE KOMPILUJE SIE. Skompiluj go, przeczytaj blad
// kompilatora i popraw go. Nie chodzi o obejscie problemu, tylko
// o to, zeby po naprawie dlugosc zycia wskazania byla poprawna.
//
//     rustc main.rs && ./main
fn main() {
    let v = vec![1, 2, 3];
    let first = &v[0];
    println!("{}", first);
    v.push(4);
    println!("{:?} {}", v, first);
}
