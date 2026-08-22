mod a {
    pub struct Foo;
}
mod b {
    use super::a::Foo;
    impl Foo {
        pub fn bar(&self) {}
    }
}
fn main() {
    let f = a::Foo;
    f.bar();
}
