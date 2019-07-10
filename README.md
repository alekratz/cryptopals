# Cryptopals

This is my shot at the Cryptopals challenge. (https://cryptopals.com)

Everything is written in stable Rust, and it requires version 1.36.

# Spoiler alert!

Not all of the Cryptopals problems have solutions alongside them, so it's usually up to you, the
participant, to determine what the answer is. This program verifies that the method to solve the
problem is correct, and involves checking against the known answer.

Be warned that if you run and/or read this program, you'll have some of the "figure it out yourself"
messages revealed to you.

# Usage

If you want to run all of the tests, you can simply use

`cargo run`

in the root directory. It will run all challenges by default.

You can specify specific challenges to run on the command line, e.g.

`cargo run c1 c3 c5     # run challenges 1, 3, and 5`

There are also a few options for input files. Use `cargo run -- --help` for more information.
