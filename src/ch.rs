pub trait Challenge {
    fn name(&self) -> &'static str;
    fn run(&mut self);
    fn report(&self) {
        println!(" => {: >030} [ {: >013} ]", self.name(), match self.success() {
            Some(true) => concat!("\u{001b}[32m", "OK", "\u{001b}[0m"),
            Some(false) => concat!("\u{001b}[31m", "FAIL", "\u{001b}[0m"),
            None => concat!("\u{001b}[33m", "?", "\u{001b}[0m"),
        });
        match self.success() {
            Some(true) => if let Some(message) = self.success_message() {
                println!("    {}", message);
            },
            Some(false) => if let Some(message) = self.fail_message() {
                println!("    {}", message);
            },
            None => if let Some(message) = self.skip_message() {
                println!("    {}", message);
            },
        }

        if let Some(message) = self.finish_message() {
            println!("    {}", message);
        }
    }
    fn success_message(&self) -> Option<String> { None }
    fn fail_message(&self) -> Option<String> { None }
    fn skip_message(&self) -> Option<String> { None }
    fn finish_message(&self) -> Option<String> { None }
    fn success(&self) -> Option<bool> { None }
}
