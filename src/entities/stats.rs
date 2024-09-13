#[derive(Default)]
pub struct Stats {
    pub n: usize,
    pub sum: usize,
    pub sum_of_squares: f64,
}

impl Stats {
    pub fn new() -> Self {
        Self{
            n: 0,
            sum: 0,
            sum_of_squares: 0.0,
        }
    }
    pub fn add_value(&mut self, value: usize) {
        self.n += 1;
        self.sum += value;
        let avg = self.sum as f64 / self.n as f64;
        let dif = value as f64 - avg;
        self.sum_of_squares += dif.powf(2.0);
    }
}