use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub struct FilterValue(pub f64, pub usize);

impl std::fmt::Display for FilterValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{}", self.0, self.1)
    }
}

impl FromStr for FilterValue {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() != 2 {
            return Err("Expected two parts separated by a comma".to_string());
        }
        let part1 = parts[0].parse::<f64>().map_err(|_| "Invalid float value".to_string())?;
        if part1 < 0.0 || part1 > 1.0 {
            return Err("Float value must be between 0 and 1".to_string());
        }
        let part2 = parts[1].parse::<usize>().map_err(|_| "Invalid usize value".to_string())?;
        Ok(FilterValue(part1, part2))
    }
}
