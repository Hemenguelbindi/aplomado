/// Russische Pluralisierung: "1 хост", "2 хоста", "5 хостов"
pub fn pluralize(
    count: usize,
    singular: &str,
    genitive_singular: &str,
    genitive_plural: &str,
) -> String {
    let last_two = count % 100;
    let last_one = count % 10;
    let word = if last_two >= 11 && last_two <= 20 {
        genitive_plural
    } else if last_one == 1 {
        singular
    } else if last_one >= 2 && last_one <= 4 {
        genitive_singular
    } else {
        genitive_plural
    };
    format!("{count} {word}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pluralize_singular() {
        assert_eq!(pluralize(1, "хост", "хоста", "хостов"), "1 хост");
    }

    #[test]
    fn test_pluralize_genitive_singular() {
        assert_eq!(pluralize(2, "хост", "хоста", "хостов"), "2 хоста");
        assert_eq!(pluralize(4, "хост", "хоста", "хостов"), "4 хоста");
    }

    #[test]
    fn test_pluralize_genitive_plural() {
        assert_eq!(pluralize(5, "хост", "хоста", "хостов"), "5 хостов");
        assert_eq!(pluralize(10, "хост", "хоста", "хостов"), "10 хостов");
    }

    #[test]
    fn test_pluralize_teens() {
        assert_eq!(pluralize(11, "хост", "хоста", "хостов"), "11 хостов");
        assert_eq!(pluralize(20, "хост", "хоста", "хостов"), "20 хостов");
    }

    #[test]
    fn test_pluralize_zero() {
        assert_eq!(pluralize(0, "хост", "хоста", "хостов"), "0 хостов");
    }
}
