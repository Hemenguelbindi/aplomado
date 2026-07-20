use super::{BorderRadius, Spacing, Typography};

/// Общая типографика для обеих тем
pub fn default_typography() -> Typography {
    Typography {
        font_family: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif".to_string(),
        font_family_mono: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace"
            .to_string(),
        text_xs: "0.75rem".to_string(),
        text_sm: "0.875rem".to_string(),
        text_base: "1rem".to_string(),
        text_lg: "1.125rem".to_string(),
        text_xl: "1.25rem".to_string(),
        text_2xl: "1.5rem".to_string(),
        text_4xl: "2.25rem".to_string(),
        font_normal: "400".to_string(),
        font_semibold: "600".to_string(),
        font_bold: "700".to_string(),
    }
}

/// Общие отступы для обеих тем
pub fn default_spacing() -> Spacing {
    Spacing {
        unit: "0.25rem".to_string(),
        xs: "0.125rem".to_string(),
        sm: "0.25rem".to_string(),
        md: "0.5rem".to_string(),
        lg: "1rem".to_string(),
        xl: "1.5rem".to_string(),
        xxl: "2rem".to_string(),
    }
}

/// Общие скругления для обеих тем
pub fn default_border_radius() -> BorderRadius {
    BorderRadius {
        none: "0".to_string(),
        sm: "0.125rem".to_string(),
        md: "0.25rem".to_string(),
        lg: "0.5rem".to_string(),
        xl: "0.75rem".to_string(),
        full: "9999px".to_string(),
    }
}
