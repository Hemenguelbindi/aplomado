use dioxus::prelude::*;

mod constants;

#[derive(Clone, Debug, PartialEq)]
pub struct ColorPalette {
    pub primary: String,
    pub primary_hover: String,
    pub secondary: String,
    pub success: String,
    pub warning: String,
    pub error: String,
    pub danger: String,
    pub background: String,
    pub surface: String,
    pub surface_hover: String,
    pub border: String,
    pub border_light: String,
    pub text_primary: String,
    pub text_secondary: String,
    pub text_muted: String,
    pub text_link: String,
    pub text_link_hover: String,
    pub input_bg: String,
    pub input_border: String,
    pub input_focus: String,
    pub placeholder: String,
    pub overlay: String,
    pub severity_critical: String,
    pub severity_high: String,
    pub severity_medium: String,
    pub severity_low: String,
    pub severity_unknown: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Typography {
    pub font_family: String,
    pub font_family_mono: String,
    pub text_xs: String,
    pub text_sm: String,
    pub text_base: String,
    pub text_lg: String,
    pub text_xl: String,
    pub text_2xl: String,
    pub text_4xl: String,
    pub font_normal: String,
    pub font_semibold: String,
    pub font_bold: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Spacing {
    pub unit: String,
    pub xs: String,
    pub sm: String,
    pub md: String,
    pub lg: String,
    pub xl: String,
    pub xxl: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BorderRadius {
    pub none: String,
    pub sm: String,
    pub md: String,
    pub lg: String,
    pub xl: String,
    pub full: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Shadows {
    pub none: String,
    pub sm: String,
    pub md: String,
    pub lg: String,
    pub xl: String,
    pub glow_primary: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Theme {
    pub name: String,
    pub colors: ColorPalette,
    pub typography: Typography,
    pub spacing: Spacing,
    pub border_radius: BorderRadius,
    pub shadows: Shadows,
}

impl Theme {
    pub fn to_css_variables(&self) -> String {
        format!(
            r#":root {{
  --color-primary: {primary};
  --color-primary-hover: {primary_hover};
  --color-secondary: {secondary};
  --color-success: {success};
  --color-warning: {warning};
  --color-error: {error};
  --color-danger: {danger};
  --color-background: {background};
  --color-surface: {surface};
  --color-surface-hover: {surface_hover};
  --color-border: {border};
  --color-border-light: {border_light};
  --color-text-primary: {text_primary};
  --color-text-secondary: {text_secondary};
  --color-text-muted: {text_muted};
  --color-text-link: {text_link};
  --color-text-link-hover: {text_link_hover};
  --color-input-bg: {input_bg};
  --color-input-border: {input_border};
  --color-input-focus: {input_focus};
  --color-placeholder: {placeholder};
  --color-overlay: {overlay};
  --color-severity-critical: {severity_critical};
  --color-severity-high: {severity_high};
  --color-severity-medium: {severity_medium};
  --color-severity-low: {severity_low};
  --color-severity-unknown: {severity_unknown};
  --color-foreground: {text_primary};
  --color-muted-foreground: {text_muted};
  --color-surface-muted: {surface};
  --font-family: {font_family};
  --font-family-mono: {font_family_mono};
  --text-xs: {text_xs};
  --text-sm: {text_sm};
  --text-base: {text_base};
  --text-lg: {text_lg};
  --text-xl: {text_xl};
  --text-2xl: {text_2xl};
  --text-4xl: {text_4xl};
  --font-normal: {font_normal};
  --font-semibold: {font_semibold};
  --font-bold: {font_bold};
  --spacing-unit: {spacing_unit};
  --spacing-xs: {spacing_xs};
  --spacing-sm: {spacing_sm};
  --spacing-md: {spacing_md};
  --spacing-lg: {spacing_lg};
  --spacing-xl: {spacing_xl};
  --spacing-xxl: {spacing_xxl};
  --radius-none: {radius_none};
  --radius-sm: {radius_sm};
  --radius-md: {radius_md};
  --radius-lg: {radius_lg};
  --radius-xl: {radius_xl};
  --radius-full: {radius_full};
  --shadow-none: {shadow_none};
  --shadow-sm: {shadow_sm};
  --shadow-md: {shadow_md};
  --shadow-lg: {shadow_lg};
  --shadow-xl: {shadow_xl};
  --shadow-glow-primary: {shadow_glow_primary};
}}"#,
            primary = self.colors.primary,
            primary_hover = self.colors.primary_hover,
            secondary = self.colors.secondary,
            success = self.colors.success,
            warning = self.colors.warning,
            error = self.colors.error,
            danger = self.colors.danger,
            background = self.colors.background,
            surface = self.colors.surface,
            surface_hover = self.colors.surface_hover,
            border = self.colors.border,
            border_light = self.colors.border_light,
            text_primary = self.colors.text_primary,
            text_secondary = self.colors.text_secondary,
            text_muted = self.colors.text_muted,
            text_link = self.colors.text_link,
            text_link_hover = self.colors.text_link_hover,
            input_bg = self.colors.input_bg,
            input_border = self.colors.input_border,
            input_focus = self.colors.input_focus,
            placeholder = self.colors.placeholder,
            overlay = self.colors.overlay,
            severity_critical = self.colors.severity_critical,
            severity_high = self.colors.severity_high,
            severity_medium = self.colors.severity_medium,
            severity_low = self.colors.severity_low,
            severity_unknown = self.colors.severity_unknown,
            font_family = self.typography.font_family,
            font_family_mono = self.typography.font_family_mono,
            text_xs = self.typography.text_xs,
            text_sm = self.typography.text_sm,
            text_base = self.typography.text_base,
            text_lg = self.typography.text_lg,
            text_xl = self.typography.text_xl,
            text_2xl = self.typography.text_2xl,
            text_4xl = self.typography.text_4xl,
            font_normal = self.typography.font_normal,
            font_semibold = self.typography.font_semibold,
            font_bold = self.typography.font_bold,
            spacing_unit = self.spacing.unit,
            spacing_xs = self.spacing.xs,
            spacing_sm = self.spacing.sm,
            spacing_md = self.spacing.md,
            spacing_lg = self.spacing.lg,
            spacing_xl = self.spacing.xl,
            spacing_xxl = self.spacing.xxl,
            radius_none = self.border_radius.none,
            radius_sm = self.border_radius.sm,
            radius_md = self.border_radius.md,
            radius_lg = self.border_radius.lg,
            radius_xl = self.border_radius.xl,
            radius_full = self.border_radius.full,
            shadow_none = self.shadows.none,
            shadow_sm = self.shadows.sm,
            shadow_md = self.shadows.md,
            shadow_lg = self.shadows.lg,
            shadow_xl = self.shadows.xl,
            shadow_glow_primary = self.shadows.glow_primary,
        )
    }
}

/// Конструктор темы: общие поля (typography, spacing, border_radius)
/// берутся из `constants`, различающиеся (colors, shadows) передаются явно.
fn make_theme(name: &str, colors: ColorPalette, shadows: Shadows) -> Theme {
    Theme {
        name: name.to_string(),
        colors,
        typography: constants::default_typography(),
        spacing: constants::default_spacing(),
        border_radius: constants::default_border_radius(),
        shadows,
    }
}

pub fn dark_theme() -> Theme {
    make_theme(
        "dark",
        ColorPalette {
            primary: "#58a6ff".to_string(),
            primary_hover: "#4a8fd4".to_string(),
            secondary: "#8b949e".to_string(),
            success: "#3fb950".to_string(),
            warning: "#d29922".to_string(),
            error: "#f85149".to_string(),
            danger: "#da3633".to_string(),
            background: "#0f1116".to_string(),
            surface: "#161b22".to_string(),
            surface_hover: "#1a2332".to_string(),
            border: "#21262d".to_string(),
            border_light: "#30363d".to_string(),
            text_primary: "#ffffff".to_string(),
            text_secondary: "#c9d1d9".to_string(),
            text_muted: "#8b949e".to_string(),
            text_link: "#58a6ff".to_string(),
            text_link_hover: "#91a4d2".to_string(),
            input_bg: "#0d1117".to_string(),
            input_border: "#21262d".to_string(),
            input_focus: "#58a6ff".to_string(),
            placeholder: "#484f58".to_string(),
            overlay: "rgba(13, 17, 23, 0.9)".to_string(),
            severity_critical: "#f85149".to_string(),
            severity_high: "#d29922".to_string(),
            severity_medium: "#58a6ff".to_string(),
            severity_low: "#3fb950".to_string(),
            severity_unknown: "#8b949e".to_string(),
        },
        Shadows {
            none: "none".to_string(),
            sm: "0 1px 2px rgba(0, 0, 0, 0.3)".to_string(),
            md: "0 4px 6px rgba(0, 0, 0, 0.4)".to_string(),
            lg: "0 10px 15px rgba(0, 0, 0, 0.5)".to_string(),
            xl: "0 20px 25px rgba(0, 0, 0, 0.6)".to_string(),
            glow_primary: "0 0 20px rgba(88, 166, 255, 0.3)".to_string(),
        },
    )
}

pub fn light_theme() -> Theme {
    make_theme(
        "light",
        ColorPalette {
            primary: "#0969da".to_string(),
            primary_hover: "#0550ae".to_string(),
            secondary: "#656d76".to_string(),
            success: "#1a7f37".to_string(),
            warning: "#9a6700".to_string(),
            error: "#cf222e".to_string(),
            danger: "#a40e26".to_string(),
            background: "#ffffff".to_string(),
            surface: "#f6f8fa".to_string(),
            surface_hover: "#eaeef2".to_string(),
            border: "#d0d7de".to_string(),
            border_light: "#e1e4e8".to_string(),
            text_primary: "#1f2328".to_string(),
            text_secondary: "#656d76".to_string(),
            text_muted: "#8b949e".to_string(),
            text_link: "#0969da".to_string(),
            text_link_hover: "#0550ae".to_string(),
            input_bg: "#ffffff".to_string(),
            input_border: "#d0d7de".to_string(),
            input_focus: "#0969da".to_string(),
            placeholder: "#8b949e".to_string(),
            overlay: "rgba(255, 255, 255, 0.9)".to_string(),
            severity_critical: "#cf222e".to_string(),
            severity_high: "#9a6700".to_string(),
            severity_medium: "#0969da".to_string(),
            severity_low: "#1a7f37".to_string(),
            severity_unknown: "#656d76".to_string(),
        },
        Shadows {
            none: "none".to_string(),
            sm: "0 1px 2px rgba(0, 0, 0, 0.1)".to_string(),
            md: "0 4px 6px rgba(0, 0, 0, 0.15)".to_string(),
            lg: "0 10px 15px rgba(0, 0, 0, 0.2)".to_string(),
            xl: "0 20px 25px rgba(0, 0, 0, 0.25)".to_string(),
            glow_primary: "0 0 20px rgba(9, 105, 218, 0.3)".to_string(),
        },
    )
}

pub fn get_theme(name: &str) -> Theme {
    match name {
        "light" => light_theme(),
        _ => dark_theme(),
    }
}

#[derive(Props, Clone, PartialEq)]
pub struct ThemeProviderProps {
    pub children: Element,
}

#[component]
pub fn ThemeProvider(props: ThemeProviderProps) -> Element {
    let current_theme = use_signal(|| "dark".to_string());
    let theme = use_memo(move || get_theme(&current_theme()));

    use_context_provider(|| current_theme);

    let css_vars = theme().to_css_variables();

    rsx! {
        document::Stylesheet { href: asset!("/assets/tailwind.css") }
        document::Style { "{css_vars}" }
        {props.children}
    }
}

pub fn use_theme() -> Theme {
    let name = use_context::<Signal<String>>();
    get_theme(&name())
}

pub fn use_theme_name() -> Signal<String> {
    use_context::<Signal<String>>()
}

pub fn use_toggle_theme() -> impl FnMut() {
    let mut theme_name = use_context::<Signal<String>>();
    move || {
        let current = theme_name();
        let new_theme = if current == "dark" { "light" } else { "dark" };
        theme_name.set(new_theme.to_string());
    }
}
