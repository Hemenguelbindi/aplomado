#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum Tone {
    #[default]
    Neutral,
    Primary,
    Info,
    Success,
    Warning,
    Danger,
}

impl Tone {
    pub fn text_class(&self) -> &'static str {
        match self {
            Self::Neutral => "text-foreground",
            Self::Primary => "text-primary",
            Self::Info => "text-info",
            Self::Success => "text-success",
            Self::Warning => "text-warning",
            Self::Danger => "text-danger",
        }
    }

    pub fn bg_class(&self) -> &'static str {
        match self {
            Self::Neutral => "bg-surface",
            Self::Primary => "bg-primary",
            Self::Info => "bg-info/10",
            Self::Success => "bg-success/10",
            Self::Warning => "bg-warning/10",
            Self::Danger => "bg-danger/10",
        }
    }

    pub fn border_class(&self) -> &'static str {
        match self {
            Self::Neutral => "border-border",
            Self::Primary => "border-primary",
            Self::Info => "border-info/30",
            Self::Success => "border-success/30",
            Self::Warning => "border-warning/30",
            Self::Danger => "border-danger/30",
        }
    }
}
