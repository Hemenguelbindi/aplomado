use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum IconSize {
    Sm,
    #[default]
    Md,
    Lg,
    Xl,
}

impl IconSize {
    pub fn class(&self) -> &'static str {
        match self {
            Self::Sm => "w-3.5 h-3.5",
            Self::Md => "w-4 h-4",
            Self::Lg => "w-5 h-5",
            Self::Xl => "w-6 h-6",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum IconName {
    Scan,
    Dashboard,
    Hosts,
    History,
    Settings,
    Network,
    Shield,
    Search,
    Plus,
    Close,
    Menu,
    Sun,
    Moon,
    AlertTriangle,
    CheckCircle,
    XCircle,
    Info,
    ArrowRight,
    ArrowLeft,
    ExternalLink,
    Copy,
    Trash2,
    Play,
    Stop,
    RefreshCw,
    List,
    LayoutGrid,
    ChevronDown,
    ChevronUp,
    ChevronRight,
    Filter,
    Terminal,
    Server,
    Globe,
    Cpu,
    Activity,
    Clock,
    Edit,
    Save,
    MoreHorizontal,
    Zap,
    Wifi,
    WifiOff,
    AlertCircle,
    Hash,
    Monitor,
    Smartphone,
    Camera,
}

#[derive(Props, Clone, PartialEq)]
pub struct IconProps {
    pub name: IconName,
    #[props(default)]
    pub size: IconSize,
    #[props(default)]
    pub class: Option<String>,
}

#[component]
pub fn Icon(props: IconProps) -> Element {
    let sz = props.size.class();
    let extra = props.class.as_deref().unwrap_or("");
    let cls = format!("{} {}", sz, extra);
    rsx! {
        svg {
            class: "{cls}",
            "aria-hidden": "true",
            fill: "none",
            view_box: "0 0 24 24",
            stroke: "currentColor",
            stroke_width: "2",
            stroke_linecap: "round" as &str,
            stroke_linejoin: "round" as &str,
            {icon_path(props.name)}
        }
    }
}

fn icon_path(name: IconName) -> Element {
    match name {
        IconName::Scan => {
            rsx! { path { d: "M3 3l7.07 16.97 2.51-7.39 7.39-2.51L3 3z" } path { d: "M13 13l6 6" } }
        }
        IconName::Dashboard => {
            rsx! { rect { x: "3", y: "3", width: "7", height: "7" } rect { x: "14", y: "3", width: "7", height: "7" } rect { x: "3", y: "14", width: "7", height: "7" } rect { x: "14", y: "14", width: "7", height: "7" } }
        }
        IconName::Hosts => {
            rsx! { path { d: "M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" } circle { cx: "12", cy: "7", r: "4" } }
        }
        IconName::History => {
            rsx! { circle { cx: "12", cy: "12", r: "10" } polyline { points: "12 6 12 12 16 14" } }
        }
        IconName::Settings => {
            rsx! { circle { cx: "12", cy: "12", r: "3" } path { d: "M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" } }
        }
        IconName::Network => {
            rsx! { rect { x: "2", y: "2", width: "8", height: "8", rx: "2" } rect { x: "14", y: "2", width: "8", height: "8", rx: "2" } rect { x: "2", y: "14", width: "8", height: "8", rx: "2" } rect { x: "14", y: "14", width: "8", height: "8", rx: "2" } }
        }
        IconName::Shield => rsx! { path { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" } },
        IconName::Search => {
            rsx! { circle { cx: "11", cy: "11", r: "8" } path { d: "M21 21l-4.35-4.35" } }
        }
        IconName::Plus => {
            rsx! { line { x1: "12", y1: "5", x2: "12", y2: "19" } line { x1: "5", y1: "12", x2: "19", y2: "12" } }
        }
        IconName::Close => {
            rsx! { line { x1: "18", y1: "6", x2: "6", y2: "18" } line { x1: "6", y1: "6", x2: "18", y2: "18" } }
        }
        IconName::Menu => {
            rsx! { line { x1: "4", y1: "6", x2: "20", y2: "6" } line { x1: "4", y1: "12", x2: "20", y2: "12" } line { x1: "4", y1: "18", x2: "20", y2: "18" } }
        }
        IconName::Sun => {
            rsx! { circle { cx: "12", cy: "12", r: "5" } line { x1: "12", y1: "1", x2: "12", y2: "3" } line { x1: "12", y1: "21", x2: "12", y2: "23" } line { x1: "4.22", y1: "4.22", x2: "5.64", y2: "5.64" } line { x1: "18.36", y1: "18.36", x2: "19.78", y2: "19.78" } line { x1: "1", y1: "12", x2: "3", y2: "12" } line { x1: "21", y1: "12", x2: "23", y2: "12" } }
        }
        IconName::Moon => rsx! { path { d: "M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" } },
        IconName::AlertTriangle => {
            rsx! { path { d: "M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" } line { x1: "12", y1: "9", x2: "12", y2: "13" } line { x1: "12", y1: "17", x2: "12.01", y2: "17" } }
        }
        IconName::CheckCircle => {
            rsx! { path { d: "M22 11.08V12a10 10 0 1 1-5.93-9.14" } polyline { points: "22 4 12 14.01 9 11.01" } }
        }
        IconName::XCircle => {
            rsx! { circle { cx: "12", cy: "12", r: "10" } line { x1: "15", y1: "9", x2: "9", y2: "15" } line { x1: "9", y1: "9", x2: "15", y2: "15" } }
        }
        IconName::Info => {
            rsx! { circle { cx: "12", cy: "12", r: "10" } line { x1: "12", y1: "16", x2: "12", y2: "12" } line { x1: "12", y1: "8", x2: "12.01", y2: "8" } }
        }
        IconName::ArrowRight => {
            rsx! { line { x1: "5", y1: "12", x2: "19", y2: "12" } polyline { points: "12 5 19 12 12 19" } }
        }
        IconName::ArrowLeft => {
            rsx! { line { x1: "19", y1: "12", x2: "5", y2: "12" } polyline { points: "12 19 5 12 12 5" } }
        }
        IconName::ExternalLink => {
            rsx! { path { d: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" } polyline { points: "15 3 21 3 21 9" } line { x1: "10", y1: "14", x2: "21", y2: "3" } }
        }
        IconName::Copy => {
            rsx! { rect { x: "9", y: "9", width: "13", height: "13", rx: "2" } path { d: "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" } }
        }
        IconName::Trash2 => {
            rsx! { polyline { points: "3 6 5 6 21 6" } path { d: "M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" } }
        }
        IconName::Play => rsx! { polygon { points: "5 3 19 12 5 21 5 3" } },
        IconName::Stop => rsx! { rect { x: "4", y: "4", width: "16", height: "16", rx: "2" } },
        IconName::RefreshCw => {
            rsx! { polyline { points: "23 4 23 10 17 10" } polyline { points: "1 20 1 14 7 14" } path { d: "M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" } }
        }
        IconName::List => {
            rsx! { line { x1: "8", y1: "6", x2: "21", y2: "6" } line { x1: "8", y1: "12", x2: "21", y2: "12" } line { x1: "8", y1: "18", x2: "21", y2: "18" } line { x1: "3", y1: "6", x2: "3.01", y2: "6" } line { x1: "3", y1: "12", x2: "3.01", y2: "12" } line { x1: "3", y1: "18", x2: "3.01", y2: "18" } }
        }
        IconName::LayoutGrid => {
            rsx! { rect { x: "3", y: "3", width: "7", height: "7" } rect { x: "14", y: "3", width: "7", height: "7" } rect { x: "3", y: "14", width: "7", height: "7" } rect { x: "14", y: "14", width: "7", height: "7" } }
        }
        IconName::ChevronDown => rsx! { polyline { points: "6 9 12 15 18 9" } },
        IconName::ChevronUp => rsx! { polyline { points: "18 15 12 9 6 15" } },
        IconName::ChevronRight => rsx! { polyline { points: "9 18 15 12 9 6" } },
        IconName::Filter => {
            rsx! { polygon { points: "22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" } }
        }
        IconName::Terminal => {
            rsx! { polyline { points: "4 17 10 11 4 5" } line { x1: "12", y1: "19", x2: "20", y2: "19" } }
        }
        IconName::Server => {
            rsx! { rect { x: "2", y: "2", width: "20", height: "8", rx: "2" } rect { x: "2", y: "14", width: "20", height: "8", rx: "2" } line { x1: "6", y1: "6", x2: "6.01", y2: "6" } line { x1: "6", y1: "18", x2: "6.01", y2: "18" } }
        }
        IconName::Globe => {
            rsx! { circle { cx: "12", cy: "12", r: "10" } line { x1: "2", y1: "12", x2: "22", y2: "12" } path { d: "M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" } }
        }
        IconName::Cpu => {
            rsx! { rect { x: "4", y: "4", width: "16", height: "16", rx: "2" } rect { x: "9", y: "9", width: "6", height: "6" } line { x1: "9", y1: "1", x2: "9", y2: "4" } line { x1: "15", y1: "1", x2: "15", y2: "4" } line { x1: "9", y1: "20", x2: "9", y2: "23" } line { x1: "15", y1: "20", x2: "15", y2: "23" } line { x1: "20", y1: "9", x2: "23", y2: "9" } line { x1: "20", y1: "14", x2: "23", y2: "14" } line { x1: "1", y1: "9", x2: "4", y2: "9" } line { x1: "1", y1: "14", x2: "4", y2: "14" } }
        }
        IconName::Activity => rsx! { polyline { points: "22 12 18 12 15 21 9 3 6 12 2 12" } },
        IconName::Clock => {
            rsx! { circle { cx: "12", cy: "12", r: "10" } polyline { points: "12 6 12 12 16 14" } }
        }
        IconName::Edit => {
            rsx! { path { d: "M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" } path { d: "M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" } }
        }
        IconName::Save => {
            rsx! { path { d: "M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z" } polyline { points: "17 21 17 13 7 13 7 21" } polyline { points: "7 3 7 8 15 8" } }
        }
        IconName::MoreHorizontal => {
            rsx! { circle { cx: "12", cy: "12", r: "1" } circle { cx: "19", cy: "12", r: "1" } circle { cx: "5", cy: "12", r: "1" } }
        }
        IconName::Zap => rsx! { polygon { points: "13 2 3 14 12 14 11 22 21 10 12 10 13 2" } },
        IconName::Wifi => {
            rsx! { path { d: "M5 12.55a11 11 0 0 1 14.08 0" } path { d: "M1.42 9a16 16 0 0 1 21.16 0" } path { d: "M8.53 16.11a6 6 0 0 1 6.95 0" } line { x1: "12", y1: "20", x2: "12.01", y2: "20" } }
        }
        IconName::WifiOff => {
            rsx! { line { x1: "1", y1: "1", x2: "23", y2: "23" } path { d: "M16.72 11.06A10.94 10.94 0 0 1 19 12.55" } path { d: "M5 12.55a10.94 10.94 0 0 1 5.17-2.39" } path { d: "M10.71 5.05A16 16 0 0 1 22.58 9" } path { d: "M1.42 9a15.91 15.91 0 0 1 4.7-2.88" } path { d: "M8.53 16.11a6 6 0 0 1 6.95 0" } line { x1: "12", y1: "20", x2: "12.01", y2: "20" } }
        }
        IconName::AlertCircle => {
            rsx! { circle { cx: "12", cy: "12", r: "10" } line { x1: "12", y1: "8", x2: "12", y2: "12" } line { x1: "12", y1: "16", x2: "12.01", y2: "16" } }
        }
        IconName::Hash => {
            rsx! { line { x1: "4", y1: "9", x2: "20", y2: "9" } line { x1: "4", y1: "15", x2: "20", y2: "15" } line { x1: "10", y1: "3", x2: "8", y2: "21" } line { x1: "16", y1: "3", x2: "14", y2: "21" } }
        }
        IconName::Monitor => {
            rsx! { rect { x: "2", y: "3", width: "20", height: "14", rx: "2" } line { x1: "8", y1: "21", x2: "16", y2: "21" } line { x1: "12", y1: "17", x2: "12", y2: "21" } }
        }
        IconName::Smartphone => {
            rsx! { rect { x: "5", y: "2", width: "14", height: "20", rx: "2" } line { x1: "12", y1: "18", x2: "12.01", y2: "18" } }
        }
        IconName::Camera => {
            rsx! { path { d: "M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z" } circle { cx: "12", cy: "13", r: "4" } }
        }
    }
}
