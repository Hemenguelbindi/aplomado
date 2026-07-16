//! This crate contains all shared UI for the workspace.

use dioxus::prelude::*;

pub mod models;

pub mod theme;
pub use theme::{Theme, ThemeProvider, use_theme, use_theme_name, use_toggle_theme, dark_theme, light_theme, get_theme};

mod navbar;
pub use navbar::{Navbar, NavbarProps};

pub mod scan_form;
pub use scan_form::{
    ScanForm, ScanFormProps, ScanConfigUi, ScanStatusUi,
    parse_target, parse_custom_ports,
};

pub use models::COMMON_PORTS;

mod network_map;
pub use network_map::{NetworkMap, NetworkMapProps, MapViewMode, HostDetailPanel};

mod topology;
pub use topology::component::TopologyView;

mod history_view;
pub use history_view::{HistoryView, HistoryViewProps};

pub mod views;
pub use views::{HomeView, ScanView, HistoryPage, DashboardView};

pub mod components;
pub use components::{
    Button, ButtonVariant, ButtonSize,
    Card, CardVariant,
    Badge, BadgeVariant, BadgeSize,
    TextInput, Textarea,
    Select,
    ProgressBar,
    Tabs, TabDef,
    Modal,
    Tooltip,
    EmptyState,
};

pub mod helpers;
pub use helpers::{create_default_session, build_scan_record, targets_to_strings};

#[cfg(all(feature = "scan-engine", not(target_arch = "wasm32")))]
pub mod scan_engine;

/// Tailwind CSS stylesheet, shared across all platforms.
pub const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");
