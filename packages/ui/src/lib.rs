#![allow(
    clippy::too_many_arguments,
    clippy::clone_on_copy,
    clippy::collapsible_if
)]

//! This crate contains all shared UI for the workspace.

use dioxus::prelude::*;

pub mod models;

pub mod theme;
pub use theme::{
    dark_theme, get_theme, light_theme, use_theme, use_theme_name, use_toggle_theme, Theme,
    ThemeProvider,
};

mod navbar;
pub use navbar::{Navbar, NavbarProps};

pub mod scan_form;
pub use scan_form::{
    parse_custom_ports, parse_target, ScanConfigUi, ScanForm, ScanFormProps, ScanStatusUi,
};

pub use models::COMMON_PORTS;

mod network_map;
pub use network_map::{HostDetailPanel, MapViewMode, NetworkMap, NetworkMapProps};

mod topology;
pub use topology::component::TopologyView;

mod history_view;
pub use history_view::{HistoryView, HistoryViewProps};

pub mod views;
pub use views::{DashboardView, HistoryPage, HomeView, ScanView};

pub mod components;
pub use components::{
    Badge, BadgeSize, BadgeVariant, Button, ButtonSize, ButtonVariant, Card, CardVariant,
    EmptyState, Icon, IconName, IconSize, Modal, ProgressBar, Select, TabDef, Tabs, TextInput,
    Textarea, Tone, Tooltip,
};

pub mod helpers;
pub use helpers::{
    build_scan_record, create_default_session, handle_scan_failure, handle_scan_success,
    targets_to_strings,
};

/// Tailwind CSS stylesheet, shared across all platforms.
pub const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");
